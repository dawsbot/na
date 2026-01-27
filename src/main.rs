use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "na", about = "Fast npm audit replacement", version)]
struct Args {
    /// Path to package-lock.json
    #[arg(short, long, default_value = "package-lock.json")]
    lockfile: PathBuf,

    /// Output format: text, json
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Only show vulnerabilities of this severity or higher
    #[arg(short, long)]
    severity: Option<String>,

    /// Show timing information
    #[arg(long)]
    timing: bool,
}

// ============================================================================
// Package-lock.json structures
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageLock {
    packages: Option<IndexMap<String, PackageEntry>>,
    dependencies: Option<IndexMap<String, LegacyDependency>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct PackageEntry {
    version: Option<String>,
    resolved: Option<String>,
    dependencies: Option<IndexMap<String, String>>,
    dev_dependencies: Option<IndexMap<String, String>>,
    peer_dependencies: Option<IndexMap<String, String>>,
    optional_dependencies: Option<IndexMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct LegacyDependency {
    version: String,
    dependencies: Option<IndexMap<String, LegacyDependency>>,
    requires: Option<IndexMap<String, String>>,
}

// ============================================================================
// npm Bulk Advisory API structures
// ============================================================================

type BulkAuditRequest = HashMap<String, Vec<String>>;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct BulkAdvisory {
    id: u64,
    title: String,
    #[serde(default)]
    severity: String,
    url: Option<String>,
    vulnerable_versions: Option<String>,
    module_name: Option<String>,
    #[serde(default)]
    cwe: Vec<String>,
    #[serde(default)]
    cvss: Option<CvssInfo>,
    overview: Option<String>,
    recommendation: Option<String>,
    references: Option<String>,
    github_advisory_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct CvssInfo {
    score: Option<f64>,
    #[serde(rename = "vectorString")]
    vector_string: Option<String>,
}

// ============================================================================
// Internal structures
// ============================================================================

#[derive(Debug, Clone)]
struct PackageInfo {
    name: String,
    version: String,
    path: String,
}

/// Dependency graph: maps package path -> list of dependency paths
type DependencyGraph = HashMap<String, Vec<String>>;

/// Reverse dependency graph: maps package path -> list of dependents (who depends on this)
type ReverseDependencyGraph = HashMap<String, Vec<String>>;

#[derive(Debug, Serialize, Clone)]
struct VulnerabilityReport {
    package: String,
    version: String,
    id: u64,
    title: String,
    severity: String,
    cvss_score: Option<f64>,
    vulnerable_versions: Option<String>,
    recommendation: Option<String>,
    url: Option<String>,
    cwe: Vec<String>,
    github_advisory_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    via: Option<String>, // For meta-vulnerabilities: which direct vuln this comes from
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependency_chain: Vec<String>, // Path from this package to the vulnerable dep
}

// ============================================================================
// Main logic
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let total_start = Instant::now();

    // Parse lockfile
    let parse_start = Instant::now();
    let lockfile_content = fs::read_to_string(&args.lockfile)
        .with_context(|| format!("Failed to read {}", args.lockfile.display()))?;
    let lockfile: PackageLock = serde_json::from_str(&lockfile_content)
        .with_context(|| "Failed to parse package-lock.json")?;
    let parse_time = parse_start.elapsed();

    // Extract packages and build dependency graph
    let build_start = Instant::now();
    let (packages, dep_graph, reverse_graph) = extract_packages_and_graph(&lockfile);
    let dep_count = packages.len();

    // Build bulk request
    let bulk_request = build_bulk_request(&packages);
    let build_time = build_start.elapsed();

    if bulk_request.is_empty() {
        println!("{}", "No packages found in lockfile".yellow());
        return Ok(());
    }

    // Query npm bulk advisory API
    let api_start = Instant::now();
    let advisories = query_npm_bulk_api(&bulk_request).await?;
    let api_time = api_start.elapsed();

    // Match advisories to packages (direct vulnerabilities)
    let direct_vulns = match_advisories_to_packages(&packages, &advisories);

    // Find meta-vulnerabilities (packages that depend on vulnerable packages)
    let all_vulns = find_meta_vulnerabilities(&packages, &direct_vulns, &reverse_graph);

    // Filter by severity if requested
    let severity_order = ["info", "low", "moderate", "high", "critical"];
    let min_index = args.severity
        .as_ref()
        .and_then(|s| severity_order.iter().position(|&x| x == s.to_lowercase()))
        .unwrap_or(0);

    let filtered: Vec<_> = all_vulns
        .into_iter()
        .filter(|r| {
            let idx = severity_order.iter().position(|&x| x == r.severity.to_lowercase()).unwrap_or(0);
            idx >= min_index
        })
        .collect();

    // Display results
    let display_start = Instant::now();
    match args.format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&filtered)?);
        }
        _ => {
            display_results(&filtered)?;
        }
    }
    let display_time = display_start.elapsed();

    if args.timing {
        eprintln!("\n{}", "Timing:".dimmed());
        eprintln!("  Parse lockfile:  {:>8.2?}", parse_time);
        eprintln!("  Build request:   {:>8.2?}", build_time);
        eprintln!("  API call:        {:>8.2?}", api_time);
        eprintln!("  Display:         {:>8.2?}", display_time);
        eprintln!("  {}: {:>8.2?}", "Total".bold(), total_start.elapsed());
        eprintln!("  Dependencies scanned: {}", dep_count);
    }

    if !filtered.is_empty() {
        std::process::exit(1);
    }

    Ok(())
}

fn extract_packages_and_graph(lockfile: &PackageLock) -> (Vec<PackageInfo>, DependencyGraph, ReverseDependencyGraph) {
    let mut packages = Vec::new();
    let mut seen = HashSet::new();
    let mut dep_graph: DependencyGraph = HashMap::new();
    let mut reverse_graph: ReverseDependencyGraph = HashMap::new();

    // Handle lockfileVersion 2/3 (packages field)
    if let Some(pkgs) = &lockfile.packages {
        for (path, entry) in pkgs {
            if path.is_empty() {
                // Root package - still process its dependencies
                if let Some(deps) = &entry.dependencies {
                    for dep_name in deps.keys() {
                        let dep_path = format!("node_modules/{}", dep_name);
                        dep_graph.entry("".to_string()).or_default().push(dep_path.clone());
                        reverse_graph.entry(dep_path).or_default().push("".to_string());
                    }
                }
                continue;
            }

            let name = extract_package_name(path);

            // Skip file: and link: dependencies
            if let Some(resolved) = &entry.resolved {
                if resolved.starts_with("file:") || resolved.starts_with("link:") {
                    continue;
                }
            }

            if let Some(version) = &entry.version {
                let key = (name.clone(), version.clone());
                if seen.insert(key) {
                    packages.push(PackageInfo {
                        name: name.clone(),
                        version: version.clone(),
                        path: path.clone(),
                    });
                }

                // Build dependency edges
                let all_deps = collect_all_deps(entry);
                for dep_name in all_deps {
                    // Find the resolved path for this dependency
                    let dep_path = resolve_dependency_path(path, &dep_name, pkgs);
                    if let Some(dp) = dep_path {
                        dep_graph.entry(path.clone()).or_default().push(dp.clone());
                        reverse_graph.entry(dp).or_default().push(path.clone());
                    }
                }
            }
        }
    }

    // Handle lockfileVersion 1 (dependencies field)
    if let Some(deps) = &lockfile.dependencies {
        collect_legacy_packages_and_graph(
            deps,
            "",
            &mut packages,
            &mut seen,
            &mut dep_graph,
            &mut reverse_graph,
        );
    }

    (packages, dep_graph, reverse_graph)
}

fn collect_all_deps(entry: &PackageEntry) -> Vec<String> {
    let mut deps = Vec::new();
    if let Some(d) = &entry.dependencies {
        deps.extend(d.keys().cloned());
    }
    if let Some(d) = &entry.dev_dependencies {
        deps.extend(d.keys().cloned());
    }
    if let Some(d) = &entry.peer_dependencies {
        deps.extend(d.keys().cloned());
    }
    if let Some(d) = &entry.optional_dependencies {
        deps.extend(d.keys().cloned());
    }
    deps
}

fn resolve_dependency_path(from_path: &str, dep_name: &str, packages: &IndexMap<String, PackageEntry>) -> Option<String> {
    // Try to find the dependency by walking up the tree
    // First, try nested: from_path/node_modules/dep_name
    let nested = format!("{}/node_modules/{}", from_path, dep_name);
    if packages.contains_key(&nested) {
        return Some(nested);
    }

    // Walk up the tree
    let mut current = from_path.to_string();
    loop {
        // Try at current level's node_modules
        let parent = if current.contains("/node_modules/") {
            current.rsplit_once("/node_modules/").map(|(p, _)| p.to_string())
        } else {
            None
        };

        if let Some(p) = parent {
            let candidate = format!("{}/node_modules/{}", p, dep_name);
            if packages.contains_key(&candidate) {
                return Some(candidate);
            }
            current = p;
        } else {
            break;
        }
    }

    // Try top-level
    let top_level = format!("node_modules/{}", dep_name);
    if packages.contains_key(&top_level) {
        return Some(top_level);
    }

    None
}

fn extract_package_name(path: &str) -> String {
    let without_prefix = path
        .strip_prefix("node_modules/")
        .unwrap_or(path);

    let last_segment = without_prefix
        .rsplit("/node_modules/")
        .next()
        .unwrap_or(without_prefix);

    if last_segment.starts_with('@') {
        let parts: Vec<&str> = last_segment.splitn(3, '/').collect();
        if parts.len() >= 2 {
            return format!("{}/{}", parts[0], parts[1]);
        }
    }

    last_segment.split('/').next().unwrap_or(last_segment).to_string()
}

fn collect_legacy_packages_and_graph(
    deps: &IndexMap<String, LegacyDependency>,
    parent_path: &str,
    packages: &mut Vec<PackageInfo>,
    seen: &mut HashSet<(String, String)>,
    dep_graph: &mut DependencyGraph,
    reverse_graph: &mut ReverseDependencyGraph,
) {
    for (name, dep) in deps {
        let path = if parent_path.is_empty() {
            format!("node_modules/{}", name)
        } else {
            format!("{}/node_modules/{}", parent_path, name)
        };

        let key = (name.clone(), dep.version.clone());
        if seen.insert(key) {
            packages.push(PackageInfo {
                name: name.clone(),
                version: dep.version.clone(),
                path: path.clone(),
            });
        }

        // Add edge from parent to this
        if !parent_path.is_empty() {
            dep_graph.entry(parent_path.to_string()).or_default().push(path.clone());
            reverse_graph.entry(path.clone()).or_default().push(parent_path.to_string());
        }

        if let Some(nested) = &dep.dependencies {
            collect_legacy_packages_and_graph(nested, &path, packages, seen, dep_graph, reverse_graph);
        }
    }
}

fn build_bulk_request(packages: &[PackageInfo]) -> BulkAuditRequest {
    let mut request: BulkAuditRequest = HashMap::new();

    for pkg in packages {
        request
            .entry(pkg.name.clone())
            .or_default()
            .push(pkg.version.clone());
    }

    for versions in request.values_mut() {
        versions.sort();
        versions.dedup();
    }

    request
}

async fn query_npm_bulk_api(request: &BulkAuditRequest) -> Result<HashMap<String, Vec<BulkAdvisory>>> {
    let client = reqwest::Client::builder()
        .user_agent("na/0.1.0")
        .gzip(true)
        .build()?;

    let response: reqwest::Response = client
        .post("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk")
        .header("Content-Type", "application/json")
        .json(request)
        .send()
        .await
        .context("Failed to call npm bulk advisory API")?;

    if !response.status().is_success() {
        let status = response.status();
        let body: String = response.text().await.unwrap_or_default();
        anyhow::bail!("npm bulk API returned {}: {}", status, body);
    }

    let advisories: HashMap<String, Vec<BulkAdvisory>> = response
        .json()
        .await
        .context("Failed to parse bulk advisory response")?;

    Ok(advisories)
}

fn match_advisories_to_packages(
    packages: &[PackageInfo],
    advisories: &HashMap<String, Vec<BulkAdvisory>>,
) -> Vec<VulnerabilityReport> {
    let mut reports = Vec::new();

    for (pkg_name, pkg_advisories) in advisories {
        for advisory in pkg_advisories {
            let vulnerable_range = advisory.vulnerable_versions.as_deref().unwrap_or("*");

            // Filter out workspace root packages (paths without node_modules)
            for pkg in packages.iter().filter(|p| &p.name == pkg_name && p.path.contains("node_modules")) {
                if version_matches_range(&pkg.version, vulnerable_range) {
                    reports.push(VulnerabilityReport {
                        package: pkg.name.clone(),
                        version: pkg.version.clone(),
                        id: advisory.id,
                        title: advisory.title.clone(),
                        severity: advisory.severity.clone(),
                        cvss_score: advisory.cvss.as_ref().and_then(|c| c.score),
                        vulnerable_versions: advisory.vulnerable_versions.clone(),
                        recommendation: advisory.recommendation.clone(),
                        url: advisory.url.clone(),
                        cwe: advisory.cwe.clone(),
                        github_advisory_id: advisory.github_advisory_id.clone(),
                        via: None,
                        dependency_chain: vec![],
                    });
                }
            }
        }
    }

    reports
}

fn find_meta_vulnerabilities(
    packages: &[PackageInfo],
    direct_vulns: &[VulnerabilityReport],
    reverse_graph: &ReverseDependencyGraph,
) -> Vec<VulnerabilityReport> {
    let mut all_vulns = direct_vulns.to_vec();

    // Build a map of package name -> paths for quick lookup
    let mut name_to_paths: HashMap<String, Vec<String>> = HashMap::new();
    for pkg in packages {
        name_to_paths.entry(pkg.name.clone()).or_default().push(pkg.path.clone());
    }

    // Build path -> PackageInfo map, excluding workspace root packages (no node_modules in path)
    let path_to_pkg: HashMap<String, &PackageInfo> = packages
        .iter()
        .filter(|p| p.path.contains("node_modules"))
        .map(|p| (p.path.clone(), p))
        .collect();

    // For each direct vulnerability, find all packages that depend on it
    let mut seen_meta: HashSet<(String, String, u64)> = HashSet::new(); // (pkg_name, version, advisory_id)

    // Mark direct vulns as seen
    for v in direct_vulns {
        seen_meta.insert((v.package.clone(), v.version.clone(), v.id));
    }

    for vuln in direct_vulns {
        // Find all paths for this vulnerable package
        if let Some(vuln_paths) = name_to_paths.get(&vuln.package) {
            for vuln_path in vuln_paths {
                // Check if this path has the vulnerable version
                if let Some(pkg) = path_to_pkg.get(vuln_path) {
                    if pkg.version != vuln.version {
                        continue;
                    }
                }

                // BFS to find all dependents
                let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
                let mut visited: HashSet<String> = HashSet::new();

                // Start with packages that directly depend on the vulnerable package
                if let Some(dependents) = reverse_graph.get(vuln_path) {
                    for dep in dependents {
                        if dep.is_empty() {
                            continue; // Skip root
                        }
                        queue.push_back((dep.clone(), vec![vuln.package.clone()]));
                    }
                }

                while let Some((path, chain)) = queue.pop_front() {
                    if visited.contains(&path) {
                        continue;
                    }
                    visited.insert(path.clone());

                    if let Some(pkg) = path_to_pkg.get(&path) {
                        let key = (pkg.name.clone(), pkg.version.clone(), vuln.id);
                        if seen_meta.insert(key) {
                            let mut new_chain = chain.clone();
                            new_chain.insert(0, pkg.name.clone());

                            all_vulns.push(VulnerabilityReport {
                                package: pkg.name.clone(),
                                version: pkg.version.clone(),
                                id: vuln.id,
                                title: vuln.title.clone(),
                                severity: vuln.severity.clone(),
                                cvss_score: vuln.cvss_score,
                                vulnerable_versions: None, // Not directly vulnerable
                                recommendation: None,
                                url: vuln.url.clone(),
                                cwe: vuln.cwe.clone(),
                                github_advisory_id: vuln.github_advisory_id.clone(),
                                via: Some(vuln.package.clone()),
                                dependency_chain: new_chain,
                            });
                        }

                        // Continue BFS to find transitive dependents
                        if let Some(next_dependents) = reverse_graph.get(&path) {
                            for next in next_dependents {
                                if !next.is_empty() && !visited.contains(next) {
                                    let mut new_chain = chain.clone();
                                    new_chain.insert(0, pkg.name.clone());
                                    queue.push_back((next.clone(), new_chain));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort by severity (critical first), then by whether it's direct or meta
    let severity_order = ["critical", "high", "moderate", "low", "info"];
    all_vulns.sort_by(|a, b| {
        let a_idx = severity_order.iter().position(|&x| x == a.severity.to_lowercase()).unwrap_or(5);
        let b_idx = severity_order.iter().position(|&x| x == b.severity.to_lowercase()).unwrap_or(5);
        match a_idx.cmp(&b_idx) {
            std::cmp::Ordering::Equal => {
                // Direct vulns first
                a.via.is_some().cmp(&b.via.is_some())
            }
            other => other,
        }
    });

    all_vulns
}

fn version_matches_range(version: &str, range: &str) -> bool {
    if range == "*" || range.is_empty() {
        return true;
    }

    if range == version {
        return true;
    }

    let v_parts: Vec<u64> = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();

    if v_parts.is_empty() {
        return false;
    }

    // Handle || (OR) ranges
    if range.contains("||") {
        for or_part in range.split("||") {
            if check_range_part(&v_parts, or_part.trim()) {
                return true;
            }
        }
        return false;
    }

    check_range_part(&v_parts, range)
}

fn check_range_part(v_parts: &[u64], range: &str) -> bool {
    // Handle space-separated (AND) conditions
    for condition in range.split_whitespace() {
        if !check_condition(v_parts, condition) {
            return false;
        }
    }
    true
}

fn check_condition(v_parts: &[u64], condition: &str) -> bool {
    let (op, ver_str) = if condition.starts_with(">=") {
        (">=", &condition[2..])
    } else if condition.starts_with("<=") {
        ("<=", &condition[2..])
    } else if condition.starts_with('>') {
        (">", &condition[1..])
    } else if condition.starts_with('<') {
        ("<", &condition[1..])
    } else if condition.starts_with('=') {
        ("=", &condition[1..])
    } else if condition.starts_with('^') || condition.starts_with('~') {
        return true; // Be conservative
    } else {
        ("=", condition)
    };

    let c_parts: Vec<u64> = ver_str
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();

    if c_parts.is_empty() {
        return true;
    }

    let cmp = compare_versions(v_parts, &c_parts);

    match op {
        ">=" => cmp >= 0,
        "<=" => cmp <= 0,
        ">" => cmp > 0,
        "<" => cmp < 0,
        "=" => cmp == 0,
        _ => true,
    }
}

fn compare_versions(a: &[u64], b: &[u64]) -> i32 {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        if av < bv {
            return -1;
        }
        if av > bv {
            return 1;
        }
    }
    0
}

fn display_results(reports: &[VulnerabilityReport]) -> Result<()> {
    if reports.is_empty() {
        println!("{}", "found 0 vulnerabilities".green().bold());
        return Ok(());
    }

    // Count by severity
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for r in reports {
        *counts.entry(r.severity.as_str()).or_insert(0) += 1;
    }

    // Count direct vs transitive
    let direct_count = reports.iter().filter(|r| r.via.is_none()).count();
    let transitive_count = reports.len() - direct_count;

    println!(
        "found {} {} ({} direct, {} transitive):\n",
        reports.len().to_string().bold(),
        if reports.len() == 1 { "vulnerability" } else { "vulnerabilities" },
        direct_count,
        transitive_count
    );

    for report in reports {
        print_report(report);
    }

    // Summary line
    let mut summary_parts = Vec::new();
    for sev in ["critical", "high", "moderate", "low", "info"] {
        if let Some(&count) = counts.get(sev) {
            summary_parts.push(format!("{} {}", count, sev));
        }
    }

    println!(
        "\n{} ({} in total)",
        summary_parts.join(", "),
        reports.len()
    );

    Ok(())
}

fn print_report(report: &VulnerabilityReport) {
    let severity_colored = match report.severity.to_lowercase().as_str() {
        "critical" => report.severity.to_lowercase().red().bold(),
        "high" => report.severity.to_lowercase().red(),
        "moderate" => report.severity.to_lowercase().yellow(),
        "low" => report.severity.to_lowercase().cyan(),
        _ => report.severity.to_lowercase().white(),
    };

    println!("{}", report.title.bold());
    println!("  Severity: {}", severity_colored);
    println!("  Package: {}", report.package);
    println!("  Installed: {}", report.version);

    if let Some(via) = &report.via {
        println!("  Via: {}", via.yellow());
        if !report.dependency_chain.is_empty() {
            println!("  Chain: {}", report.dependency_chain.join(" > "));
        }
    }

    if let Some(vuln_versions) = &report.vulnerable_versions {
        println!("  Vulnerable: {}", vuln_versions);
    }

    if let Some(rec) = &report.recommendation {
        println!("  Recommendation: {}", rec.green());
    }

    if let Some(url) = &report.url {
        println!("  More info: {}", url.dimmed());
    }

    println!();
}
