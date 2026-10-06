//! `na` — `npm audit` output, byte for byte, without starting Node.
//!
//! The pipeline mirrors npm's: load the lockfile into an arborist-style tree,
//! POST the bulk advisory request, compute metavulns against registry
//! packuments with the same algorithm as `@npmcli/metavuln-calculator`, work
//! out `fixAvailable` with `npm-pick-manifest`'s rules, and print through a
//! port of `npm-audit-report`. The speed comes from skipping Node startup and
//! fetching every packument concurrently over HTTP/2.

mod advisory;
mod audit;
mod collate;
mod config;
mod npa;
mod pick;
mod registry;
mod report;
mod semver;
mod tree;

use clap::Parser;
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "na",
    version,
    about = "npm audit, identical output, without Node.js",
    disable_help_subcommand = true
)]
struct Args {
    /// `npm audit fix` / `npm audit signatures` are not supported.
    #[arg(hide = true)]
    subcommand: Vec<String>,

    /// Output the audit report as JSON (`npm audit --json`)
    #[arg(long)]
    json: bool,

    /// Minimum severity that causes a non-zero exit code
    #[arg(long = "audit-level", value_name = "LEVEL")]
    audit_level: Option<String>,

    /// Dependency types to omit (dev, optional, peer); repeatable
    #[arg(long, value_delimiter = ',', value_name = "TYPE")]
    omit: Vec<String>,

    /// Dependency types to include even if omitted; repeatable
    #[arg(long, value_delimiter = ',', value_name = "TYPE")]
    include: Vec<String>,

    /// Same as --omit=dev
    #[arg(long, visible_alias = "prod")]
    production: bool,

    /// `--only=prod` is the same as --omit=dev
    #[arg(long, value_name = "TYPE")]
    only: Option<String>,

    /// Registry to use (default from .npmrc or https://registry.npmjs.org)
    #[arg(long, value_name = "URL")]
    registry: Option<String>,

    /// Project directory (default: nearest ancestor with a package.json)
    #[arg(long, value_name = "DIR")]
    prefix: Option<PathBuf>,

    /// Force color on (`--color`, `--color=always`) or off (`--color=false`)
    #[arg(long, num_args = 0..=1, default_missing_value = "always", require_equals = true, value_name = "WHEN")]
    color: Option<String>,

    /// Disable color
    #[arg(long = "no-color")]
    no_color: bool,

    /// Accepted for npm compatibility (na never reads node_modules)
    #[arg(long = "package-lock-only", hide = true)]
    package_lock_only: bool,

    /// Directory for the packument cache (default: ~/.cache/na)
    #[arg(long = "cache-dir", value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    /// Do not read or write the packument cache
    #[arg(long = "no-cache")]
    no_cache: bool,

    /// Revalidate cached packuments with the registry even when fresh
    #[arg(long = "prefer-online")]
    prefer_online: bool,

    /// Print phase timings to stderr
    #[arg(long)]
    timing: bool,

    /// Maximum concurrent registry requests
    #[arg(long, default_value_t = 64, value_name = "N")]
    concurrency: usize,

    /// Node version used for `engines` checks (default: `node --version`)
    #[arg(long = "node-version", value_name = "VERSION")]
    node_version: Option<String>,

    /// npm version used for `engines` checks (default: the installed npm)
    #[arg(long = "npm-version", value_name = "VERSION")]
    npm_version: Option<String>,
}

fn main() {
    let args = Args::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(async_main(args));
    // Let stdout flush, then exit with npm's exit code.
    std::process::exit(code);
}

/// buildOmitList() from npm's config definitions.
fn build_omit(args: &Args) -> HashSet<String> {
    let include: HashSet<&str> = args.include.iter().map(|s| s.as_str()).collect();
    let mut omit: HashSet<String> = args
        .omit
        .iter()
        .filter(|t| !include.contains(t.as_str()))
        .cloned()
        .collect();
    let only_prod = args
        .only
        .as_deref()
        .map(|o| o == "prod" || o == "production")
        .unwrap_or(false);
    if only_prod || args.production {
        omit.insert("dev".to_string());
    }
    if include.contains("dev") {
        omit.remove("dev");
    }
    omit
}

fn cache_dir(args: &Args) -> PathBuf {
    if let Some(d) = &args.cache_dir {
        return d.clone();
    }
    if let Some(d) = std::env::var_os("NA_CACHE_DIR") {
        return PathBuf::from(d);
    }
    if let Some(x) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(x).join("na");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    home.join(".cache").join("na")
}

async fn detect_node_version() -> Option<String> {
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("node").arg("--version").output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

async fn detect_npm_version() -> Option<String> {
    // Resolve the `npm` on PATH to its package.json without spawning it.
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("npm");
            if let Ok(real) = std::fs::canonicalize(&candidate) {
                let mut p = real.parent();
                while let Some(dir) = p {
                    let pj = dir.join("package.json");
                    if let Ok(text) = std::fs::read_to_string(&pj) {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                            if v.get("name").and_then(|n| n.as_str()) == Some("npm") {
                                return v.get("version").and_then(|n| n.as_str()).map(|s| s.to_string());
                            }
                        }
                    }
                    p = dir.parent();
                }
            }
        }
    }
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new("npm").arg("--version").output(),
    )
    .await
    .ok()?
    .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && !s.is_empty() {
        Some(s)
    } else {
        None
    }
}

async fn async_main(args: Args) -> i32 {
    let t0 = Instant::now();
    if let Some(sub) = args.subcommand.first() {
        eprintln!("na: `npm audit {sub}` is not supported; na only produces the audit report.");
        return 1;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let prefix = match &args.prefix {
        Some(p) if p.is_absolute() => p.clone(),
        Some(p) => cwd.join(p),
        None => tree::find_prefix(&cwd),
    };
    let cfg = config::NpmConfig::load(&prefix);

    // engine checks need the local node/npm versions; find them in the
    // background while everything else happens.
    let node_fut = match args.node_version.clone() {
        Some(v) => tokio::spawn(async move { Some(v) }),
        None => tokio::spawn(detect_node_version()),
    };
    let npm_fut = match args.npm_version.clone() {
        Some(v) => tokio::spawn(async move { Some(v) }),
        None => tokio::spawn(detect_npm_version()),
    };

    let t_tree = Instant::now();
    let tree = match tree::Tree::load(&prefix) {
        Ok(t) => t,
        Err(e) if e.to_string() == "ENOLOCK" => {
            eprintln!("npm error code ENOLOCK");
            eprintln!("npm error audit This command requires an existing lockfile.");
            eprintln!("npm error audit Try creating one first with: npm i --package-lock-only");
            eprintln!("npm error audit Original error: loadVirtual requires existing shrinkwrap file");
            return 1;
        }
        Err(e) => {
            eprintln!("npm error {e}");
            return 1;
        }
    };
    let tree_ms = t_tree.elapsed().as_millis();

    let registry_url = args
        .registry
        .clone()
        .unwrap_or_else(|| cfg.registry.clone())
        .trim_end_matches('/')
        .to_string();
    let registry = match registry::Registry::new(registry::RegistryConfig {
        registry: registry_url,
        scopes: cfg.scopes.clone(),
        tokens: cfg.tokens.clone(),
        audit_registry: cfg.audit_registry.clone(),
        concurrency: args.concurrency,
        user_agent: format!("na/{}", env!("CARGO_PKG_VERSION")),
        cache_dir: if args.no_cache { None } else { Some(cache_dir(&args)) },
        prefer_online: args.prefer_online,
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("npm error {e}");
            return 1;
        }
    };

    let color = if args.no_color {
        false
    } else if let Some(c) = args.color.as_deref().or(cfg.color.as_deref()) {
        match c {
            "always" | "true" | "1" => true,
            "false" | "0" | "never" | "" => false,
            _ => std::io::stdout().is_terminal(),
        }
    } else if std::env::var("NO_COLOR").map(|v| v != "0").unwrap_or(false) {
        false
    } else {
        std::io::stdout().is_terminal()
    };

    let opts = audit::AuditOpts {
        omit: build_omit(&args),
        default_tag: cfg.tag.clone(),
        node_version: None,
        npm_version: None,
    };
    let env = async move {
        (
            node_fut.await.ok().flatten(),
            npm_fut.await.ok().flatten(),
        )
    };

    let mut stats = audit::RunStats {
        bulk_ms: 0,
        packuments_fetched: 0,
        advisories_computed: 0,
        blocked_awaits: 0,
        wait_ms: 0,
        load_ms: 0,
    };
    let t_audit = Instant::now();
    let mut report = match audit::run(&tree, registry, opts, env, &mut stats).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("npm warn audit {e}");
            eprintln!("audit endpoint returned an error");
            return 1;
        }
    };
    let audit_ms = t_audit.elapsed().as_millis();

    if std::env::var_os("NA_DEBUG_ORDER").is_some() {
        for v in report.vulns.iter().filter(|v| !v.deleted) {
            let advs: Vec<String> = v
                .advisories
                .iter()
                .map(|a| {
                    let src = match &a.source {
                        Some(s) if a.is_advisory() => s.to_string(),
                        _ => "meta".to_string(),
                    };
                    format!("{}:{}:{}", a.dependency, src, a.range())
                })
                .collect();
            eprintln!("{}\t{}", v.name, advs.join(" | "));
        }
    }

    let data = report.to_json(&tree);
    let level = args
        .audit_level
        .clone()
        .or_else(|| cfg.audit_level.clone())
        .unwrap_or_else(|| "low".to_string());
    let code = report::exit_code(&data, &level);

    let out = if args.json {
        report::json(&data)
    } else {
        report::detail(&data, &report::Colors { enabled: color })
    };
    {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = writeln!(lock, "{out}");
        let _ = lock.flush();
    }

    if args.timing {
        eprintln!("na timing:");
        eprintln!("  load tree:        {tree_ms:>6} ms ({} nodes)", tree.nodes.len());
        eprintln!("  bulk advisories:  {:>6} ms", stats.bulk_ms);
        use std::sync::atomic::Ordering::Relaxed;
        eprintln!(
            "  packuments:       {:>6} fetched, {} fresh in cache, {} revalidated, {} failed, {:.1} MB, {} ms summed network, {} ms summed parse",
            stats.packuments_fetched,
            registry::stats::CACHE_FRESH.load(Relaxed),
            registry::stats::CACHE_REVALIDATED.load(Relaxed),
            registry::stats::FAILED.load(Relaxed),
            registry::stats::BYTES.load(Relaxed) as f64 / 1e6,
            registry::stats::NET_NS.load(Relaxed) / 1_000_000,
            registry::stats::PARSE_NS.load(Relaxed) / 1_000_000,
        );
        eprintln!(
            "  metavuln calc:    {:>6} ms over {} advisories; {} waits on downloads ({} ms summed)",
            stats.load_ms, stats.advisories_computed, stats.blocked_awaits, stats.wait_ms
        );
        eprintln!("  audit total:      {audit_ms:>6} ms");
        eprintln!("  total:            {:>6} ms", t0.elapsed().as_millis());
    }
    code
}
