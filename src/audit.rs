//! Port of `@npmcli/arborist`'s `AuditReport` and `Vuln`: turns the bulk
//! advisory response into the set of vulnerable packages (including the
//! "depends on vulnerable versions of" metavulns), works out `fixAvailable`
//! for each, and renders the same JSON structure `npm audit --json` emits.

use crate::advisory::{Advisory, BulkAdvisory};
use crate::collate;
use crate::npa;
use crate::pick::{pick_manifest, PickOpts};
use crate::registry::{Packument, Registry};
use crate::semver;
use crate::tree::Tree;
use anyhow::Result;
use indexmap::IndexMap;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use futures::stream::{FuturesUnordered, StreamExt};

#[derive(Clone, Debug)]
pub struct FixObj {
    pub name: Option<String>,
    pub version: Option<String>,
    pub is_semver_major: Option<bool>,
}

#[derive(Clone, Debug)]
pub enum Fix {
    True,
    False,
    Obj(Rc<FixObj>),
}

impl Fix {
    /// JavaScript `===`: objects compare by identity.
    fn same(&self, other: &Fix) -> bool {
        match (self, other) {
            (Fix::True, Fix::True) | (Fix::False, Fix::False) => true,
            (Fix::Obj(a), Fix::Obj(b)) => Rc::ptr_eq(a, b),
            _ => false,
        }
    }
    fn is_obj(&self) -> bool {
        matches!(self, Fix::Obj(_))
    }
}

fn severity_rank(sev: Option<&str>) -> Option<i32> {
    match sev {
        None => Some(-1),
        Some("info") => Some(0),
        Some("low") => Some(1),
        Some("moderate") => Some(2),
        Some("high") => Some(3),
        Some("critical") => Some(4),
        Some(_) => None,
    }
}

pub struct Vuln {
    pub name: String,
    pub via: Vec<usize>,
    pub advisories: Vec<Arc<Advisory>>,
    pub severity: Option<String>,
    pub effects: Vec<usize>,
    pub top_nodes: Vec<usize>,
    pub nodes: Vec<usize>,
    pub fix: Fix,
    pub packument: Arc<Packument>,
    pub versions: Vec<String>,
    range: Option<String>,
    simple_range: Option<String>,
    pub deleted: bool,
}

impl Vuln {
    fn new(name: &str, advisory: &Arc<Advisory>) -> Vuln {
        let mut v = Vuln {
            name: name.to_string(),
            via: Vec::new(),
            advisories: Vec::new(),
            severity: None,
            effects: Vec::new(),
            top_nodes: Vec::new(),
            nodes: Vec::new(),
            fix: Fix::True,
            packument: advisory.packument.clone(),
            versions: advisory.versions.clone(),
            range: None,
            simple_range: None,
            deleted: false,
        };
        v.add_advisory(advisory);
        v
    }

    fn add_advisory(&mut self, advisory: &Arc<Advisory>) {
        if !self.advisories.iter().any(|a| a.uid == advisory.uid) {
            self.advisories.push(advisory.clone());
        }
        let sev = severity_rank(Some(&advisory.severity));
        self.range = None;
        self.simple_range = None;
        if let Some(sev) = sev {
            if sev > severity_rank(self.severity.as_deref()).unwrap_or(-1) {
                self.severity = Some(advisory.severity.clone());
            }
        }
    }

    fn range(&mut self) -> String {
        if self.range.is_none() {
            self.range = Some(
                self.advisories.iter().map(|a| a.range()).collect::<Vec<_>>().join(" || "),
            );
        }
        self.range.clone().unwrap()
    }

    fn simple_range(&mut self) -> String {
        if let (Some(s), Some(r)) = (&self.simple_range, &self.range) {
            if s == r {
                return s.clone();
            }
        }
        let mut versions = self.advisories[0].versions.clone();
        let range = self.range();
        let simple = semver::simplify_range(&mut versions, &range, semver::LOOSE_PRE);
        self.simple_range = Some(simple.clone());
        self.range = Some(simple.clone());
        simple
    }

    fn test_spec(&mut self, spec: &str) -> bool {
        let Ok(s) = npa::npa(spec) else { return true };
        if !s.registry {
            return true;
        }
        let spec = s.sub_spec.unwrap_or_else(|| spec.to_string());
        let range = self.range();
        for v in &self.versions {
            if semver::satisfies(v, &spec, semver::STRICT)
                && !semver::satisfies(v, &range, semver::LOOSE_PRE)
            {
                return false;
            }
        }
        true
    }
}

pub struct AuditOpts {
    pub omit: HashSet<String>,
    pub default_tag: String,
    pub node_version: Option<String>,
    pub npm_version: Option<String>,
}

pub struct AuditReport {
    pub vulns: Vec<Vuln>,
    by_name: HashMap<String, usize>,
}

/// Memoized advisory calculation (`@npmcli/metavuln-calculator`'s
/// `Calculator`). Loads run on blocking threads as their packuments arrive;
/// results are consumed in the deterministic order the caller asks for them.
struct Calculator {
    registry: Arc<Registry>,
    memo: HashMap<String, Arc<Advisory>>,
    next_uid: usize,
    blocked_awaits: usize,
    wait_ns: u128,
    load_ns: u128,
}

enum Source {
    Bulk(Arc<BulkAdvisory>),
    Meta(Arc<Advisory>),
}

impl Calculator {
    fn key(name: &str, source: &Source) -> String {
        match source {
            Source::Bulk(b) => format!("security-advisory:{name}:{}", b.id_key()),
            Source::Meta(a) => format!("security-advisory:{name}:meta:{}", a.uid),
        }
    }

    /// Compute every (name, source) pair not already memoized, overlapping
    /// packument downloads with the CPU work.
    async fn calculate_all(&mut self, items: Vec<(String, Source)>) {
        let mut tasks = FuturesUnordered::new();
        let mut scheduled: HashSet<String> = HashSet::new();
        for (name, source) in items {
            let key = Calculator::key(&name, &source);
            if self.memo.contains_key(&key) || !scheduled.insert(key.clone()) {
                continue;
            }
            let uid = self.next_uid;
            self.next_uid += 1;
            let registry = self.registry.clone();
            let ready = registry.packument_ready(&name);
            tasks.push(async move {
                let t0 = std::time::Instant::now();
                let packument = registry.packument(&name).await;
                let waited = if ready { 0 } else { t0.elapsed().as_nanos() };
                let t1 = std::time::Instant::now();
                // the CPU work runs here on the main thread, in packument
                // arrival order, while other downloads continue
                let adv = match source {
                    Source::Bulk(b) => Advisory::from_bulk(uid, &name, &b, packument),
                    Source::Meta(a) => Advisory::from_meta(uid, &name, a, packument),
                };
                (key, adv, waited, t1.elapsed().as_nanos())
            });
        }
        while let Some((key, adv, waited, load)) = tasks.next().await {
            if waited > 0 {
                self.blocked_awaits += 1;
                self.wait_ns += waited;
            }
            self.load_ns += load;
            self.memo.insert(key, adv);
        }
    }

    fn get(&self, name: &str, source: &Source) -> Arc<Advisory> {
        self.memo[&Calculator::key(name, source)].clone()
    }
}

impl AuditReport {
    pub fn empty() -> AuditReport {
        AuditReport { vulns: Vec::new(), by_name: HashMap::new() }
    }

    pub fn len(&self) -> usize {
        self.vulns.iter().filter(|v| !v.deleted).count()
    }

    fn live(&self) -> impl Iterator<Item = (usize, &Vuln)> {
        self.vulns.iter().enumerate().filter(|(_, v)| !v.deleted)
    }

    fn set_fix(&mut self, idx: usize, f: Fix) {
        self.vulns[idx].fix = f.clone();
        // if there's a fix available for this at the top level, it means that
        // it will also fix the vulns that led to it being there.  to get there,
        // we set the vias to the most "strict" of fix availables.
        let vias = self.vulns[idx].via.clone();
        for v in vias {
            let cur = self.vulns[v].fix.clone();
            if cur.same(&f) {
                continue;
            }
            if matches!(f, Fix::False) {
                self.set_fix(v, f.clone());
            } else if matches!(cur, Fix::True) {
                self.set_fix(v, f.clone());
            } else if f.is_obj() {
                let cur_major = match &cur {
                    Fix::Obj(o) => o.is_semver_major.unwrap_or(false),
                    _ => false,
                };
                if !cur.is_obj() || !cur_major {
                    self.set_fix(v, f.clone());
                }
            }
        }
    }

    fn add_via(&mut self, idx: usize, v: usize) {
        if !self.vulns[idx].via.contains(&v) {
            self.vulns[idx].via.push(v);
        }
        if !self.vulns[v].effects.contains(&idx) {
            self.vulns[v].effects.push(idx);
        }
        // call the setter since we might add vias _after_ setting fixAvailable
        let f = self.vulns[idx].fix.clone();
        self.set_fix(idx, f);
    }

    fn delete_via(&mut self, idx: usize, v: usize) {
        self.vulns[idx].via.retain(|&x| x != v);
        self.vulns[v].effects.retain(|&x| x != idx);
    }

    fn delete_advisory(&mut self, idx: usize, uid: usize) {
        let vuln = &mut self.vulns[idx];
        vuln.advisories.retain(|a| a.uid != uid);
        vuln.severity = None;
        vuln.range = None;
        vuln.simple_range = None;
        let remaining = vuln.advisories.clone();
        for a in &remaining {
            vuln.add_advisory(a);
        }
        let vias: HashSet<String> = remaining.iter().map(|a| a.dependency.clone()).collect();
        let via_list = vuln.via.clone();
        for v in via_list {
            if !vias.contains(&self.vulns[v].name) {
                self.delete_via(idx, v);
            }
        }
    }

    fn fix_available(&mut self, idx: usize, spec: &str, opts: &AuditOpts) -> Fix {
        if !self.vulns[idx].test_spec(spec) {
            return Fix::True;
        }
        let Ok(s) = npa::npa(spec) else { return Fix::False };
        if !s.registry {
            return Fix::False;
        }
        let spec = s.sub_spec.unwrap_or_else(|| spec.to_string());
        let range = self.vulns[idx].range();
        let picked = pick_manifest(
            &self.vulns[idx].packument,
            &spec,
            &PickOpts {
                default_tag: &opts.default_tag,
                node_version: opts.node_version.as_deref(),
                npm_version: opts.npm_version.as_deref(),
                avoid: Some(&range),
                avoid_strict: true,
            },
        );
        match picked {
            Ok(p) => Fix::Obj(Rc::new(FixObj {
                name: p.name,
                version: p.version,
                is_semver_major: p.is_semver_major,
            })),
            Err(_) => Fix::False,
        }
    }

    fn is_direct(&self, tree: &Tree, idx: usize) -> bool {
        for &node in &self.vulns[idx].nodes {
            for &e in &tree.nodes[node].edges_in {
                let from = tree.edges[e].from;
                if tree.is_project_root(from) || tree.is_workspace(from) {
                    return true;
                }
            }
        }
        false
    }

    /// `AuditReport#toJSON()`
    pub fn to_json(&mut self, tree: &Tree) -> Value {
        let mut deps = json!({
            "prod": 0, "dev": 0, "optional": 0, "peer": 0, "peerOptional": 0,
            "total": tree.nodes.len().saturating_sub(1),
        });
        for node in &tree.nodes {
            let mut prod = true;
            for (flag, key) in [(node.dev, "dev"), (node.optional, "optional"), (node.peer, "peer")] {
                if flag {
                    bump(&mut deps, key);
                    prod = false;
                }
            }
            if prod {
                bump(&mut deps, "prod");
            }
        }

        let mut sev_counts = json!({
            "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": self.len(),
        });

        let live: Vec<usize> = self.live().map(|(i, _)| i).collect();
        let mut entries: Vec<(String, Value)> = Vec::new();
        for i in live {
            let v = self.vuln_json(tree, i);
            let sev_key = self.vulns[i].severity.clone().unwrap_or_else(|| "null".to_string());
            if sev_counts.get(&sev_key).is_some() {
                bump(&mut sev_counts, &sev_key);
            } else {
                sev_counts[&sev_key] = Value::Null;
            }
            entries.push((self.vulns[i].name.clone(), v));
        }
        entries.sort_by(|a, b| collate::compare(&a.0, &b.0));
        let mut vulns = Map::new();
        for (name, v) in entries {
            vulns.insert(name, v);
        }

        json!({
            "auditReportVersion": 2,
            "vulnerabilities": Value::Object(vulns),
            "metadata": {
                "vulnerabilities": sev_counts,
                "dependencies": deps,
            },
        })
    }

    fn vuln_json(&mut self, tree: &Tree, idx: usize) -> Value {
        let is_direct = self.is_direct(tree, idx);
        let range = self.vulns[idx].simple_range();
        let vuln = &self.vulns[idx];

        let mut via: Vec<(String, Value)> = Vec::new();
        for a in &vuln.advisories {
            if a.is_metavuln() {
                via.push((a.dependency.clone(), Value::String(a.dependency.clone())));
            } else {
                let mut o = Map::new();
                let source = a.source.clone().unwrap_or(Value::Null);
                o.insert("source".into(), source.clone());
                o.insert("name".into(), Value::String(a.name.clone()));
                o.insert("dependency".into(), Value::String(a.dependency.clone()));
                if let Some(t) = &a.title {
                    o.insert("title".into(), t.clone());
                }
                if let Some(u) = &a.url {
                    o.insert("url".into(), u.clone());
                }
                o.insert("severity".into(), Value::String(a.severity.clone()));
                if let Some(c) = &a.cwe {
                    o.insert("cwe".into(), c.clone());
                }
                if let Some(c) = &a.cvss {
                    o.insert("cvss".into(), c.clone());
                }
                o.insert("range".into(), Value::String(a.range()));
                // String(a.source || a)
                let key = if crate::registry::truthy(Some(&source)) {
                    js_string(&source)
                } else {
                    "[object Object]".to_string()
                };
                via.push((key, Value::Object(o)));
            }
        }
        via.sort_by(|a, b| collate::compare(&a.0, &b.0));

        let mut effects: Vec<String> = vuln.effects.iter().map(|&e| self.vulns[e].name.clone()).collect();
        effects.sort_by(|a, b| collate::compare(a, b));
        let mut nodes: Vec<String> = vuln.nodes.iter().map(|&n| tree.nodes[n].location.clone()).collect();
        nodes.sort_by(|a, b| collate::compare(a, b));

        let fix = match &vuln.fix {
            Fix::True => Value::Bool(true),
            Fix::False => Value::Bool(false),
            Fix::Obj(o) => {
                let mut m = Map::new();
                if let Some(n) = &o.name {
                    m.insert("name".into(), Value::String(n.clone()));
                }
                if let Some(v) = &o.version {
                    m.insert("version".into(), Value::String(v.clone()));
                }
                if let Some(b) = o.is_semver_major {
                    m.insert("isSemVerMajor".into(), Value::Bool(b));
                }
                Value::Object(m)
            }
        };

        json!({
            "name": vuln.name,
            "severity": vuln.severity.clone().map(Value::String).unwrap_or(Value::Null),
            "isDirect": is_direct,
            "via": via.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
            "effects": effects,
            "range": range,
            "nodes": nodes,
            "fixAvailable": fix,
        })
    }
}

fn bump(v: &mut Value, key: &str) {
    let n = v[key].as_i64().unwrap_or(0);
    v[key] = Value::from(n + 1);
}

fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

fn should_audit(tree: &Tree, node: usize, omit: &HashSet<String>) -> bool {
    let n = &tree.nodes[node];
    if tree.version(node).is_empty() || tree.is_root(node) || n.is_link || !n.links_in.is_empty() {
        return false;
    }
    if omit.is_empty() {
        return true;
    }
    !tree.should_omit(node, omit)
}

/// `prepareBulkData()`
pub fn prepare_bulk_data(tree: &Tree, omit: &HashSet<String>) -> IndexMap<String, Vec<String>> {
    let mut payload = IndexMap::new();
    for (name, nodes) in &tree.by_package_name {
        let mut set: Vec<String> = Vec::new();
        for &node in nodes {
            if !should_audit(tree, node, omit) {
                continue;
            }
            let v = tree.version(node).to_string();
            if !set.contains(&v) {
                set.push(v);
            }
        }
        if !set.is_empty() {
            payload.insert(name.clone(), set);
        }
    }
    payload
}

/// Start fetching the packuments of every non-top dependent of the given
/// nodes, so they are in flight before the algorithm asks for them.
fn prefetch_dependents(tree: &Tree, registry: &Arc<Registry>, nodes: &[usize]) {
    for &node in nodes {
        for &e in &tree.nodes[node].edges_in {
            let from = tree.edges[e].from;
            if !tree.is_top(from) {
                if let Some(name) = tree.package_name(from) {
                    registry.prefetch(name);
                }
            }
        }
    }
}

pub struct RunStats {
    pub bulk_ms: u128,
    pub packuments_fetched: usize,
    pub advisories_computed: usize,
    pub blocked_awaits: usize,
    pub wait_ms: u128,
    pub load_ms: u128,
}

/// `AuditReport.load(tree, opts)`: runs the whole audit.
pub async fn run(
    tree: &Tree,
    registry: Arc<Registry>,
    mut opts: AuditOpts,
    env: impl std::future::Future<Output = (Option<String>, Option<String>)>,
    stats: &mut RunStats,
) -> Result<AuditReport> {
    let mut report = AuditReport::empty();
    if tree.nodes.len() == 1 {
        return Ok(report);
    }
    let body = prepare_bulk_data(tree, &opts.omit);
    if body.is_empty() {
        return Ok(report);
    }

    // While the bulk request is in flight, start loading packuments we
    // already have on disk for packages in this tree (a warm run needs most
    // of them again).
    for name in registry.cached_names() {
        if tree.by_package_name.contains_key(&name) {
            registry.prefetch(&name);
        }
    }

    let t0 = std::time::Instant::now();
    let response = registry.bulk_advisories(&body).await?;
    stats.bulk_ms = t0.elapsed().as_millis();
    let (node_version, npm_version) = env.await;
    opts.node_version = node_version;
    opts.npm_version = npm_version;
    let opts = &opts;

    // Parse advisories and start every packument fetch we can already
    // predict: the advisories' own packages plus the dependents of the nodes
    // their vulnerable ranges hit.
    let mut bulk: Vec<(String, BulkAdvisory)> = Vec::new();
    for (name, advs) in &response {
        registry.prefetch(name);
        for a in advs {
            let adv = BulkAdvisory::from_value(a);
            if let Some(nodes) = tree.by_package_name.get(name) {
                let hit: Vec<usize> = nodes
                    .iter()
                    .copied()
                    .filter(|&n| {
                        should_audit(tree, n, &opts.omit)
                            && semver::satisfies(tree.version(n), &adv.vulnerable_versions, semver::LOOSE_PRE)
                    })
                    .collect();
                prefetch_dependents(tree, &registry, &hit);
            }
            bulk.push((name.clone(), adv));
        }
    }

    let mut calc = Calculator {
        registry: registry.clone(),
        memo: HashMap::new(),
        next_uid: 1,
        blocked_awaits: 0,
        wait_ns: 0,
        load_ns: 0,
    };

    // now the advisories are calculated with a set of versions and the
    // packument.
    let bulk: Vec<(String, Arc<BulkAdvisory>)> =
        bulk.into_iter().map(|(n, a)| (n, Arc::new(a))).collect();
    calc.calculate_all(bulk.iter().map(|(n, a)| (n.clone(), Source::Bulk(a.clone()))).collect()).await;
    let mut advisories: Vec<Arc<Advisory>> = Vec::new();
    let mut adv_uids: HashSet<usize> = HashSet::new();
    for (name, adv) in &bulk {
        let a = calc.get(name, &Source::Bulk(adv.clone()));
        if adv_uids.insert(a.uid) {
            advisories.push(a);
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut i = 0;
    while i < advisories.len() {
        let advisory = advisories[i].clone();
        i += 1;
        let name = advisory.name.clone();
        let k = format!("{}@{}", name, advisory.range());

        let idx = match report.by_name.get(&name) {
            Some(&idx) => {
                report.vulns[idx].add_advisory(&advisory);
                idx
            }
            None => {
                report.vulns.push(Vuln::new(&name, &advisory));
                let idx = report.vulns.len() - 1;
                report.by_name.insert(name.clone(), idx);
                idx
            }
        };

        // don't flag the exact same name/range more than once
        if !seen.contains(&k) {
            let mut pending: Vec<(String, usize, String)> = Vec::new();
            let nodes: Vec<usize> = tree.by_package_name.get(&name).cloned().unwrap_or_default();
            for node in nodes {
                if !should_audit(tree, node, &opts.omit) {
                    continue;
                }
                // if not vulnerable by this advisory, keep searching
                if !advisory.test_version(tree.version(node), None) {
                    continue;
                }
                // already marked this one, no need to do it again
                if report.vulns[idx].nodes.contains(&node) {
                    continue;
                }
                // haven't marked this one yet.  get its dependents.
                report.vulns[idx].nodes.push(node);
                let edges: Vec<usize> = tree.nodes[node].edges_in.clone();
                for e in edges {
                    let dep = tree.edges[e].from;
                    let spec = tree.edges[e].spec.clone();
                    if tree.is_top(dep) && !report.vulns[idx].top_nodes.contains(&dep) {
                        let f = report.fix_available(idx, &spec, opts);
                        report.set_fix(idx, f);
                        if !matches!(report.vulns[idx].fix, Fix::True) {
                            // now we know the top node is vulnerable, and cannot be
                            // upgraded out of the bad place without --force.
                            report.vulns[idx].top_nodes.push(dep);
                        }
                    } else if let Some(dep_name) = tree.package_name(dep) {
                        // calculate a metavuln, if necessary
                        pending.push((dep_name.to_string(), dep, spec));
                    }
                }
            }
            // calculate the metavulns (downloads and CPU overlap), then test
            // them in dependency-edge order so results are deterministic
            calc.calculate_all(
                pending.iter().map(|(n, _, _)| (n.clone(), Source::Meta(advisory.clone()))).collect(),
            )
            .await;
            for (dep_name, dep, spec) in pending {
                let meta = calc.get(&dep_name, &Source::Meta(advisory.clone()));
                if meta.test_version(tree.version(dep), Some(&spec)) && adv_uids.insert(meta.uid) {
                    // look ahead: the dependents of this metavuln's nodes will
                    // need their packuments next
                    if let Some(nodes) = tree.by_package_name.get(&meta.name) {
                        let hit: Vec<usize> = nodes
                            .iter()
                            .copied()
                            .filter(|&n| {
                                should_audit(tree, n, &opts.omit)
                                    && meta.test_version(tree.version(n), None)
                            })
                            .collect();
                        prefetch_dependents(tree, &registry, &hit);
                    }
                    advisories.push(meta);
                }
            }
            seen.insert(k);
        }

        // make sure we actually got something.  if not, remove it
        if report.vulns[idx].nodes.is_empty() {
            report.vulns[idx].deleted = true;
            report.by_name.remove(&name);
            continue;
        }

        // if the vuln is valid, but THIS advisory doesn't apply to any of
        // the nodes it references, then remove it from the advisory list.
        let advs = report.vulns[idx].advisories.clone();
        for a in advs {
            let relevant = report.vulns[idx]
                .nodes
                .iter()
                .any(|&n| a.test_version(tree.version(n), None));
            if !relevant {
                report.delete_advisory(idx, a.uid);
            }
        }
    }

    // post-loop reconciliation: establish all via links
    let live: Vec<usize> = report.live().map(|(i, _)| i).collect();
    for idx in live {
        let advs = report.vulns[idx].advisories.clone();
        for a in advs {
            if a.is_metavuln() {
                if let Some(&v) = report.by_name.get(&a.dependency) {
                    report.add_via(idx, v);
                }
            }
        }
    }

    stats.advisories_computed = calc.memo.len();
    stats.packuments_fetched = crate::registry::stats::FETCHED.load(std::sync::atomic::Ordering::Relaxed) as usize;
    stats.blocked_awaits = calc.blocked_awaits;
    stats.wait_ms = calc.wait_ns / 1_000_000;
    stats.load_ms = calc.load_ns / 1_000_000;
    Ok(report)
}
