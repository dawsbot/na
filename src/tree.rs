//! Loads the dependency graph the way `@npmcli/arborist`'s `loadVirtual`
//! does: nodes from the lockfile, the root from `package.json`, edges from
//! each package's declared dependencies resolved through the `node_modules`
//! hierarchy, links/workspaces, and the dev/optional/peer flags.

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Default, Clone, Debug)]
pub struct Package {
    pub name: Option<String>,
    pub version: Option<String>,
    pub dependencies: IndexMap<String, String>,
    pub dev_dependencies: IndexMap<String, String>,
    pub optional_dependencies: IndexMap<String, String>,
    pub peer_dependencies: IndexMap<String, String>,
    pub peer_optional: HashSet<String>,
    pub workspaces: Option<Vec<String>>,
    pub bundle_dependencies: Vec<String>,
}

fn string_map(v: Option<&Value>) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    if let Some(Value::Object(m)) = v {
        for (k, val) in m {
            if let Value::String(s) = val {
                out.insert(k.clone(), s.clone());
            }
        }
    }
    out
}

impl Package {
    /// Build a package from a package.json / lockfile entry object and apply
    /// the normalization steps arborist runs on every node.
    pub fn from_value(v: &Value) -> Package {
        let mut pkg = Package {
            name: v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()),
            version: v.get("version").and_then(|n| n.as_str()).map(|s| s.to_string()),
            dependencies: string_map(v.get("dependencies")),
            dev_dependencies: string_map(v.get("devDependencies")),
            optional_dependencies: string_map(v.get("optionalDependencies")),
            peer_dependencies: string_map(v.get("peerDependencies")),
            peer_optional: HashSet::new(),
            workspaces: None,
            bundle_dependencies: Vec::new(),
        };
        if let Some(Value::Object(meta)) = v.get("peerDependenciesMeta") {
            for (name, m) in meta {
                if crate::registry::truthy(m.get("optional")) {
                    pkg.peer_optional.insert(name.clone());
                }
            }
        }
        // workspaces: array, or { packages: [...] }
        let ws = v.get("workspaces").map(|w| match w {
            Value::Object(o) => o.get("packages").cloned().unwrap_or(Value::Null),
            other => other.clone(),
        });
        if let Some(Value::Array(arr)) = ws {
            pkg.workspaces =
                Some(arr.iter().filter_map(|p| p.as_str().map(|s| s.to_string())).collect());
        }
        // bundledDependencies typo + bundleDependencies normalization
        let bd = v.get("bundleDependencies").or_else(|| v.get("bundledDependencies"));
        match bd {
            Some(Value::Bool(true)) => {
                pkg.bundle_dependencies = pkg.dependencies.keys().cloned().collect()
            }
            Some(Value::Array(a)) => {
                pkg.bundle_dependencies =
                    a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect()
            }
            Some(Value::Object(o)) => pkg.bundle_dependencies = o.keys().cloned().collect(),
            _ => {}
        }
        // optionalDedupe
        if !pkg.optional_dependencies.is_empty() {
            for name in pkg.optional_dependencies.keys() {
                pkg.dependencies.shift_remove(name);
            }
        }
        pkg
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum EdgeType {
    Prod,
    Dev,
    Optional,
    Peer,
    PeerOptional,
    Workspace,
}

#[derive(Clone, Debug)]
pub struct Edge {
    pub from: usize,
    pub to: Option<usize>,
    #[allow(dead_code)]
    pub name: String,
    pub spec: String,
    pub ty: EdgeType,
}

impl Edge {
    pub fn optional(&self) -> bool {
        matches!(self.ty, EdgeType::Optional | EdgeType::PeerOptional)
    }
    pub fn peer(&self) -> bool {
        matches!(self.ty, EdgeType::Peer | EdgeType::PeerOptional)
    }
    pub fn dev(&self) -> bool {
        self.ty == EdgeType::Dev
    }
}

#[derive(Debug)]
pub struct Node {
    pub location: String,
    pub name: String,
    pub pkg: Package,
    pub is_link: bool,
    pub target: Option<usize>,
    pub links_in: Vec<usize>,
    pub parent: Option<usize>,
    pub fs_parent: Option<usize>,
    pub children: HashMap<String, usize>,
    pub edges_out: IndexMap<String, usize>,
    pub edges_in: Vec<usize>,
    pub dev: bool,
    pub optional: bool,
    pub dev_optional: bool,
    pub peer: bool,
    pub extraneous: bool,
}

pub struct Tree {
    pub path: PathBuf,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub by_location: HashMap<String, usize>,
    /// inventory index by packageName, in insertion order.
    pub by_package_name: IndexMap<String, Vec<usize>>,
}

fn name_from_folder(loc: &str) -> String {
    let mut parts = loc.rsplit('/');
    let base = parts.next().unwrap_or("");
    let parent = parts.next().unwrap_or("");
    if parent.starts_with('@') {
        format!("{parent}/{base}")
    } else {
        base.to_string()
    }
}

fn norm_key(s: &str) -> String {
    s.to_lowercase()
}

fn read_json(path: &Path) -> Result<Option<Value>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let v: Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("Failed to parse {}", path.display()))?;
            Ok(Some(v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

/// Locate the project prefix like npm does: the nearest ancestor containing a
/// package.json or node_modules directory.
pub fn find_prefix(start: &Path) -> PathBuf {
    let mut p = Some(start);
    while let Some(dir) = p {
        if dir.join("package.json").is_file() || dir.join("node_modules").is_dir() {
            return dir.to_path_buf();
        }
        p = dir.parent();
    }
    start.to_path_buf()
}

// ---------------------------------------------------------------------------
// minimatch-ish glob matching for workspace patterns
// ---------------------------------------------------------------------------

fn expand_braces(pat: &str) -> Vec<String> {
    if let Some(open) = pat.find('{') {
        let mut depth = 0;
        let mut close = None;
        for (i, c) in pat[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(close) = close {
            let inner = &pat[open + 1..close];
            let mut out = Vec::new();
            for alt in inner.split(',') {
                let s = format!("{}{}{}", &pat[..open], alt, &pat[close + 1..]);
                out.extend(expand_braces(&s));
            }
            return out;
        }
    }
    vec![pat.to_string()]
}

fn seg_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    fn rec(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| rec(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && rec(&p[1..], &t[1..]),
            Some(c) => t.first() == Some(c) && rec(&p[1..], &t[1..]),
        }
    }
    // minimatch: `*`/`?` do not match a leading dot
    if s.starts_with('.') && pat.starts_with(['*', '?']) {
        return false;
    }
    rec(&p, &t)
}

fn glob_match_segments(pat: &[&str], path: &[&str]) -> bool {
    match pat.first() {
        None => path.is_empty(),
        Some(&"**") => {
            if glob_match_segments(&pat[1..], path) {
                return true;
            }
            !path.is_empty()
                && !path[0].starts_with('.')
                && glob_match_segments(pat, &path[1..])
        }
        Some(p) => !path.is_empty() && seg_match(p, path[0]) && glob_match_segments(&pat[1..], &path[1..]),
    }
}

pub fn glob_match(pattern: &str, path: &str) -> bool {
    for pat in expand_braces(pattern) {
        let pat = pat.trim_end_matches('/');
        let ps: Vec<&str> = pat.split('/').filter(|s| !s.is_empty()).collect();
        let ts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if glob_match_segments(&ps, &ts) {
            return true;
        }
    }
    false
}

/// `mapWorkspaces.virtual`: workspace name -> location, from the lockfile.
fn map_workspaces_virtual(patterns: &[String], packages: &IndexMap<String, Value>) -> IndexMap<String, String> {
    let mut pats = Vec::new();
    let mut negated = Vec::new();
    for raw in patterns {
        let excl = raw.len() - raw.trim_start_matches('!').len();
        let mut pattern = raw[excl..].to_string();
        // strip off any / or ./ from the start of the pattern
        while pattern.starts_with("./") || pattern.starts_with('/') {
            pattern = pattern.trim_start_matches("./").trim_start_matches('/').to_string();
        }
        if excl % 2 == 1 {
            negated.push(pattern);
        } else {
            negated.retain(|n| !glob_match(n, &pattern));
            pats.push(pattern);
        }
    }
    for n in &negated {
        pats.retain(|p| !glob_match(n, p));
    }
    if pats.is_empty() && negated.is_empty() {
        return IndexMap::new();
    }
    negated.push("**/node_modules/**".to_string());
    let mut keys: Vec<&String> = packages.keys().collect();
    for n in &negated {
        keys.retain(|k| !glob_match(n, k));
    }
    let mut by_path: IndexMap<String, String> = IndexMap::new();
    for pat in &pats {
        for key in &keys {
            if glob_match(pat, key) {
                let name = packages[*key]
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| name_from_folder(key));
                by_path.insert((*key).clone(), name);
            }
        }
    }
    let mut out = IndexMap::new();
    for (path, name) in by_path {
        out.insert(name, path);
    }
    out
}

// ---------------------------------------------------------------------------
// lockfile v1 conversion (Shrinkwrap#loadAll + #fixDependencies, simplified)
// ---------------------------------------------------------------------------

fn convert_v1(lock: &Value, root_pkg_json: Option<&Value>) -> IndexMap<String, Value> {
    let mut packages: IndexMap<String, Value> = IndexMap::new();
    let mut root = serde_json::Map::new();
    if let Some(Value::String(n)) = lock.get("name") {
        root.insert("name".into(), Value::String(n.clone()));
    }
    if let Some(pkg) = root_pkg_json {
        for key in [
            "version",
            "dependencies",
            "peerDependencies",
            "peerDependenciesMeta",
            "optionalDependencies",
            "bundleDependencies",
            "workspaces",
        ] {
            if let Some(v) = pkg.get(key) {
                if crate::registry::truthy(Some(v)) {
                    root.insert(key.into(), v.clone());
                }
            }
        }
    }
    packages.insert(String::new(), Value::Object(root));

    fn load_all(location: &str, deps: &Value, packages: &mut IndexMap<String, Value>) {
        let Value::Object(deps) = deps else { return };
        for (name, dep) in deps {
            let loc = if location.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{location}/node_modules/{name}")
            };
            let mut meta = serde_json::Map::new();
            let version = dep.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let mut nested_loc = loc.clone();
            if version.starts_with("file:") && !version.ends_with(".tgz") && !version.ends_with(".tar.gz") && !version.ends_with(".tar") {
                let target = version.trim_start_matches("file:").trim_start_matches("./").to_string();
                meta.insert("link".into(), Value::Bool(true));
                meta.insert("resolved".into(), Value::String(target.clone()));
                packages.entry(target.clone()).or_insert_with(|| Value::Object(serde_json::Map::new()));
                nested_loc = target;
            } else if let Some(rest) = version.strip_prefix("npm:") {
                let at = rest[1.min(rest.len())..].find('@').map(|i| i + 1);
                if let Some(i) = at {
                    meta.insert("name".into(), Value::String(rest[..i].to_string()));
                    meta.insert("version".into(), Value::String(rest[i + 1..].to_string()));
                }
            } else if crate::semver::valid(version, crate::semver::LOOSE).is_some() {
                meta.insert("version".into(), Value::String(version.trim().to_string()));
            } else if !version.is_empty() {
                meta.insert("resolved".into(), Value::String(version.to_string()));
            }
            if let Some(r) = dep.get("resolved") {
                meta.entry("resolved".to_string()).or_insert(r.clone());
            }
            if let Some(i) = dep.get("integrity") {
                meta.insert("integrity".into(), i.clone());
            }
            if crate::registry::truthy(dep.get("dev")) {
                meta.insert("dev".into(), Value::Bool(true));
            }
            if crate::registry::truthy(dep.get("optional")) {
                meta.insert("optional".into(), Value::Bool(true));
            }
            if let Some(req @ Value::Object(_)) = dep.get("requires") {
                meta.insert("requires".into(), req.clone());
            }
            packages.insert(loc, Value::Object(meta));
            if let Some(nested) = dep.get("dependencies") {
                load_all(&nested_loc, nested, packages);
            }
        }
    }
    load_all("", lock.get("dependencies").unwrap_or(&Value::Null), &mut packages);

    // #fixDependencies: turn `requires` into typed dependency maps
    let keys: Vec<String> = packages.keys().cloned().collect();
    for loc in keys {
        if loc.is_empty() {
            continue;
        }
        let Some(Value::Object(requires)) = packages[&loc].get("requires").cloned() else { continue };
        let meta_opt = crate::registry::truthy(packages[&loc].get("optional"));
        let meta_dev = crate::registry::truthy(packages[&loc].get("dev"));
        let mut typed: IndexMap<&str, serde_json::Map<String, Value>> = IndexMap::new();
        for (name, spec) in &requires {
            // resolve the require to a meta entry by walking up
            let mut path = loc.clone();
            let mut dep: Option<&Value> = None;
            loop {
                let check = if path.is_empty() {
                    format!("node_modules/{name}")
                } else {
                    format!("{path}/node_modules/{name}")
                };
                if let Some(d) = packages.get(&check) {
                    dep = Some(d);
                    break;
                }
                if path.is_empty() {
                    break;
                }
                path = match path.rfind('/') {
                    Some(i) => path[..i].to_string(),
                    None => String::new(),
                };
            }
            let dep_opt = dep.map(|d| crate::registry::truthy(d.get("optional"))).unwrap_or(false);
            let dep_dev = dep.map(|d| crate::registry::truthy(d.get("dev"))).unwrap_or(false);
            let ty = if dep_opt && !meta_opt {
                "optionalDependencies"
            } else if dep_dev && !meta_dev {
                "devDependencies"
            } else {
                "dependencies"
            };
            typed.entry(ty).or_default().insert(name.clone(), spec.clone());
        }
        if let Value::Object(m) = &mut packages[&loc] {
            m.remove("requires");
            for (ty, deps) in typed {
                m.insert(ty.to_string(), Value::Object(deps));
            }
        }
    }
    packages
}

// ---------------------------------------------------------------------------
// Tree loading
// ---------------------------------------------------------------------------

impl Tree {
    pub fn load(prefix: &Path) -> Result<Tree> {
        let prefix = prefix.canonicalize().unwrap_or_else(|_| prefix.to_path_buf());
        let lock = match read_json(&prefix.join("npm-shrinkwrap.json"))? {
            Some(v) => v,
            None => match read_json(&prefix.join("package-lock.json"))? {
                Some(v) => v,
                None => bail!("ENOLOCK"),
            },
        };
        let pkg_json = read_json(&prefix.join("package.json"))?;

        let lockfile_version = lock.get("lockfileVersion").and_then(|v| v.as_i64()).unwrap_or(1);
        let ancient = !(lockfile_version >= 2) && !crate::registry::truthy(lock.get("requires"));
        let packages: IndexMap<String, Value> = match lock.get("packages") {
            Some(Value::Object(p)) => p.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            _ if lock.get("dependencies").is_some() => convert_v1(&lock, pkg_json.as_ref()),
            _ => IndexMap::new(),
        };

        let root_value = pkg_json
            .clone()
            .or_else(|| packages.get("").cloned())
            .unwrap_or(Value::Object(Default::default()));
        let root_pkg = Package::from_value(&root_value);

        let mut tree = Tree {
            path: prefix.clone(),
            nodes: Vec::new(),
            edges: Vec::new(),
            by_location: HashMap::new(),
            by_package_name: IndexMap::new(),
        };

        // root node
        let root_name = name_from_folder(&prefix.to_string_lossy());
        tree.add_node(Node {
            location: String::new(),
            name: root_name,
            pkg: root_pkg,
            is_link: false,
            target: None,
            links_in: Vec::new(),
            parent: None,
            fs_parent: None,
            children: HashMap::new(),
            edges_out: IndexMap::new(),
            edges_in: Vec::new(),
            dev: false,
            optional: false,
            dev_optional: false,
            peer: false,
            extraneous: false,
        });

        // regular nodes, in lockfile order
        let mut links: Vec<(String, Value)> = Vec::new();
        for (location, meta) in &packages {
            if location.is_empty() {
                continue;
            }
            if crate::registry::truthy(meta.get("link")) {
                links.push((location.clone(), meta.clone()));
                continue;
            }
            let mut pkg = Package::from_value(meta);
            let name = name_from_folder(location);
            if pkg.name.is_none() {
                pkg.name = Some(name.clone());
            }
            let dev = crate::registry::truthy(meta.get("dev"));
            let optional = crate::registry::truthy(meta.get("optional"));
            let dev_optional = crate::registry::truthy(meta.get("devOptional")) || dev || optional;
            tree.add_node(Node {
                location: location.clone(),
                name,
                pkg,
                is_link: false,
                target: None,
                links_in: Vec::new(),
                parent: None,
                fs_parent: None,
                children: HashMap::new(),
                edges_out: IndexMap::new(),
                edges_in: Vec::new(),
                dev,
                optional,
                dev_optional,
                peer: crate::registry::truthy(meta.get("peer")),
                extraneous: crate::registry::truthy(meta.get("extraneous")),
            });
        }

        // links
        for (location, meta) in &links {
            let resolved = meta.get("resolved").and_then(|r| r.as_str()).unwrap_or("");
            let target_loc = normalize_rel(resolved);
            let Some(&target) = tree.by_location.get(&target_loc) else {
                bail!(
                    "Missing target in lock file: \"{target_loc}\" is referenced by \"{location}\" but does not exist.\nTo fix:\n1. rm package-lock.json\n2. npm install"
                );
            };
            let name = name_from_folder(location);
            let t = &tree.nodes[target];
            let node = Node {
                location: location.clone(),
                name,
                pkg: t.pkg.clone(),
                is_link: true,
                target: Some(target),
                links_in: Vec::new(),
                parent: None,
                fs_parent: None,
                children: HashMap::new(),
                edges_out: IndexMap::new(),
                edges_in: Vec::new(),
                dev: t.dev,
                optional: t.optional,
                dev_optional: t.dev_optional,
                peer: t.peer,
                extraneous: t.extraneous,
            };
            let idx = tree.add_node(node);
            tree.nodes[target].links_in.push(idx);
        }

        // parent / fsParent assignment
        for i in 1..tree.nodes.len() {
            let loc = tree.nodes[i].location.clone();
            let name = tree.nodes[i].name.clone();
            let mut dir = loc.as_str();
            loop {
                dir = match dir.rfind('/') {
                    Some(p) => &dir[..p],
                    None => "",
                };
                if let Some(&anc) = tree.by_location.get(dir) {
                    if tree.nodes[anc].is_link {
                        // never assign parentage to a link; keep walking
                        if dir.is_empty() {
                            break;
                        }
                        continue;
                    }
                    let child_loc = if dir.is_empty() {
                        format!("node_modules/{name}")
                    } else {
                        format!("{dir}/node_modules/{name}")
                    };
                    if child_loc == loc {
                        tree.nodes[i].parent = Some(anc);
                        tree.nodes[anc].children.insert(norm_key(&name), i);
                    } else {
                        tree.nodes[i].fs_parent = Some(anc);
                    }
                    break;
                }
                if dir.is_empty() {
                    break;
                }
            }
        }

        // link targets outside node_modules get their real package.json
        for i in 0..tree.nodes.len() {
            if !tree.nodes[i].is_link {
                continue;
            }
            let target = tree.nodes[i].target.unwrap();
            if tree.nodes[target].parent.is_none() {
                let real = prefix.join(&tree.nodes[target].location).join("package.json");
                if let Ok(Some(v)) = read_json(&real) {
                    let mut pkg = Package::from_value(&v);
                    if pkg.name.is_none() {
                        pkg.name = tree.nodes[target].pkg.name.clone();
                    }
                    tree.nodes[target].pkg = pkg.clone();
                    tree.nodes[i].pkg = pkg;
                }
            }
        }
        // rebuild the packageName index now that packages may have changed
        tree.by_package_name.clear();
        for i in 0..tree.nodes.len() {
            if let Some(n) = tree.nodes[i].pkg.name.clone() {
                tree.by_package_name.entry(n).or_default().push(i);
            }
        }

        // workspaces (root edges of type workspace)
        let ws_patterns = tree.nodes[0]
            .pkg
            .workspaces
            .clone()
            .or_else(|| packages.get("").map(Package::from_value).and_then(|p| p.workspaces))
            .unwrap_or_default();
        let workspaces = map_workspaces_virtual(&ws_patterns, &packages);

        // edges
        for i in 0..tree.nodes.len() {
            if tree.nodes[i].is_link {
                continue;
            }
            if i == 0 {
                for (name, path) in &workspaces {
                    let abs = prefix.join(path).to_string_lossy().to_string();
                    tree.add_edge(i, name, &format!("file:{abs}"), EdgeType::Workspace);
                }
            }
            tree.load_deps(i);
        }

        // dep flags: trust the lockfile unless the root's edges disagree with it
        let lock_root = packages.get("").cloned().unwrap_or(Value::Object(Default::default()));
        let loaded_from_disk = true;
        if loaded_from_disk && !ancient && tree.root_edges_suspect(&lock_root, &workspaces) {
            for i in 1..tree.nodes.len() {
                let n = &mut tree.nodes[i];
                n.extraneous = true;
                n.dev = true;
                n.optional = true;
                n.dev_optional = true;
                n.peer = true;
            }
            tree.calc_dep_flags();
        }

        Ok(tree)
    }

    fn add_node(&mut self, node: Node) -> usize {
        let idx = self.nodes.len();
        self.by_location.insert(node.location.clone(), idx);
        if let Some(n) = node.pkg.name.clone() {
            self.by_package_name.entry(n).or_default().push(idx);
        }
        self.nodes.push(node);
        idx
    }

    fn add_edge(&mut self, from: usize, name: &str, spec: &str, ty: EdgeType) {
        let key = norm_key(name);
        // replace an existing edge of the same name
        if let Some(old) = self.nodes[from].edges_out.shift_remove(&key) {
            if let Some(to) = self.edges[old].to {
                self.nodes[to].edges_in.retain(|&e| e != old);
            }
        }
        let to = self.resolve(from, name);
        let idx = self.edges.len();
        self.edges.push(Edge { from, to, name: name.to_string(), spec: spec.to_string(), ty });
        self.nodes[from].edges_out.insert(key, idx);
        if let Some(to) = to {
            self.nodes[to].edges_in.push(idx);
        }
    }

    fn load_dep_type(&mut self, i: usize, deps: IndexMap<String, String>, ty: EdgeType) {
        for (name, spec) in deps {
            let current = self.nodes[i].edges_out.get(&norm_key(&name)).copied();
            if current.map(|e| self.edges[e].ty != EdgeType::Workspace).unwrap_or(true) {
                self.add_edge(i, &name, &spec, ty);
            }
        }
    }

    fn load_deps(&mut self, i: usize) {
        let pkg = self.nodes[i].pkg.clone();
        let mut peer = IndexMap::new();
        let mut peer_optional = IndexMap::new();
        for (name, spec) in &pkg.peer_dependencies {
            if pkg.peer_optional.contains(name) {
                peer_optional.insert(name.clone(), spec.clone());
            } else {
                peer.insert(name.clone(), spec.clone());
            }
        }
        self.load_dep_type(i, peer, EdgeType::Peer);
        self.load_dep_type(i, peer_optional, EdgeType::PeerOptional);
        self.load_dep_type(i, pkg.dependencies.clone(), EdgeType::Prod);
        self.load_dep_type(i, pkg.optional_dependencies.clone(), EdgeType::Optional);
        if self.is_top(i) {
            self.load_dep_type(i, pkg.dev_dependencies.clone(), EdgeType::Dev);
        }
    }

    pub fn resolve(&self, from: usize, name: &str) -> Option<usize> {
        let key = norm_key(name);
        let mut cur = Some(from);
        while let Some(n) = cur {
            if let Some(&c) = self.nodes[n].children.get(&key) {
                return Some(c);
            }
            cur = self.nodes[n].parent.or(self.nodes[n].fs_parent);
        }
        None
    }

    fn root_edges_suspect(&self, lock_root: &Value, workspaces: &IndexMap<String, String>) -> bool {
        let mut prod = string_map(lock_root.get("dependencies"));
        let dev = string_map(lock_root.get("devDependencies"));
        let optional = string_map(lock_root.get("optionalDependencies"));
        let mut peer = string_map(lock_root.get("peerDependencies"));
        let mut peer_optional = IndexMap::new();
        if let Some(Value::Object(meta)) = lock_root.get("peerDependenciesMeta") {
            for (name, m) in meta {
                if crate::registry::truthy(m.get("optional")) {
                    if let Some(spec) = peer.shift_remove(name) {
                        peer_optional.insert(name.clone(), spec);
                    }
                }
            }
        }
        for name in optional.keys() {
            prod.shift_remove(name);
        }
        let mut lock_ws = IndexMap::new();
        for (name, path) in workspaces {
            lock_ws.insert(name.clone(), format!("file:{}", self.path.join(path).to_string_lossy()));
        }
        let root = &self.nodes[0];
        let mut root_names: HashSet<String> = root.edges_out.keys().cloned().collect();
        let by_type: [(EdgeType, &IndexMap<String, String>); 6] = [
            (EdgeType::Dev, &dev),
            (EdgeType::Optional, &optional),
            (EdgeType::Peer, &peer),
            (EdgeType::PeerOptional, &peer_optional),
            (EdgeType::Prod, &prod),
            (EdgeType::Workspace, &lock_ws),
        ];
        for (ty, deps) in by_type {
            for (name, spec) in deps {
                let key = norm_key(name);
                match root.edges_out.get(&key) {
                    Some(&e) if self.edges[e].ty == ty && &self.edges[e].spec == spec => {}
                    _ => return true,
                }
                root_names.remove(&key);
            }
        }
        !root_names.is_empty()
    }

    fn calc_dep_flags(&mut self) {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut queue = vec![0usize];
        while let Some(node) = queue.pop() {
            seen.insert(node);
            // Unset extraneous from all parents to avoid removal of children.
            if !self.nodes[node].extraneous {
                let mut n = self.resolve_parent(node);
                while let Some(p) = n {
                    if !self.nodes[p].extraneous {
                        break;
                    }
                    self.nodes[p].extraneous = false;
                    n = self.resolve_parent(p);
                }
            }
            if self.nodes[node].is_link {
                let Some(target) = self.nodes[node].target else { continue };
                let mut changed = false;
                let (ldev, lopt, ldevopt, lpeer, lext) = {
                    let l = &self.nodes[node];
                    (l.dev, l.optional, l.dev_optional, l.peer, l.extraneous)
                };
                let t = &mut self.nodes[target];
                if t.dev && !ldev {
                    t.dev = false;
                    changed = true;
                }
                if t.optional && !lopt {
                    t.optional = false;
                    changed = true;
                }
                if t.dev_optional && !ldevopt {
                    t.dev_optional = false;
                    changed = true;
                }
                if t.peer && !lpeer {
                    t.peer = false;
                    changed = true;
                }
                if t.extraneous && !lext {
                    t.extraneous = false;
                    changed = true;
                }
                if changed || !seen.contains(&target) {
                    queue.push(target);
                }
                continue;
            }
            let edges: Vec<usize> = self.nodes[node].edges_out.values().copied().collect();
            for e in edges {
                let edge = &self.edges[e];
                let Some(to) = edge.to else { continue };
                let (peer, optional, dev) = (edge.peer(), edge.optional(), edge.dev());
                let (ndev, nopt, ndevopt, npeer, next) = {
                    let n = &self.nodes[node];
                    (n.dev, n.optional, n.dev_optional, n.peer, n.extraneous)
                };
                let t = &mut self.nodes[to];
                let mut changed = false;
                if t.extraneous && !next && !(peer && optional) {
                    t.extraneous = false;
                    changed = true;
                }
                if t.dev && !ndev && !dev {
                    t.dev = false;
                    changed = true;
                }
                if t.optional && !nopt && !optional {
                    t.optional = false;
                    changed = true;
                }
                if t.dev_optional && !ndevopt && !ndev && !nopt && !dev && !optional {
                    t.dev_optional = false;
                    changed = true;
                }
                if t.peer && !npeer && !peer {
                    t.peer = false;
                    changed = true;
                }
                if changed {
                    queue.push(to);
                }
            }
        }
        seen.remove(&0);
        for i in seen {
            let n = &mut self.nodes[i];
            if n.dev_optional && (n.dev || n.optional) {
                n.dev_optional = false;
            }
        }
    }

    fn resolve_parent(&self, i: usize) -> Option<usize> {
        self.nodes[i].parent.or(self.nodes[i].fs_parent)
    }

    // -- node queries -------------------------------------------------------

    pub fn version(&self, i: usize) -> &str {
        let n = &self.nodes[i];
        if n.is_link {
            if let Some(t) = n.target {
                return self.version(t);
            }
        }
        n.pkg.version.as_deref().unwrap_or("")
    }

    pub fn package_name(&self, i: usize) -> Option<&str> {
        self.nodes[i].pkg.name.as_deref()
    }

    pub fn is_root(&self, i: usize) -> bool {
        i == 0
    }

    pub fn is_project_root(&self, i: usize) -> bool {
        i == 0
    }

    pub fn is_top(&self, i: usize) -> bool {
        self.nodes[i].parent.is_none()
    }

    pub fn top(&self, i: usize) -> usize {
        let mut cur = i;
        while let Some(p) = self.nodes[cur].parent {
            cur = p;
        }
        cur
    }

    pub fn is_workspace(&self, i: usize) -> bool {
        if self.is_project_root(i) {
            return false;
        }
        let Some(name) = self.package_name(i) else { return false };
        let Some(&e) = self.nodes[0].edges_out.get(&norm_key(name)) else { return false };
        let edge = &self.edges[e];
        if edge.ty != EdgeType::Workspace {
            return false;
        }
        match edge.to {
            Some(to) => to == i || self.nodes[to].target == Some(i),
            None => false,
        }
    }

    pub fn should_omit(&self, i: usize, omit: &HashSet<String>) -> bool {
        if omit.is_empty() {
            return false;
        }
        let top = self.top(i);
        if !self.is_project_root(top) && !self.is_workspace(top) {
            return false;
        }
        let n = &self.nodes[i];
        (n.peer && omit.contains("peer"))
            || (n.dev && omit.contains("dev"))
            || (n.optional && omit.contains("optional"))
            || (n.dev_optional && omit.contains("optional") && omit.contains("dev"))
    }
}

fn normalize_rel(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("packages/*", "packages/a"));
        assert!(!glob_match("packages/*", "packages/a/b"));
        assert!(glob_match("packages/**", "packages/a/b"));
        assert!(glob_match("**/node_modules/**", "packages/a/node_modules/x"));
        assert!(glob_match("apps/{web,api}", "apps/api"));
        assert!(!glob_match("packages/*", "node_modules/a"));
    }

    #[test]
    fn names() {
        assert_eq!(name_from_folder("node_modules/@scope/pkg"), "@scope/pkg");
        assert_eq!(name_from_folder("node_modules/a/node_modules/b"), "b");
        assert_eq!(name_from_folder("packages/a"), "a");
    }
}
