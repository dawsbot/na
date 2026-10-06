//! Port of `@npmcli/metavuln-calculator`'s `Advisory` class: given an
//! advisory (or a vulnerable dependency) and a packument, work out which
//! versions of a package are affected, using the exact same bisection
//! heuristics npm uses so the computed ranges match.

use crate::registry::{Manifest, Packument};
use crate::semver::{self, has_dash, LOOSE_PRE};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

/// One entry from the bulk advisory response.
#[derive(Debug, Clone)]
pub struct BulkAdvisory {
    pub id: Value,
    pub title: Option<Value>,
    pub url: Option<Value>,
    pub severity: String,
    pub vulnerable_versions: String,
    pub cwe: Option<Value>,
    pub cvss: Option<Value>,
}

impl BulkAdvisory {
    pub fn from_value(v: &Value) -> BulkAdvisory {
        let get = |k: &str| v.get(k).cloned();
        let severity = match v.get("severity") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(other) if crate::registry::truthy(Some(other)) => other.to_string(),
            _ => "high".to_string(),
        };
        let vulnerable_versions = match v.get("vulnerable_versions") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => "*".to_string(),
        };
        BulkAdvisory {
            id: get("id").unwrap_or(Value::Null),
            title: get("title"),
            url: get("url"),
            severity,
            vulnerable_versions,
            cwe: get("cwe"),
            cvss: get("cvss"),
        }
    }

    /// Key used by the calculator's memo (`security-advisory:<name>:<id>`).
    pub fn id_key(&self) -> String {
        match &self.id {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }
}

pub struct Advisory {
    pub uid: usize,
    pub name: String,
    pub dependency: String,
    /// `source` (the bulk advisory id) — only meaningful for advisories.
    pub source: Option<Value>,
    pub title: Option<Value>,
    pub url: Option<Value>,
    pub severity: String,
    pub cwe: Option<Value>,
    pub cvss: Option<Value>,
    pub packument: Arc<Packument>,
    /// All known versions of `name`, semver-sorted.
    pub versions: Vec<String>,
    source_adv: Option<Arc<Advisory>>,
    range: RwLock<String>,
    vulnerable: Mutex<Vec<String>>,
    vulnerable_set: RwLock<HashSet<String>>,
    version_memo: RwLock<HashMap<String, bool>>,
    spec_memo: RwLock<HashMap<String, bool>>,
}

fn get_dep_spec(mani: &Manifest, name: &str) -> Option<String> {
    let pick = |v: &Option<Value>| -> Option<String> {
        v.as_ref()
            .and_then(|m| m.get(name))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
    };
    pick(&mani.dependencies)
        .or_else(|| pick(&mani.optional_dependencies))
        .or_else(|| pick(&mani.peer_dependencies))
}

impl Advisory {
    pub fn from_bulk(uid: usize, name: &str, src: &BulkAdvisory, packument: Arc<Packument>) -> Arc<Advisory> {
        let adv = Advisory {
            uid,
            name: name.to_string(),
            dependency: name.to_string(),
            source: Some(src.id.clone()),
            title: src.title.clone(),
            url: src.url.clone(),
            severity: src.severity.clone(),
            cwe: src.cwe.clone(),
            cvss: src.cvss.clone(),
            packument,
            versions: Vec::new(),
            source_adv: None,
            range: RwLock::new(src.vulnerable_versions.clone()),
            vulnerable: Mutex::new(Vec::new()),
            vulnerable_set: RwLock::new(HashSet::new()),
            version_memo: RwLock::new(HashMap::new()),
            spec_memo: RwLock::new(HashMap::new()),
        };
        Arc::new(adv.load())
    }

    pub fn from_meta(uid: usize, name: &str, source: Arc<Advisory>, packument: Arc<Packument>) -> Arc<Advisory> {
        let adv = Advisory {
            uid,
            name: name.to_string(),
            dependency: source.name.clone(),
            source: None,
            title: Some(Value::String(format!(
                "Depends on vulnerable versions of {}",
                source.name
            ))),
            url: Some(Value::Null),
            severity: source.severity.clone(),
            cwe: source.cwe.clone(),
            cvss: source.cvss.clone(),
            packument,
            versions: Vec::new(),
            source_adv: Some(source),
            range: RwLock::new(String::new()),
            vulnerable: Mutex::new(Vec::new()),
            vulnerable_set: RwLock::new(HashSet::new()),
            version_memo: RwLock::new(HashMap::new()),
            spec_memo: RwLock::new(HashMap::new()),
        };
        Arc::new(adv.load())
    }

    pub fn is_advisory(&self) -> bool {
        self.dependency == self.name
    }

    pub fn is_metavuln(&self) -> bool {
        !self.is_advisory()
    }

    pub fn range(&self) -> String {
        self.range.read().unwrap().clone()
    }

    /// `load(cached = {}, packument)` for a fresh (uncached) calculation.
    fn load(mut self) -> Advisory {
        let mut versions: Vec<String> = self.packument.versions.keys().cloned().collect();
        semver::sort(&mut versions, LOOSE_PRE);
        self.versions = versions;
        // not cached: everything gets (re)tested
        self.test_versions(&self.versions.clone());
        {
            let mut vulnerable = self.vulnerable.lock().unwrap();
            semver::sort(&mut vulnerable, LOOSE_PRE);
        }
        if self.is_metavuln() {
            self.calculate_range();
        }
        self
    }

    fn calculate_range(&self) {
        // calling semver.simplifyRange with a massive list of versions, and those
        // versions all concatenated with `||` is a geometric CPU explosion!
        // we can try to be a *little* smarter up front by doing x-y for all
        // contiguous version sets in the list
        let versions = &self.versions;
        let vulnerable = self.vulnerable.lock().unwrap().clone();
        let mut ranges: Vec<String> = Vec::new();
        let mut v = 0usize;
        let mut vuln_ver = 0usize;
        while v < versions.len() {
            // figure out the vulnerable subrange
            let mut vr: Vec<String> = vec![versions[v].clone()];
            while v < versions.len() {
                if vuln_ver >= vulnerable.len() || versions[v] != vulnerable[vuln_ver] {
                    // we don't test prerelease versions, so just skip past it
                    if has_dash(&versions[v]) {
                        v += 1;
                        continue;
                    }
                    break;
                }
                if vr.len() > 1 {
                    vr[1] = versions[v].clone();
                } else {
                    vr.push(versions[v].clone());
                }
                v += 1;
                vuln_ver += 1;
            }
            // it'll either be just the first version, which means no overlap,
            // or the start and end versions, which might be the same version
            if vr.len() > 1 {
                let tail = versions.last().unwrap();
                ranges.push(if &vr[1] == tail {
                    format!(">={}", vr[0])
                } else if vr[0] == vr[1] {
                    vr[0].clone()
                } else {
                    format!("{} - {}", vr[0], vr[1])
                });
            }
            v += 1;
        }
        let metavuln = ranges.join(" || ").trim().to_string();
        let range = if metavuln.is_empty() {
            "<0.0.0-0".to_string()
        } else {
            let mut vs = versions.clone();
            semver::simplify_range(&mut vs, &metavuln, LOOSE_PRE)
        };
        *self.range.write().unwrap() = range;
    }

    fn mark_vulnerable(&self, version: &str) {
        if self.vulnerable_set.write().unwrap().insert(version.to_string()) {
            self.vulnerable.lock().unwrap().push(version.to_string());
        }
    }

    /// returns true if marked as vulnerable, false if ok
    pub fn test_version(&self, version: &str, spec: Option<&str>) -> bool {
        if let Some(r) = self.version_memo.read().unwrap().get(version) {
            return *r;
        }
        let result = self.test_version_inner(version, spec);
        if result {
            self.mark_vulnerable(version);
        }
        self.version_memo.write().unwrap().insert(version.to_string(), result);
        result
    }

    fn test_version_inner(&self, version: &str, spec: Option<&str>) -> bool {
        if self.vulnerable_set.read().unwrap().contains(version) {
            return true;
        }
        if self.is_advisory() {
            // advisory, just test range
            let range = self.range();
            return semver::satisfies(version, &range, LOOSE_PRE);
        }

        // check the dependency of this version on the vulnerable dep
        // if we got a version that's not in the packument, fall back on
        // the spec provided, if possible.
        let mani = self.packument.versions.get(version);
        let spec: Option<String> = match spec {
            Some(s) => Some(s.to_string()),
            None => mani.and_then(|m| get_dep_spec(m, &self.dependency)),
        };
        // no dep, no vuln
        let Some(spec) = spec else { return false };

        if !semver::valid_range(&spec, LOOSE_PRE) {
            // not a semver range, nothing we can hope to do about it
            return true;
        }

        let source = self.source_adv.as_ref().expect("metavuln has a source");
        let bundled = mani
            .and_then(|m| m.bundle_dependencies.as_ref())
            .and_then(|bd| bd.as_array())
            .map(|arr| arr.iter().any(|x| x.as_str() == Some(source.name.as_str())))
            .unwrap_or(false);
        // XXX if bundled, then semver.intersects() means vulnerable
        // else, pick a manifest and see if it can't be avoided
        // try to pick a version of the dep that isn't vulnerable
        let avoid = source.range();
        if bundled {
            return semver::intersects(&spec, &avoid, LOOSE_PRE).unwrap_or(false);
        }
        source.test_spec(&spec)
    }

    pub fn test_spec(&self, spec: &str) -> bool {
        if let Some(r) = self.spec_memo.read().unwrap().get(spec) {
            return *r;
        }
        let res = self.test_spec_inner(spec);
        self.spec_memo.write().unwrap().insert(spec.to_string(), res);
        res
    }

    fn test_spec_inner(&self, spec: &str) -> bool {
        let Ok(range) = semver::Range::parse(spec, LOOSE_PRE) else { return true };
        for v in &self.versions {
            if !range.test_str(v) {
                continue;
            }
            if !self.test_version(v, None) {
                return false;
            }
        }
        // either vulnerable, or not installable because nothing satisfied
        // either way, best avoided.
        true
    }

    fn test_versions(&self, versions: &[String]) {
        if versions.is_empty() {
            return;
        }
        // set of lists of versions
        use std::rc::Rc;
        let mut parsed: Vec<Rc<semver::SemVer>> =
            versions.iter().filter_map(|v| semver::parse_cached(v, LOOSE_PRE)).collect();
        parsed.sort_by(|a, b| a.compare(b).then_with(|| a.compare_build(b)));

        let mut sets: Vec<Vec<Rc<semver::SemVer>>> = Vec::new();
        // start out with the versions grouped by major and minor
        let mut last = format!("{}.{}", parsed[0].major, parsed[0].minor);
        sets.push(Vec::new());
        for v in parsed {
            let k = format!("{}.{}", v.major, v.minor);
            if k != last {
                last = k;
                sets.push(Vec::new());
            }
            sets.last_mut().unwrap().push(v);
        }

        let mut i = 0;
        while i < sets.len() {
            let set = sets[i].clone();
            i += 1;
            if set.is_empty() {
                continue;
            }
            let sv = |j: usize| set[j].version.as_str();
            let mut h = 0usize;
            let orig_head_vuln = self.test_version(sv(0), None);
            while h < set.len() && has_dash(sv(h)) {
                h += 1;
            }

            // don't filter out the whole list!  they might all be pr's
            if h == set.len() {
                h = 0;
            } else if orig_head_vuln {
                // if the original was vulnerable, assume so are all of these
                for hh in 0..h {
                    self.mark_vulnerable(sv(hh));
                }
            }

            let mut t = set.len() - 1;
            let orig_tail_vuln = self.test_version(sv(t), None);
            while t > h && has_dash(sv(t)) {
                t -= 1;
            }

            // don't filter out the whole list!  might all be pr's
            if t == h {
                t = set.len() - 1;
            } else if orig_tail_vuln {
                // if original tail was vulnerable, assume these are as well
                let mut tt = set.len() - 1;
                while tt > t {
                    self.mark_vulnerable(sv(tt));
                    tt -= 1;
                }
            }

            let head_vuln = if h == 0 { orig_head_vuln } else { self.test_version(sv(h), None) };
            let tail_vuln =
                if t == set.len() - 1 { orig_tail_vuln } else { self.test_version(sv(t), None) };

            // if head and tail both vulnerable, whole list is thrown out
            if head_vuln && tail_vuln {
                for v in h..t {
                    self.mark_vulnerable(sv(v));
                }
                continue;
            }

            // if length is 2 or 1, then we marked them all already
            if t < h + 2 {
                continue;
            }

            let mid = set.len() / 2;
            let mut pre: Vec<Rc<semver::SemVer>> = set[..mid].to_vec();
            let mut post: Vec<Rc<semver::SemVer>> = set[mid..].to_vec();

            // if the parent list wasn't prereleases, then drop pr tags
            // from end of the pre list, and beginning of the post list,
            // marking as vulnerable if the midpoint item we picked is.
            if !has_dash(&pre[0].version) {
                let mid_vuln = self.test_version(&pre[pre.len() - 1].version, None);
                while pre.last().is_some_and(|v| has_dash(&v.version)) {
                    let v = pre.pop().unwrap();
                    if mid_vuln {
                        self.mark_vulnerable(&v.version);
                    }
                }
            }

            if !has_dash(&post[post.len() - 1].version) {
                let mid_vuln = self.test_version(&post[0].version, None);
                while post.first().is_some_and(|v| has_dash(&v.version)) {
                    let v = post.remove(0);
                    if mid_vuln {
                        self.mark_vulnerable(&v.version);
                    }
                }
            }

            sets.push(pre);
            sets.push(post);
        }
    }
}
