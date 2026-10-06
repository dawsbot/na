//! A faithful port of the parts of node-semver 7.8.5 that `npm audit` relies on.
//!
//! Everything here mirrors the JavaScript implementation operation for
//! operation (regex rewrites included) so that range matching, prerelease
//! handling, loose parsing and `simplifyRange` output are identical to what
//! npm produces.

use regex::Regex;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Opts {
    pub loose: bool,
    pub include_prerelease: bool,
}

pub const STRICT: Opts = Opts { loose: false, include_prerelease: false };
pub const LOOSE: Opts = Opts { loose: true, include_prerelease: false };
pub const PRE: Opts = Opts { loose: false, include_prerelease: true };
pub const LOOSE_PRE: Opts = Opts { loose: true, include_prerelease: true };

const MAX_LENGTH: usize = 256;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

// ---------------------------------------------------------------------------
// Regular expressions (internal/re.js)
// ---------------------------------------------------------------------------

struct Re {
    full: Regex,
    loose: Regex,
    xrange: Regex,
    xrange_loose: Regex,
    tildetrim: Regex,
    tilde: Regex,
    tilde_loose: Regex,
    carettrim: Regex,
    caret: Regex,
    caret_loose: Regex,
    comparator_loose: Regex,
    comparator: Regex,
    comparatortrim: Regex,
    hyphenrange: Regex,
    hyphenrange_loose: Regex,
    star: Regex,
    gte0: Regex,
    gte0pre: Regex,
    build: Regex,
    ws: Regex,
    numeric: Regex,
}

static RE: LazyLock<Re> = LazyLock::new(|| {
    let ldn = "[a-zA-Z0-9-]";
    let nid = "0|[1-9][0-9]*";
    let nidl = "[0-9]+";
    let nonnum = format!("[0-9]*[a-zA-Z-]{ldn}*");
    let mainversion = format!("({nid})\\.({nid})\\.({nid})");
    let mainversion_loose = format!("({nidl})\\.({nidl})\\.({nidl})");
    let prid = format!("(?:{nonnum}|{nid})");
    let pridl = format!("(?:{nonnum}|{nidl})");
    let prerelease = format!("(?:-({prid}(?:\\.{prid})*))");
    let prerelease_loose = format!("(?:-?({pridl}(?:\\.{pridl})*))");
    let bid = format!("{ldn}+");
    let build = format!("(?:\\+({bid}(?:\\.{bid})*))");
    let fullplain = format!("v?{mainversion}{prerelease}?{build}?");
    let looseplain = format!("[v=\\s]*{mainversion_loose}{prerelease_loose}?{build}?");
    let gtlt = "((?:<|>)?=?)";
    let xridl = format!("{nidl}|x|X|\\*");
    let xrid = format!("{nid}|x|X|\\*");
    let xrangeplain = format!(
        "[v=\\s]*({xrid})(?:\\.({xrid})(?:\\.({xrid})(?:{prerelease})?{build}?)?)?"
    );
    let xrangeplain_loose = format!(
        "[v=\\s]*({xridl})(?:\\.({xridl})(?:\\.({xridl})(?:{prerelease_loose})?{build}?)?)?"
    );
    let lonetilde = "(?:~>?)";
    let lonecaret = "(?:\\^)";
    let r = |s: &str| Regex::new(s).expect("semver regex");
    Re {
        full: r(&format!("^{fullplain}$")),
        loose: r(&format!("^{looseplain}$")),
        xrange: r(&format!("^{gtlt}\\s*{xrangeplain}$")),
        xrange_loose: r(&format!("^{gtlt}\\s*{xrangeplain_loose}$")),
        tildetrim: r(&format!("(\\s*){lonetilde}\\s+")),
        tilde: r(&format!("^{lonetilde}{xrangeplain}$")),
        tilde_loose: r(&format!("^{lonetilde}{xrangeplain_loose}$")),
        carettrim: r(&format!("(\\s*){lonecaret}\\s+")),
        caret: r(&format!("^{lonecaret}{xrangeplain}$")),
        caret_loose: r(&format!("^{lonecaret}{xrangeplain_loose}$")),
        comparator_loose: r(&format!("^{gtlt}\\s*({looseplain})$|^$")),
        comparator: r(&format!("^{gtlt}\\s*({fullplain})$|^$")),
        comparatortrim: r(&format!("(\\s*){gtlt}\\s*({looseplain}|{xrangeplain})")),
        hyphenrange: r(&format!("^\\s*({xrangeplain})\\s+-\\s+({xrangeplain})\\s*$")),
        hyphenrange_loose: r(&format!(
            "^\\s*({xrangeplain_loose})\\s+-\\s+({xrangeplain_loose})\\s*$"
        )),
        star: r("(<|>)?=?\\s*\\*"),
        gte0: r("^\\s*>=\\s*0\\.0\\.0\\s*$"),
        gte0pre: r("^\\s*>=\\s*0\\.0\\.0-0\\s*$"),
        build: r(&build),
        ws: r("\\s+"),
        numeric: r("^[0-9]+$"),
    }
});

/// `/-/.test(String(v))` as used by metavuln-calculator.
pub fn has_dash(s: &str) -> bool {
    s.contains('-')
}

// ---------------------------------------------------------------------------
// SemVer (classes/semver.js)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Ident {
    Num(u64),
    Str(String),
}

impl Ident {
    fn is_numeric(&self) -> bool {
        match self {
            Ident::Num(_) => true,
            Ident::Str(s) => RE.numeric.is_match(s),
        }
    }
    fn as_f64(&self) -> f64 {
        match self {
            Ident::Num(n) => *n as f64,
            Ident::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
        }
    }
}

impl std::fmt::Display for Ident {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ident::Num(n) => write!(f, "{n}"),
            Ident::Str(s) => write!(f, "{s}"),
        }
    }
}

/// identifiers.js compareIdentifiers
fn compare_identifiers(a: &Ident, b: &Ident) -> Ordering {
    if let (Ident::Num(x), Ident::Num(y)) = (a, b) {
        return x.cmp(y);
    }
    let anum = a.is_numeric();
    let bnum = b.is_numeric();
    if anum && bnum {
        let (x, y) = (a.as_f64(), b.as_f64());
        return if x == y {
            Ordering::Equal
        } else if x < y {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if a == b {
        return Ordering::Equal;
    }
    if anum && !bnum {
        return Ordering::Less;
    }
    if bnum && !anum {
        return Ordering::Greater;
    }
    let (x, y) = (a.to_string(), b.to_string());
    if x == y {
        Ordering::Equal
    } else if x < y {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[derive(Clone, Debug)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Vec<Ident>,
    pub build: Vec<String>,
    /// The formatted `major.minor.patch[-pre]` string (JS `.version`).
    pub version: String,
    #[allow(dead_code)]
    pub raw: String,
}

fn parse_main(s: &str) -> Result<u64, String> {
    match s.parse::<u64>() {
        Ok(n) if n <= MAX_SAFE_INTEGER => Ok(n),
        _ => Err(format!("Invalid version component: {s}")),
    }
}

impl SemVer {
    pub fn parse(version: &str, opts: Opts) -> Result<SemVer, String> {
        if version.len() > MAX_LENGTH {
            return Err(format!("version is longer than {MAX_LENGTH} characters"));
        }
        let re = if opts.loose { &RE.loose } else { &RE.full };
        let trimmed = version.trim();
        let m = re
            .captures(trimmed)
            .ok_or_else(|| format!("Invalid Version: {version}"))?;
        let major = parse_main(&m[1])?;
        let minor = parse_main(&m[2])?;
        let patch = parse_main(&m[3])?;
        let prerelease = match m.get(4) {
            None => Vec::new(),
            Some(p) => p
                .as_str()
                .split('.')
                .map(|id| {
                    if RE.numeric.is_match(id) {
                        if let Ok(num) = id.parse::<u64>() {
                            if num < MAX_SAFE_INTEGER {
                                return Ident::Num(num);
                            }
                        }
                    }
                    Ident::Str(id.to_string())
                })
                .collect(),
        };
        let build = match m.get(5) {
            None => Vec::new(),
            Some(b) => b.as_str().split('.').map(|s| s.to_string()).collect(),
        };
        let mut v = SemVer {
            major,
            minor,
            patch,
            prerelease,
            build,
            version: String::new(),
            raw: version.to_string(),
        };
        v.version = v.format();
        Ok(v)
    }

    fn format(&self) -> String {
        let mut s = format!("{}.{}.{}", self.major, self.minor, self.patch);
        if !self.prerelease.is_empty() {
            s.push('-');
            s.push_str(
                &self
                    .prerelease
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join("."),
            );
        }
        s
    }

    pub fn compare(&self, other: &SemVer) -> Ordering {
        if other.version == self.version {
            return Ordering::Equal;
        }
        match self.compare_main(other) {
            Ordering::Equal => self.compare_pre(other),
            o => o,
        }
    }

    pub fn compare_main(&self, other: &SemVer) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }

    pub fn compare_pre(&self, other: &SemVer) -> Ordering {
        // NOT having a prerelease is > having one
        if !self.prerelease.is_empty() && other.prerelease.is_empty() {
            return Ordering::Less;
        } else if self.prerelease.is_empty() && !other.prerelease.is_empty() {
            return Ordering::Greater;
        } else if self.prerelease.is_empty() && other.prerelease.is_empty() {
            return Ordering::Equal;
        }
        let mut i = 0;
        loop {
            let a = self.prerelease.get(i);
            let b = other.prerelease.get(i);
            match (a, b) {
                (None, None) => return Ordering::Equal,
                (Some(_), None) => return Ordering::Greater,
                (None, Some(_)) => return Ordering::Less,
                (Some(a), Some(b)) => {
                    if a == b {
                        i += 1;
                        continue;
                    }
                    return compare_identifiers(a, b);
                }
            }
        }
    }

    pub fn compare_build(&self, other: &SemVer) -> Ordering {
        let mut i = 0;
        loop {
            let a = self.build.get(i);
            let b = other.build.get(i);
            match (a, b) {
                (None, None) => return Ordering::Equal,
                (Some(_), None) => return Ordering::Greater,
                (None, Some(_)) => return Ordering::Less,
                (Some(a), Some(b)) => {
                    if a == b {
                        i += 1;
                        continue;
                    }
                    return compare_identifiers(
                        &Ident::Str(a.clone()),
                        &Ident::Str(b.clone()),
                    );
                }
            }
        }
    }
}

thread_local! {
    // index 0: strict, 1: loose
    static SEMVER_CACHE: RefCell<[HashMap<String, Option<Rc<SemVer>>>; 2]> = RefCell::new([HashMap::new(), HashMap::new()]);
    static RANGE_CACHE: RefCell<HashMap<Opts, HashMap<String, Option<Rc<Range>>>>> = RefCell::new(HashMap::new());
    static SIMPLE_RANGE_CACHE: RefCell<HashMap<Opts, HashMap<String, Result<Rc<Vec<Comparator>>, String>>>> = RefCell::new(HashMap::new());
}

/// Cached `new SemVer(version, opts)`; `None` where JS would throw.
pub fn parse_cached(version: &str, opts: Opts) -> Option<Rc<SemVer>> {
    SEMVER_CACHE.with(|c| {
        let idx = opts.loose as usize;
        if let Some(v) = c.borrow()[idx].get(version) {
            return v.clone();
        }
        let parsed = SemVer::parse(version, opts).ok().map(Rc::new);
        c.borrow_mut()[idx].insert(version.to_string(), parsed.clone());
        parsed
    })
}

/// functions/valid.js: the cleaned version string, or None.
pub fn valid(version: &str, opts: Opts) -> Option<String> {
    parse_cached(version, opts).map(|v| v.version.clone())
}

/// functions/clean.js
pub fn clean(version: &str, opts: Opts) -> Option<String> {
    let trimmed = version.trim();
    let stripped = trimmed.trim_start_matches(['=', 'v']);
    parse_cached(stripped, opts).map(|v| v.version.clone())
}

/// functions/compare.js (loose parse); `None` if either side is unparsable.
pub fn compare(a: &str, b: &str, opts: Opts) -> Option<Ordering> {
    let va = parse_cached(a, opts)?;
    let vb = parse_cached(b, opts)?;
    Some(va.compare(&vb))
}

/// functions/sort.js — stable sort by compareBuild. Unparsable entries are
/// dropped (JS would throw here).
pub fn sort(list: &mut Vec<String>, opts: Opts) {
    let mut parsed: Vec<(Rc<SemVer>, String)> = Vec::with_capacity(list.len());
    for v in list.drain(..) {
        if let Some(p) = parse_cached(&v, opts) {
            parsed.push((p, v));
        }
    }
    parsed.sort_by(|a, b| a.0.compare(&b.0).then_with(|| a.0.compare_build(&b.0)));
    list.extend(parsed.into_iter().map(|(_, v)| v));
}

// ---------------------------------------------------------------------------
// Comparator (classes/comparator.js)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Comparator {
    pub operator: String,
    /// `None` is the ANY comparator.
    pub semver: Option<Rc<SemVer>>,
    pub value: String,
}

fn cmp(a: &SemVer, op: &str, b: &SemVer) -> bool {
    let o = a.compare(b);
    match op {
        "" | "=" | "==" => o == Ordering::Equal,
        "!=" => o != Ordering::Equal,
        ">" => o == Ordering::Greater,
        ">=" => o != Ordering::Less,
        "<" => o == Ordering::Less,
        "<=" => o != Ordering::Greater,
        _ => false,
    }
}

impl Comparator {
    pub fn parse(comp: &str, opts: Opts) -> Result<Comparator, String> {
        let comp = RE
            .ws
            .split(comp.trim())
            .collect::<Vec<_>>()
            .join(" ");
        let re = if opts.loose { &RE.comparator_loose } else { &RE.comparator };
        let m = re
            .captures(&comp)
            .ok_or_else(|| format!("Invalid comparator: {comp}"))?;
        let mut operator = m.get(1).map(|g| g.as_str()).unwrap_or("").to_string();
        if operator == "=" {
            operator = String::new();
        }
        let semver = match m.get(2) {
            None => None,
            Some(v) => Some(
                parse_cached(v.as_str(), Opts { loose: opts.loose, include_prerelease: false })
                    .ok_or_else(|| format!("Invalid Version: {}", v.as_str()))?,
            ),
        };
        let value = match &semver {
            None => String::new(),
            Some(s) => format!("{}{}", operator, s.version),
        };
        Ok(Comparator { operator, semver, value })
    }

    pub fn is_any(&self) -> bool {
        self.semver.is_none()
    }

    pub fn test(&self, version: &SemVer) -> bool {
        match &self.semver {
            None => true,
            Some(s) => cmp(version, &self.operator, s),
        }
    }

    pub fn intersects(&self, comp: &Comparator, opts: Opts) -> bool {
        if self.operator.is_empty() {
            if self.value.is_empty() {
                return true;
            }
            return match Range::parse(&comp.value, opts) {
                Ok(r) => r.test_str(&self.value),
                Err(_) => false,
            };
        } else if comp.operator.is_empty() {
            if comp.value.is_empty() {
                return true;
            }
            return match Range::parse(&self.value, opts) {
                Ok(r) => r.test(comp.semver.as_ref().expect("non-any")),
                Err(_) => false,
            };
        }

        // Special cases where nothing can possibly be lower
        if opts.include_prerelease && (self.value == "<0.0.0-0" || comp.value == "<0.0.0-0") {
            return false;
        }
        if !opts.include_prerelease
            && (self.value.starts_with("<0.0.0") || comp.value.starts_with("<0.0.0"))
        {
            return false;
        }
        let (a, b) = (
            self.semver.as_ref().expect("non-any"),
            comp.semver.as_ref().expect("non-any"),
        );
        // Same direction increasing (> or >=)
        if self.operator.starts_with('>') && comp.operator.starts_with('>') {
            return true;
        }
        // Same direction decreasing (< or <=)
        if self.operator.starts_with('<') && comp.operator.starts_with('<') {
            return true;
        }
        // same SemVer and both sides are inclusive (<= or >=)
        if a.version == b.version && self.operator.contains('=') && comp.operator.contains('=') {
            return true;
        }
        // opposite directions less than
        if cmp(a, "<", b) && self.operator.starts_with('>') && comp.operator.starts_with('<') {
            return true;
        }
        // opposite directions greater than
        if cmp(a, ">", b) && self.operator.starts_with('<') && comp.operator.starts_with('>') {
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Range (classes/range.js)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Range {
    #[allow(dead_code)]
    pub raw: String,
    pub set: Vec<Rc<Vec<Comparator>>>,
    pub opts: Opts,
}

fn is_null_set(c: &Comparator) -> bool {
    c.value == "<0.0.0-0"
}

fn is_x(id: Option<&str>) -> bool {
    match id {
        None => true,
        Some(s) => s.is_empty() || s.eq_ignore_ascii_case("x") || s == "*",
    }
}

fn num(s: Option<&str>) -> u64 {
    s.and_then(|s| s.parse::<u64>().ok()).unwrap_or(0)
}

fn g<'a>(m: &'a regex::Captures<'a>, i: usize) -> Option<&'a str> {
    m.get(i).map(|x| x.as_str())
}

fn z(opts: Opts) -> &'static str {
    if opts.include_prerelease {
        "-0"
    } else {
        ""
    }
}

fn replace_tilde(comp: &str, opts: Opts) -> String {
    let re = if opts.loose { &RE.tilde_loose } else { &RE.tilde };
    let Some(m) = re.captures(comp) else {
        return comp.to_string();
    };
    let (mm, mi, p, pr) = (g(&m, 1), g(&m, 2), g(&m, 3), g(&m, 4));
    let z = z(opts);
    if is_x(mm) {
        String::new()
    } else if is_x(mi) {
        let mm = mm.unwrap();
        format!(">={mm}.0.0{z} <{}.0.0-0", num(Some(mm)) + 1)
    } else if is_x(p) {
        let (mm, mi) = (mm.unwrap(), mi.unwrap());
        format!(">={mm}.{mi}.0{z} <{mm}.{}.0-0", num(Some(mi)) + 1)
    } else if let Some(pr) = pr {
        let (mm, mi, p) = (mm.unwrap(), mi.unwrap(), p.unwrap());
        format!(">={mm}.{mi}.{p}-{pr} <{mm}.{}.0-0", num(Some(mi)) + 1)
    } else {
        let (mm, mi, p) = (mm.unwrap(), mi.unwrap(), p.unwrap());
        format!(">={mm}.{mi}.{p} <{mm}.{}.0-0", num(Some(mi)) + 1)
    }
}

fn replace_tildes(comp: &str, opts: Opts) -> String {
    RE.ws
        .split(comp.trim())
        .map(|c| replace_tilde(c, opts))
        .collect::<Vec<_>>()
        .join(" ")
}

fn replace_caret(comp: &str, opts: Opts) -> String {
    let re = if opts.loose { &RE.caret_loose } else { &RE.caret };
    let Some(m) = re.captures(comp) else {
        return comp.to_string();
    };
    let (mm, mi, p, pr) = (g(&m, 1), g(&m, 2), g(&m, 3), g(&m, 4));
    let z = z(opts);
    if is_x(mm) {
        String::new()
    } else if is_x(mi) {
        let mm = mm.unwrap();
        format!(">={mm}.0.0{z} <{}.0.0-0", num(Some(mm)) + 1)
    } else if is_x(p) {
        let (mm, mi) = (mm.unwrap(), mi.unwrap());
        if mm == "0" {
            format!(">={mm}.{mi}.0{z} <{mm}.{}.0-0", num(Some(mi)) + 1)
        } else {
            format!(">={mm}.{mi}.0{z} <{}.0.0-0", num(Some(mm)) + 1)
        }
    } else if let Some(pr) = pr {
        let (mm, mi, p) = (mm.unwrap(), mi.unwrap(), p.unwrap());
        if mm == "0" {
            if mi == "0" {
                format!(">={mm}.{mi}.{p}-{pr} <{mm}.{mi}.{}-0", num(Some(p)) + 1)
            } else {
                format!(">={mm}.{mi}.{p}-{pr} <{mm}.{}.0-0", num(Some(mi)) + 1)
            }
        } else {
            format!(">={mm}.{mi}.{p}-{pr} <{}.0.0-0", num(Some(mm)) + 1)
        }
    } else {
        let (mm, mi, p) = (mm.unwrap(), mi.unwrap(), p.unwrap());
        if mm == "0" {
            if mi == "0" {
                format!(">={mm}.{mi}.{p} <{mm}.{mi}.{}-0", num(Some(p)) + 1)
            } else {
                format!(">={mm}.{mi}.{p} <{mm}.{}.0-0", num(Some(mi)) + 1)
            }
        } else {
            format!(">={mm}.{mi}.{p} <{}.0.0-0", num(Some(mm)) + 1)
        }
    }
}

fn replace_carets(comp: &str, opts: Opts) -> String {
    RE.ws
        .split(comp.trim())
        .map(|c| replace_caret(c, opts))
        .collect::<Vec<_>>()
        .join(" ")
}

fn replace_xrange(comp: &str, opts: Opts) -> String {
    let comp = comp.trim();
    let re = if opts.loose { &RE.xrange_loose } else { &RE.xrange };
    let Some(m) = re.captures(comp) else {
        return comp.to_string();
    };
    let mut gtlt = g(&m, 1).unwrap_or("").to_string();
    let (mm, mi, p) = (g(&m, 2), g(&m, 3), g(&m, 4));
    // invalidXRangeOrder
    if (is_x(mm) && !is_x(mi)) || (is_x(mi) && p.is_some_and(|p| !p.is_empty()) && !is_x(p)) {
        return comp.to_string();
    }
    let xm_major = is_x(mm);
    let xm = xm_major || is_x(mi);
    let xp = xm || is_x(p);
    let any_x = xp;
    if gtlt == "=" && any_x {
        gtlt = String::new();
    }
    let mut pr = z(opts).to_string();

    if xm_major {
        if gtlt == ">" || gtlt == "<" {
            // nothing is allowed
            "<0.0.0-0".to_string()
        } else {
            // nothing is forbidden
            "*".to_string()
        }
    } else if !gtlt.is_empty() && any_x {
        // we know patch is an x, because we have any x at all.
        // replace X with 0
        let mut major = mm.unwrap().to_string();
        let mut minor = if xm { "0".to_string() } else { mi.unwrap().to_string() };
        let patch = "0".to_string();
        if gtlt == ">" {
            // >1 => >=2.0.0
            // >1.2 => >=1.3.0
            gtlt = ">=".to_string();
            if xm {
                major = (num(mm) + 1).to_string();
                minor = "0".to_string();
            } else {
                minor = (num(mi) + 1).to_string();
            }
        } else if gtlt == "<=" {
            // <=0.7.x is actually <0.8.0, since any 0.7.x should
            // pass.  Similarly, <=7.x is actually <8.0.0, etc.
            gtlt = "<".to_string();
            if xm {
                major = (num(mm) + 1).to_string();
            } else {
                minor = (num(mi) + 1).to_string();
            }
        }
        if gtlt == "<" {
            pr = "-0".to_string();
        }
        format!("{gtlt}{major}.{minor}.{patch}{pr}")
    } else if xm {
        let mm = mm.unwrap();
        format!(">={mm}.0.0{pr} <{}.0.0-0", num(Some(mm)) + 1)
    } else if xp {
        let (mm, mi) = (mm.unwrap(), mi.unwrap());
        format!(">={mm}.{mi}.0{pr} <{mm}.{}.0-0", num(Some(mi)) + 1)
    } else {
        comp.to_string()
    }
}

fn replace_xranges(comp: &str, opts: Opts) -> String {
    RE.ws
        .split(comp)
        .map(|c| replace_xrange(c, opts))
        .collect::<Vec<_>>()
        .join(" ")
}

fn replace_stars(comp: &str) -> String {
    RE.star.replacen(comp.trim(), 1, "").into_owned()
}

fn replace_gte0(comp: &str, opts: Opts) -> String {
    let re = if opts.include_prerelease { &RE.gte0pre } else { &RE.gte0 };
    re.replacen(comp.trim(), 1, "").into_owned()
}

fn parse_comparator(comp: &str, opts: Opts) -> String {
    let comp = RE.build.replacen(comp, 1, "").into_owned();
    let comp = replace_carets(&comp, opts);
    let comp = replace_tildes(&comp, opts);
    let comp = replace_xranges(&comp, opts);
    replace_stars(&comp)
}

fn hyphen_replace(m: &regex::Captures<'_>, inc_pr: bool) -> String {
    let from = g(m, 1).unwrap_or("");
    let (fm, fmi, fp, fpr) = (g(m, 2), g(m, 3), g(m, 4), g(m, 5));
    let to = g(m, 7).unwrap_or("");
    let (tm, tmi, tp, tpr) = (g(m, 8), g(m, 9), g(m, 10), g(m, 11));
    let pre = if inc_pr { "-0" } else { "" };

    let from = if is_x(fm) {
        String::new()
    } else if is_x(fmi) {
        format!(">={}.0.0{pre}", fm.unwrap())
    } else if is_x(fp) {
        format!(">={}.{}.0{pre}", fm.unwrap(), fmi.unwrap())
    } else if fpr.is_some() {
        format!(">={from}")
    } else {
        format!(">={from}{pre}")
    };

    let to = if is_x(tm) {
        String::new()
    } else if is_x(tmi) {
        format!("<{}.0.0-0", num(tm) + 1)
    } else if is_x(tp) {
        format!("<{}.{}.0-0", tm.unwrap(), num(tmi) + 1)
    } else if let Some(tpr) = tpr {
        format!("<={}.{}.{}-{tpr}", tm.unwrap(), tmi.unwrap(), tp.unwrap())
    } else if inc_pr {
        format!("<{}.{}.{}-0", tm.unwrap(), tmi.unwrap(), num(tp) + 1)
    } else {
        format!("<={to}")
    };

    format!("{from} {to}").trim().to_string()
}

fn parse_simple_range(range: &str, opts: Opts) -> Result<Rc<Vec<Comparator>>, String> {
    if let Some(hit) = SIMPLE_RANGE_CACHE.with(|c| c.borrow().get(&opts).and_then(|m| m.get(range)).cloned()) {
        return hit;
    }
    let result = parse_simple_range_uncached(range, opts).map(Rc::new);
    SIMPLE_RANGE_CACHE.with(|c| {
        c.borrow_mut().entry(opts).or_default().insert(range.to_string(), result.clone())
    });
    result
}

fn parse_simple_range_uncached(range: &str, opts: Opts) -> Result<Vec<Comparator>, String> {
    // strip build metadata so it can't bleed into the version
    let range = RE.build.replace_all(range, "").into_owned();
    // `1.2.3 - 1.2.4` => `>=1.2.3 <=1.2.4`
    let hr = if opts.loose { &RE.hyphenrange_loose } else { &RE.hyphenrange };
    let range = hr
        .replacen(&range, 1, |m: &regex::Captures<'_>| hyphen_replace(m, opts.include_prerelease))
        .into_owned();
    // `> 1.2.3 < 1.2.5` => `>1.2.3 <1.2.5`
    let range = RE.comparatortrim.replace_all(&range, "$1$2$3").into_owned();
    // `~ 1.2.3` => `~1.2.3`
    let range = RE.tildetrim.replace_all(&range, "$1~").into_owned();
    // `^ 1.2.3` => `^1.2.3`
    let range = RE.carettrim.replace_all(&range, "$1^").into_owned();

    let joined = range
        .split(' ')
        .map(|comp| parse_comparator(comp, opts))
        .collect::<Vec<_>>()
        .join(" ");
    let mut range_list: Vec<String> = RE
        .ws
        .split(&joined)
        .map(|comp| replace_gte0(comp, opts))
        .collect();

    if opts.loose {
        // in loose mode, throw out any that are not valid comparators
        range_list.retain(|comp| RE.comparator_loose.is_match(comp));
    }

    // if any comparators are the null set, then replace with JUST null set
    // if more than one comparator, remove any * comparators
    // also, don't include the same comparator more than once
    let mut comparators = Vec::new();
    for comp in &range_list {
        comparators.push(Comparator::parse(comp, opts)?);
    }
    let mut map: indexmap::IndexMap<String, Comparator> = indexmap::IndexMap::new();
    for comp in comparators {
        if is_null_set(&comp) {
            return Ok(vec![comp]);
        }
        map.insert(comp.value.clone(), comp);
    }
    if map.len() > 1 && map.contains_key("") {
        map.shift_remove("");
    }
    Ok(map.into_values().collect())
}

impl Range {
    pub fn parse(range: &str, opts: Opts) -> Result<Rc<Range>, String> {
        if let Some(hit) = RANGE_CACHE.with(|c| c.borrow().get(&opts).and_then(|m| m.get(range)).cloned()) {
            return hit.ok_or_else(|| format!("Invalid SemVer Range: {range}"));
        }
        let result = Range::parse_uncached(range, opts).map(Rc::new);
        RANGE_CACHE.with(|c| {
            c.borrow_mut().entry(opts).or_default().insert(range.to_string(), result.clone().ok())
        });
        result
    }

    fn parse_uncached(range: &str, opts: Opts) -> Result<Range, String> {
        let raw = RE.ws.replace_all(range.trim(), " ").into_owned();
        let mut set: Vec<Rc<Vec<Comparator>>> = Vec::new();
        for r in raw.split("||") {
            let comps = parse_simple_range(r.trim(), opts)?;
            if !comps.is_empty() {
                set.push(comps);
            }
        }
        if set.is_empty() {
            return Err(format!("Invalid SemVer Range: {raw}"));
        }
        // if we have any that are not the null set, throw out null sets.
        if set.len() > 1 {
            // keep the first one, in case they're all null sets
            let first = set[0].clone();
            set.retain(|c| !is_null_set(&c[0]));
            if set.is_empty() {
                set = vec![first];
            } else if set.len() > 1 {
                // if we have any that are *, then the range is just *
                if let Some(any) = set.iter().find(|c| c.len() == 1 && c[0].is_any()) {
                    set = vec![any.clone()];
                }
            }
        }
        Ok(Range { raw, set, opts })
    }

    /// The `range` getter: formatted comparator sets joined by `||`.
    #[allow(dead_code)]
    pub fn format(&self) -> String {
        self.set
            .iter()
            .map(|comps| {
                comps
                    .iter()
                    .map(|c| c.value.trim().to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("||")
    }

    pub fn test_str(&self, version: &str) -> bool {
        if version.is_empty() {
            return false;
        }
        match parse_cached(version, self.opts) {
            Some(v) => self.test(&v),
            None => false,
        }
    }

    pub fn test(&self, version: &SemVer) -> bool {
        self.set.iter().any(|set| test_set(set, version, self.opts))
    }

    pub fn intersects(&self, other: &Range, opts: Opts) -> bool {
        self.set.iter().any(|this_comps| {
            is_satisfiable(this_comps, opts)
                && other.set.iter().any(|range_comps| {
                    is_satisfiable(range_comps, opts)
                        && this_comps.iter().all(|tc| {
                            range_comps.iter().all(|rc| tc.intersects(rc, opts))
                        })
                })
        })
    }
}

fn test_set(set: &[Comparator], version: &SemVer, opts: Opts) -> bool {
    for c in set {
        if !c.test(version) {
            return false;
        }
    }
    if !version.prerelease.is_empty() && !opts.include_prerelease {
        // Find the set of versions that are allowed to have prereleases
        for c in set {
            let Some(allowed) = &c.semver else { continue };
            if !allowed.prerelease.is_empty()
                && allowed.major == version.major
                && allowed.minor == version.minor
                && allowed.patch == version.patch
            {
                return true;
            }
        }
        // Version has a -pre, but it's not one of the ones we like.
        return false;
    }
    true
}

// take a set of comparators and determine whether there
// exists a version which can satisfy it
fn is_satisfiable(comparators: &[Comparator], opts: Opts) -> bool {
    let mut result = true;
    let mut remaining: Vec<&Comparator> = comparators.iter().collect();
    let mut test = remaining.pop();
    while result && !remaining.is_empty() {
        let t = test.expect("comparator");
        result = remaining.iter().all(|other| t.intersects(other, opts));
        test = remaining.pop();
    }
    result
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// functions/satisfies.js
pub fn satisfies(version: &str, range: &str, opts: Opts) -> bool {
    match Range::parse(range, opts) {
        Ok(r) => r.test_str(version),
        Err(_) => false,
    }
}

/// ranges/valid.js — truthiness of `validRange`.
pub fn valid_range(range: &str, opts: Opts) -> bool {
    Range::parse(range, opts).is_ok()
}

/// ranges/intersects.js. Returns `None` where JS would throw.
pub fn intersects(r1: &str, r2: &str, opts: Opts) -> Option<bool> {
    let a = Range::parse(r1, opts).ok()?;
    let b = Range::parse(r2, opts).ok()?;
    Some(a.intersects(&b, opts))
}

/// ranges/simplify.js. Sorts `versions` in place like the original.
pub fn simplify_range(versions: &mut Vec<String>, range: &str, opts: Opts) -> String {
    {
        let mut parsed: Vec<(Option<Rc<SemVer>>, String)> =
            versions.drain(..).map(|v| (parse_cached(&v, opts), v)).collect();
        parsed.sort_by(|a, b| match (&a.0, &b.0) {
            (Some(x), Some(y)) => x.compare(y),
            _ => Ordering::Equal,
        });
        versions.extend(parsed.into_iter().map(|(_, v)| v));
    }
    let v = &*versions;
    let parsed_range = Range::parse(range, opts).ok();
    let mut set: Vec<(String, Option<String>)> = Vec::new();
    let mut first: Option<String> = None;
    let mut prev: Option<String> = None;
    for version in v {
        let included = parsed_range.as_ref().map(|r| r.test_str(version)).unwrap_or(false);
        if included {
            prev = Some(version.clone());
            if first.is_none() {
                first = Some(version.clone());
            }
        } else {
            if let Some(p) = prev.take() {
                set.push((first.clone().unwrap(), Some(p)));
            }
            prev = None;
            first = None;
        }
    }
    if let Some(f) = first {
        set.push((f, None));
    }

    let mut ranges = Vec::new();
    for (min, max) in &set {
        match max {
            Some(max) if min == max => ranges.push(min.clone()),
            None if Some(min) == v.first() => ranges.push("*".to_string()),
            None => ranges.push(format!(">={min}")),
            Some(max) if Some(min) == v.first() => ranges.push(format!("<={max}")),
            Some(max) => ranges.push(format!("{min} - {max}")),
        }
    }
    let simplified = ranges.join(" || ");
    if simplified.len() < range.len() {
        simplified
    } else {
        range.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        assert!(satisfies("1.2.3", "^1.0.0", STRICT));
        assert!(!satisfies("2.0.0", "^1.0.0", STRICT));
        assert!(satisfies("1.2.3-beta.1", "^1.0.0", PRE));
        assert!(!satisfies("1.2.3-beta.1", "^1.0.0", STRICT));
        assert!(satisfies("1.2.3", "1.2.3 - 1.3", STRICT));
        assert!(satisfies("1.0.0", "*", STRICT));
        assert!(satisfies("1.0.0", "", STRICT));
        assert!(satisfies("1.0.0", ">=1.0.0", STRICT));
        assert!(!satisfies("1.0.0", "<1.0.0", STRICT));
        assert!(valid_range("npm:foo@1", LOOSE_PRE) == false);
        assert_eq!(valid("v1.2.3", LOOSE).as_deref(), Some("1.2.3"));
        assert_eq!(clean(" =v1.2.3 ", LOOSE).as_deref(), Some("1.2.3"));
        assert_eq!(
            Range::parse("~1.2.3", STRICT).unwrap().format(),
            ">=1.2.3 <1.3.0-0"
        );
        assert_eq!(intersects("^1.0.0", "1.5.0", LOOSE_PRE), Some(true));
        assert_eq!(intersects("^1.0.0", "2.0.0", LOOSE_PRE), Some(false));
    }

    #[test]
    fn simplify() {
        let mut versions: Vec<String> =
            ["1.0.0", "1.1.0", "1.2.0", "2.0.0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(simplify_range(&mut versions, "<2.0.0", LOOSE_PRE), "<2.0.0");
        let mut versions: Vec<String> =
            ["1.0.0", "1.1.0", "1.2.0", "2.0.0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            simplify_range(&mut versions, ">=1.0.0 <1.1.0 || >=1.2.0 <2.0.0", LOOSE_PRE),
            "1.0.0 || 1.2.0"
        );
    }
}
