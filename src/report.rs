//! Port of `npm-audit-report`: the `detail` reporter, the install summary,
//! the exit code rule, and `JSON.stringify(data, null, 2)` output.

use serde_json::{Map, Value};
use std::collections::HashSet;

pub struct Colors {
    pub enabled: bool,
}

impl Colors {
    fn wrap(&self, open: &str, close: &str, s: &str) -> String {
        if !self.enabled || s.is_empty() {
            s.to_string()
        } else {
            format!("{open}{s}{close}")
        }
    }
    /// chalk.bold
    pub fn white(&self, s: &str) -> String {
        self.wrap("\x1b[1m", "\x1b[22m", s)
    }
    /// chalk.green.bold
    pub fn green(&self, s: &str) -> String {
        self.wrap("\x1b[32m\x1b[1m", "\x1b[22m\x1b[39m", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("\x1b[31m\x1b[1m", "\x1b[22m\x1b[39m", s)
    }
    pub fn magenta(&self, s: &str) -> String {
        self.wrap("\x1b[35m\x1b[1m", "\x1b[22m\x1b[39m", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("\x1b[33m\x1b[1m", "\x1b[22m\x1b[39m", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("\x1b[2m", "\x1b[22m", s)
    }
    pub fn severity(&self, sev: &str) -> String {
        match sev.to_lowercase().as_str() {
            "moderate" => self.yellow(sev),
            "high" => self.red(sev),
            "critical" => self.magenta(sev),
            _ => self.white(sev),
        }
    }
}

fn js_str(v: Option<&Value>) -> String {
    match v {
        None => "undefined".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => "null".to_string(),
        Some(other) => other.to_string(),
    }
}

fn count(v: &Value) -> i64 {
    v.as_i64().unwrap_or(0)
}

struct Summary {
    summary: String,
}

fn calculate(data: &Value, c: &Colors) -> Summary {
    let mut output: Vec<String> = Vec::new();
    let vulnerabilities = &data["metadata"]["vulnerabilities"];
    let vuln_count = count(&vulnerabilities["total"]);

    let mut some_fixable = false;
    let mut some_force_fixable = false;
    let mut force_fix_semver_major = false;
    let mut some_unfixable = false;

    if vuln_count == 0 {
        output.push(format!("found {} vulnerabilities", c.green("0")));
    } else {
        if let Some(vulns) = data["vulnerabilities"].as_object() {
            for (_, vuln) in vulns {
                let fa = &vuln["fixAvailable"];
                some_fixable = some_fixable || fa == &Value::Bool(true);
                some_unfixable = some_unfixable || fa == &Value::Bool(false);
                if fa.is_object() {
                    some_force_fixable = true;
                    force_fix_semver_major = force_fix_semver_major
                        || crate::registry::truthy(fa.get("isSemVerMajor"));
                }
            }
        }
        let total = vuln_count;
        let sevs: Vec<(&String, i64)> = vulnerabilities
            .as_object()
            .map(|m| {
                m.iter()
                    .filter(|(s, n)| {
                        matches!(s.as_str(), "low" | "moderate" | "high" | "critical") && count(n) > 0
                    })
                    .map(|(s, n)| (s, count(n)))
                    .collect()
            })
            .unwrap_or_default();

        if sevs.len() > 1 {
            let severities = sevs
                .iter()
                .map(|(s, n)| format!("{n} {}", c.severity(s)))
                .collect::<Vec<_>>()
                .join(", ");
            output.push(format!("{} vulnerabilities ({severities})", c.red(&total.to_string())));
        } else {
            let (sev, n) = sevs
                .first()
                .map(|(s, n)| (s.to_string(), *n))
                .unwrap_or(("info".to_string(), total));
            output.push(format!(
                "{n} {} severity vulnerabilit{}",
                c.severity(&sev),
                if n == 1 { "y" } else { "ies" }
            ));
        }

        if some_fixable {
            output.push(String::new());
            output.push(format!(
                "To address {}, run:\n  npm audit fix",
                if some_force_fixable || some_unfixable {
                    "issues that do not require attention"
                } else {
                    "all issues"
                }
            ));
        }

        if some_force_fixable {
            output.push(String::new());
            output.push(format!(
                "To address all issues{}{}, run:\n  npm audit fix --force",
                if some_unfixable { " possible" } else { "" },
                if force_fix_semver_major { " (including breaking changes)" } else { "" }
            ));
        }

        if some_unfixable {
            output.push(String::new());
            output.push("Some issues need review, and may require choosing".to_string());
            output.push("a different dependency.".to_string());
        }
    }

    Summary { summary: output.join("\n") }
}

/// reporters/detail.js
pub fn detail(data: &Value, c: &Colors) -> String {
    let summary = calculate(data, c).summary;
    let none = count(&data["metadata"]["vulnerabilities"]["total"]) == 0;
    if none {
        return summary;
    }
    let empty = Map::new();
    let vulns = data["vulnerabilities"].as_object().unwrap_or(&empty);
    let mut output: Vec<Option<String>> = vec![Some(c.white("# npm audit report")), Some(String::new())];
    let mut printed: HashSet<String> = HashSet::new();
    for (_, vuln) in vulns {
        // only print starting from the top-level advisories
        let has_advisory = vuln["via"]
            .as_array()
            .map(|a| a.iter().any(|v| !v.is_string()))
            .unwrap_or(false);
        if has_advisory {
            output.push(print_vuln(vuln, c, vulns, &mut printed, ""));
        }
    }
    output.push(Some(summary));
    output
        .iter()
        .map(|o| o.as_deref().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

fn print_vuln(
    vuln: &Value,
    c: &Colors,
    vulns: &Map<String, Value>,
    printed: &mut HashSet<String>,
    indent: &str,
) -> Option<String> {
    let name = js_str(vuln.get("name"));
    if printed.contains(&name) {
        return None;
    }
    printed.insert(name.clone());
    let mut output: Vec<String> = Vec::new();

    output.push(format!("{}  {}", c.white(&name), js_str(vuln.get("range"))));

    let severity = js_str(vuln.get("severity"));
    if indent.is_empty() && (severity != "low" || severity == "info") {
        output.push(format!("Severity: {}", c.severity(&severity)));
    }

    if let Some(via) = vuln["via"].as_array() {
        for v in via {
            if let Value::String(s) = v {
                output.push(format!("Depends on vulnerable versions of {}", c.white(s)));
            } else if indent.is_empty() {
                output.push(format!(
                    "{} - {}",
                    c.white(&js_str(v.get("title"))),
                    js_str(v.get("url"))
                ));
            }
        }
    }

    if indent.is_empty() {
        let fa = &vuln["fixAvailable"];
        if fa == &Value::Bool(false) {
            output.push(c.red("No fix available"));
        } else if fa == &Value::Bool(true) {
            output.push(format!("{} via `npm audit fix`", c.green("fix available")));
        } else if fa.is_object() {
            output.push(format!("{} via `npm audit fix --force`", c.yellow("fix available")));
            output.push(format!(
                "Will install {}@{}, which is {}",
                js_str(fa.get("name")),
                js_str(fa.get("version")),
                if crate::registry::truthy(fa.get("isSemVerMajor")) {
                    "a breaking change"
                } else {
                    "outside the stated dependency range"
                }
            ));
        }
    }

    if let Some(nodes) = vuln["nodes"].as_array() {
        for path in nodes {
            output.push(c.dim(&js_str(Some(path))));
        }
    }

    if let Some(effects) = vuln["effects"].as_array() {
        for effect in effects {
            let Some(ev) = effect.as_str().and_then(|e| vulns.get(e)) else { continue };
            if let Some(e) = print_vuln(ev, c, vulns, printed, "  ") {
                output.extend(e.split('\n').map(|s| s.to_string()));
            }
        }
    }

    if indent.is_empty() {
        output.push(String::new());
    }

    Some(output.iter().map(|l| format!("{indent}{l}")).collect::<Vec<_>>().join("\n"))
}

/// exit-code.js: 1 if any vulns at or above `level`.
pub fn exit_code(data: &Value, level: &str) -> i32 {
    const SEVERITIES: [&str; 6] = ["info", "low", "moderate", "high", "critical", "none"];
    let Some(li) = SEVERITIES.iter().position(|s| *s == level) else { return 0 };
    let Some(m) = data["metadata"]["vulnerabilities"].as_object() else { return 0 };
    for (sev, n) in m {
        if count(n) > 0 {
            if let Some(si) = SEVERITIES.iter().position(|s| s == sev) {
                if si >= li {
                    return 1;
                }
            }
        }
    }
    0
}

/// Make floats that JavaScript would print as integers print as integers.
fn normalize_numbers(v: &mut Value) {
    match v {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if n.as_i64().is_none() && f.fract() == 0.0 && f.abs() < 1e15 {
                    *v = Value::from(f as i64);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(normalize_numbers),
        Value::Object(o) => o.values_mut().for_each(normalize_numbers),
        _ => {}
    }
}

/// reporters/json.js: `JSON.stringify(data, null, 2)`
pub fn json(data: &Value) -> String {
    let mut v = data.clone();
    normalize_numbers(&mut v);
    serde_json::to_string_pretty(&v).unwrap_or_default()
}
