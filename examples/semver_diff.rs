//! Differential test driver for the node-semver port.
//!
//! Reads one JSON object per line from stdin and prints one JSON result per
//! line. Used by test/semver-diff.mjs, which runs the same cases through the
//! real `semver` package and compares.
//!
//! Case shapes:
//!   {"op":"satisfies","v":"1.2.3","r":"^1.0.0","loose":true,"pre":false}
//!   {"op":"validRange","r":"^1.0.0","loose":true,"pre":true}
//!   {"op":"valid","v":"v1.2.3","loose":true}
//!   {"op":"intersects","r":"^1.0.0","r2":"<2","loose":true,"pre":true}
//!   {"op":"simplify","versions":[...],"r":"<2","loose":true,"pre":true}
//!   {"op":"sort","versions":[...],"loose":true,"pre":true}
//!   {"op":"clean","v":" =v1.2.3","loose":true}

#[path = "../src/semver.rs"]
#[allow(dead_code)]
mod semver;

use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let case: serde_json::Value = serde_json::from_str(&line).unwrap();
        let opts = semver::Opts {
            loose: case["loose"].as_bool().unwrap_or(false),
            include_prerelease: case["pre"].as_bool().unwrap_or(false),
        };
        let s = |k: &str| case[k].as_str().unwrap_or("").to_string();
        let versions = || -> Vec<String> {
            case["versions"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default()
        };
        let result = match case["op"].as_str().unwrap_or("") {
            "satisfies" => serde_json::json!(semver::satisfies(&s("v"), &s("r"), opts)),
            "validRange" => serde_json::json!(semver::valid_range(&s("r"), opts)),
            "valid" => serde_json::json!(semver::valid(&s("v"), opts)),
            "clean" => serde_json::json!(semver::clean(&s("v"), opts)),
            "intersects" => serde_json::json!(semver::intersects(&s("r"), &s("r2"), opts)),
            "simplify" => {
                let mut v = versions();
                serde_json::json!(semver::simplify_range(&mut v, &s("r"), opts))
            }
            "sort" => {
                let mut v = versions();
                semver::sort(&mut v, opts);
                serde_json::json!(v)
            }
            "format" => serde_json::json!(semver::Range::parse(&s("r"), opts).ok().map(|r| r.format())),
            other => serde_json::json!({ "error": format!("unknown op {other}") }),
        };
        writeln!(out, "{}", result).unwrap();
    }
}
