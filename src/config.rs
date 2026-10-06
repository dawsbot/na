//! The small slice of npm configuration that affects `npm audit` output:
//! registry (incl. scoped registries and auth tokens), audit-level, color
//! and the default dist-tag, from `.npmrc` files and `npm_config_*` env vars.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct NpmConfig {
    pub registry: String,
    pub audit_registry: Option<String>,
    pub scopes: HashMap<String, String>,
    pub tokens: HashMap<String, String>,
    pub audit_level: Option<String>,
    pub color: Option<String>,
    pub tag: String,
}

impl Default for NpmConfig {
    fn default() -> Self {
        NpmConfig {
            registry: "https://registry.npmjs.org".to_string(),
            audit_registry: None,
            scopes: HashMap::new(),
            tokens: HashMap::new(),
            audit_level: None,
            color: None,
            tag: "latest".to_string(),
        }
    }
}

fn expand_env(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        match rest[start..].find('}') {
            Some(end) => {
                let var = &rest[start + 2..start + end];
                out.push_str(&std::env::var(var).unwrap_or_default());
                rest = &rest[start + end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_npmrc(path: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim().to_string();
        let mut v = v.trim().to_string();
        if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            v = v[1..v.len() - 1].to_string();
        }
        out.push((k, expand_env(&v)));
    }
    out
}

impl NpmConfig {
    fn apply(&mut self, key: &str, value: &str) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        if let Some(scope) = key.strip_suffix(":registry") {
            if scope.starts_with('@') {
                self.scopes.insert(scope.to_string(), value.trim_end_matches('/').to_string());
            }
            return;
        }
        if let Some(reg) = key.strip_suffix(":_authToken") {
            let reg = reg.trim_start_matches("//").trim_end_matches('/').to_string();
            self.tokens.insert(reg, value.to_string());
            return;
        }
        match key {
            "registry" => self.registry = value.trim_end_matches('/').to_string(),
            "audit-registry" | "audit_registry" => {
                self.audit_registry = Some(value.trim_end_matches('/').to_string())
            }
            "audit-level" | "audit_level" => self.audit_level = Some(value.to_string()),
            "color" => self.color = Some(value.to_string()),
            "tag" => self.tag = value.to_string(),
            _ => {}
        }
    }

    pub fn load(prefix: &Path) -> NpmConfig {
        let mut cfg = NpmConfig::default();
        let user_rc = std::env::var("NPM_CONFIG_USERCONFIG")
            .ok()
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var("HOME").ok().map(|h| Path::new(&h).join(".npmrc")));
        if let Some(p) = user_rc {
            for (k, v) in parse_npmrc(&p) {
                cfg.apply(&k, &v);
            }
        }
        for (k, v) in parse_npmrc(&prefix.join(".npmrc")) {
            cfg.apply(&k, &v);
        }
        for (k, v) in std::env::vars() {
            if let Some(name) = k.strip_prefix("npm_config_") {
                cfg.apply(&name.replace('_', "-"), &v);
            }
        }
        cfg
    }
}
