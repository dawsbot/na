//! The slice of `npm-package-arg` that `npm audit` depends on: whether a
//! dependency spec is a registry spec, the alias sub-spec of `npm:` specs, and
//! the registry spec kind (`version` / `range` / `tag`).

use crate::semver;
use regex::Regex;
use std::sync::LazyLock;

static IS_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(?:git[+])?[a-z]+:").unwrap());
static IS_GIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^[^@]+@[^:.]+\.[^:]+:.+$").unwrap());
static IS_FILE_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[.](?:tgz|tar\.gz|tar)$").unwrap());
static IS_POSIX_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[.]|~[/]|[/]|[a-zA-Z]:)").unwrap());

#[derive(Debug, Clone)]
pub struct Spec {
    pub registry: bool,
    /// For `npm:name@spec` aliases: the sub spec's raw spec (`rawSpec`).
    pub sub_spec: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryType {
    Version,
    Range,
    Tag,
}

fn is_file_spec(spec: &str) -> bool {
    if spec.is_empty() {
        return false;
    }
    if spec.to_lowercase().starts_with("file:") {
        return true;
    }
    IS_POSIX_FILE.is_match(spec)
}

fn is_alias_spec(spec: &str) -> bool {
    spec.to_lowercase().starts_with("npm:")
}

fn has_slashes(s: &str) -> bool {
    s.contains('/')
}

/// `npa(arg)` for a bare spec (no `name@` prefix other than what the spec
/// itself contains). `Err` where npm-package-arg would throw.
pub fn npa(arg: &str) -> Result<Spec, String> {
    let name_ends_at = arg[1.min(arg.len())..].find('@').map(|i| i + 1);
    let name_part = match name_ends_at {
        Some(i) if i > 0 => &arg[..i],
        _ => arg,
    };
    let spec: &str;
    if IS_URL.is_match(arg) {
        spec = arg;
    } else if IS_GIT.is_match(arg) {
        // git+ssh://... : never a registry spec
        return Ok(Spec { registry: false, sub_spec: None });
    } else if !name_part.starts_with('@') && (has_slashes(name_part) || IS_FILE_TYPE.is_match(name_part))
    {
        spec = arg;
    } else if let Some(i) = name_ends_at.filter(|i| *i > 0) {
        // `name@spec`
        let s = &arg[i + 1..];
        spec = if s.is_empty() { "*" } else { s };
    } else {
        // either a bare valid package name (=> `name@*`, a registry range) or
        // a spec on its own. Either way it resolves against the registry
        // unless it looks like a file/url/git spec below.
        spec = arg;
    }
    resolve(spec)
}

fn resolve(spec: &str) -> Result<Spec, String> {
    if is_file_spec(spec) {
        return Ok(Spec { registry: false, sub_spec: None });
    }
    if is_alias_spec(spec) {
        let inner = &spec[4..];
        let sub = npa(inner)?;
        if is_alias_spec(inner) {
            return Err("nested aliases not supported".into());
        }
        if !sub.registry {
            return Err("aliases only work for registry deps".into());
        }
        // the sub spec's rawSpec
        let name_ends_at = inner[1.min(inner.len())..].find('@').map(|i| i + 1);
        let raw = match name_ends_at {
            Some(i) if i > 0 => {
                let s = &inner[i + 1..];
                if s.is_empty() { "*" } else { s }
            }
            _ => return Err("aliases must have a name".into()),
        };
        return Ok(Spec { registry: true, sub_spec: Some(raw.to_string()) });
    }
    // hosted git shortcuts, URLs, scp-style git, paths and tarballs are all
    // non-registry specs.
    if IS_URL.is_match(spec) || IS_GIT.is_match(spec) || has_slashes(spec) || IS_FILE_TYPE.is_match(spec) {
        return Ok(Spec { registry: false, sub_spec: None });
    }
    Ok(Spec { registry: true, sub_spec: None })
}

/// Tag names may not contain characters that `encodeURIComponent` encodes.
fn is_valid_tag(spec: &str) -> bool {
    spec.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')')
    })
}

/// `npa.resolve(name, wanted).type` for a registry spec (fromRegistry).
/// `Err` if npa would throw (invalid tag name or not a registry spec).
pub fn registry_type(wanted: &str) -> Result<RegistryType, String> {
    let s = resolve(wanted)?;
    if !s.registry || s.sub_spec.is_some() {
        return Err("Only tag, version, and range are supported".into());
    }
    let spec = wanted.trim();
    if semver::valid(spec, semver::LOOSE).is_some() {
        return Ok(RegistryType::Version);
    }
    if semver::valid_range(spec, semver::LOOSE) {
        return Ok(RegistryType::Range);
    }
    if !is_valid_tag(spec) {
        return Err(format!("Invalid tag name \"{spec}\""));
    }
    Ok(RegistryType::Tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies() {
        assert!(npa("^1.2.3").unwrap().registry);
        assert!(npa("latest").unwrap().registry);
        assert!(npa("1.2.3").unwrap().registry);
        assert!(npa("*").unwrap().registry);
        assert!(npa(">=1 <2").unwrap().registry);
        assert!(!npa("file:../foo").unwrap().registry);
        assert!(!npa("github:user/repo").unwrap().registry);
        assert!(!npa("user/repo").unwrap().registry);
        assert!(!npa("https://x.y/z.tgz").unwrap().registry);
        assert!(!npa("git+ssh://git@github.com/a/b.git").unwrap().registry);
        let a = npa("npm:string-width@^4.2.0").unwrap();
        assert!(a.registry);
        assert_eq!(a.sub_spec.as_deref(), Some("^4.2.0"));
        let a = npa("npm:@scope/name@~1").unwrap();
        assert_eq!(a.sub_spec.as_deref(), Some("~1"));
        assert_eq!(registry_type("^1.0.0").unwrap(), RegistryType::Range);
        assert_eq!(registry_type("1.0.0").unwrap(), RegistryType::Version);
        assert_eq!(registry_type("latest").unwrap(), RegistryType::Tag);
    }
}
