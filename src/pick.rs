//! Port of `npm-pick-manifest` (the parts reachable from `npm audit`):
//! picking the version `npm audit fix --force` would install, with the
//! `avoid` / `avoidStrict` semantics that decide "breaking change" vs
//! "outside the stated dependency range".

use crate::npa::{self, RegistryType};
use crate::registry::{truthy, Manifest, Packument};
use crate::semver;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct PickOpts<'a> {
    pub default_tag: &'a str,
    pub node_version: Option<&'a str>,
    pub npm_version: Option<&'a str>,
    pub avoid: Option<&'a str>,
    pub avoid_strict: bool,
}

/// The fields `#fixAvailable` reads off the picked manifest.
#[derive(Debug, Clone)]
pub struct Picked {
    pub name: Option<String>,
    pub version: Option<String>,
    pub is_semver_major: Option<bool>,
    pub should_avoid: bool,
}

fn should_avoid(ver: &str, avoid: Option<&str>) -> bool {
    match avoid {
        Some(a) => semver::satisfies(ver, a, semver::LOOSE_PRE),
        None => false,
    }
}

fn engine_ok(mani: &Manifest, npm_version: Option<&str>, node_version: Option<&str>) -> bool {
    let Some(eng) = mani.engines.as_ref().filter(|e| truthy(Some(e))) else {
        return true;
    };
    let check = |ver: Option<&str>, key: &str| -> bool {
        // returns true if this engine check FAILS
        let Some(ver) = ver else { return false };
        let Some(req) = eng.get(key).filter(|r| truthy(Some(r))) else { return false };
        match req.as_str() {
            Some(r) => !semver::satisfies(ver, r, semver::PRE),
            // `semver.satisfies(v, <non-string>)` throws inside checkEngine
            None => true,
        }
    };
    !(check(node_version, "node") || check(npm_version, "npm"))
}

fn picked_from(mani: &Manifest, avoid: Option<&str>) -> Picked {
    Picked {
        name: mani.name.as_ref().and_then(|n| n.as_str()).map(|s| s.to_string()),
        version: Some(mani.version.clone()),
        is_semver_major: None,
        should_avoid: should_avoid(&mani.version, avoid),
    }
}

/// Inner `pickManifest`: `Ok(None)` is a falsy result, `Err` a thrown error.
fn pick(paku: &Packument, wanted: &str, opts: &PickOpts) -> Result<Option<Picked>, ()> {
    if opts.avoid_strict {
        let loose = PickOpts { avoid_strict: false, ..opts.clone() };
        let result = pick(paku, wanted, &loose)?;
        let result = match result {
            Some(r) if r.should_avoid => r,
            other => return Ok(other),
        };
        let caret = pick(paku, &format!("^{}", result.version.as_deref().unwrap_or("")), &loose)?;
        match caret {
            Some(c) if c.should_avoid => {}
            other => {
                return Ok(Some(Picked {
                    name: other.as_ref().and_then(|c| c.name.clone()),
                    version: other.as_ref().and_then(|c| c.version.clone()),
                    is_semver_major: Some(false),
                    should_avoid: other.as_ref().map(|c| c.should_avoid).unwrap_or(false),
                }))
            }
        }
        let star = pick(paku, "*", &loose)?;
        match star {
            Some(s) if s.should_avoid => {}
            other => {
                return Ok(Some(Picked {
                    name: other.as_ref().and_then(|c| c.name.clone()),
                    version: other.as_ref().and_then(|c| c.version.clone()),
                    is_semver_major: Some(true),
                    should_avoid: other.as_ref().map(|c| c.should_avoid).unwrap_or(false),
                }))
            }
        }
        // No avoidable versions
        return Err(());
    }

    let versions = &paku.versions;
    let ty = npa::registry_type(wanted).map_err(|_| ())?;
    let dist_tags = &paku.dist_tags;

    // if the type is 'tag', and not just the implicit default, then it must be that exactly, or nothing else will do.
    if ty == RegistryType::Tag {
        let ver = dist_tags.get(wanted).and_then(|v| v.as_str());
        // isBefore is always true without a `before` date
        return Ok(ver.and_then(|v| versions.get(v)).map(|m| picked_from(m, opts.avoid)));
    }

    // similarly, if a specific version, then only that version will do
    if ty == RegistryType::Version {
        let ver = semver::clean(wanted, semver::LOOSE).unwrap_or_default();
        return Ok(versions.get(&ver).map(|m| picked_from(m, opts.avoid)));
    }

    // ok, sort based on our heuristics, and pick the best fit
    let range = wanted;

    // if the range is *, then we prefer the 'latest' if available but skip this if it should be avoided
    if let Some(default_ver) = dist_tags.get(opts.default_tag).and_then(|v| v.as_str()) {
        if (range == "*" || semver::satisfies(default_ver, range, semver::LOOSE))
            && !should_avoid(default_ver, opts.avoid)
        {
            if let Some(mani) = versions.get(default_ver) {
                let ok = engine_ok(mani, opts.npm_version, opts.node_version)
                    && !truthy(mani.deprecated.as_ref());
                if ok {
                    return Ok(Some(picked_from(mani, opts.avoid)));
                }
            }
        }
    }

    if versions.is_empty() {
        // No versions available
        return Err(());
    }

    // ok, actually have to sort the list and take the winner
    let best = versions
        .iter()
        .filter(|(ver, _)| semver::satisfies(ver, range, semver::LOOSE))
        .max_by(|(va, ma), (vb, mb)| {
            let notavoid_a = !should_avoid(va, opts.avoid);
            let notavoid_b = !should_avoid(vb, opts.avoid);
            let notdepr_a = !truthy(ma.deprecated.as_ref());
            let notdepr_b = !truthy(mb.deprecated.as_ref());
            let engine_a = engine_ok(ma, opts.npm_version, opts.node_version);
            let engine_b = engine_ok(mb, opts.npm_version, opts.node_version);
            // sort by: not avoided, not deprecated and engine ok, engine ok, not deprecated, semver
            notavoid_a
                .cmp(&notavoid_b)
                .then((notdepr_a && engine_a).cmp(&(notdepr_b && engine_b)))
                .then(engine_a.cmp(&engine_b))
                .then(notdepr_a.cmp(&notdepr_b))
                .then(semver::compare(va, vb, semver::LOOSE).unwrap_or(Ordering::Equal))
        });
    Ok(best.map(|(_, m)| picked_from(m, opts.avoid)))
}

/// The exported `pickManifest(packument, wanted, opts)`: `Err` where it throws.
pub fn pick_manifest(paku: &Packument, wanted: &str, opts: &PickOpts) -> Result<Picked, ()> {
    match pick(paku, wanted, opts)? {
        Some(p) => Ok(p),
        None => Err(()),
    }
}
