//! Registry access: the bulk advisory endpoint and (corgi) packuments, with a
//! shared in-memory packument cache so every name is fetched at most once and
//! fetches can be started speculatively ahead of when they are needed.

use anyhow::{Context, Result};
use futures::future::{BoxFuture, FutureExt, Shared};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

const CORGI_ACCEPT: &str = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*";

/// Counters for `--timing`.
pub mod stats {
    use std::sync::atomic::AtomicU64;
    pub static FETCHED: AtomicU64 = AtomicU64::new(0);
    pub static BYTES: AtomicU64 = AtomicU64::new(0);
    pub static PARSE_NS: AtomicU64 = AtomicU64::new(0);
    pub static NET_NS: AtomicU64 = AtomicU64::new(0);
    pub static FAILED: AtomicU64 = AtomicU64::new(0);
    pub static CACHE_FRESH: AtomicU64 = AtomicU64::new(0);
    pub static CACHE_REVALIDATED: AtomicU64 = AtomicU64::new(0);
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct Manifest {
    pub name: Option<Value>,
    #[serde(default)]
    pub version: String,
    pub dependencies: Option<Value>,
    #[serde(rename = "optionalDependencies")]
    pub optional_dependencies: Option<Value>,
    #[serde(rename = "peerDependencies")]
    pub peer_dependencies: Option<Value>,
    #[serde(rename = "bundleDependencies")]
    pub bundle_dependencies: Option<Value>,
    pub engines: Option<Value>,
    pub deprecated: Option<Value>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Packument {
    #[serde(default)]
    #[allow(dead_code)]
    pub name: String,
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: IndexMap<String, Value>,
    #[serde(default)]
    pub versions: IndexMap<String, Manifest>,
}

impl Packument {
    pub fn empty(name: &str) -> Packument {
        Packument { name: name.to_string(), ..Default::default() }
    }
}

/// JavaScript truthiness of a JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_)) | Some(Value::Object(_)) => true,
    }
}

#[derive(Clone, Debug, Default)]
pub struct RegistryConfig {
    /// Default registry, no trailing slash.
    pub registry: String,
    /// `@scope` -> registry url (no trailing slash).
    pub scopes: HashMap<String, String>,
    /// registry url (no trailing slash) -> bearer token.
    pub tokens: HashMap<String, String>,
    pub audit_registry: Option<String>,
    pub concurrency: usize,
    pub user_agent: String,
    /// On-disk packument cache (None disables caching).
    pub cache_dir: Option<PathBuf>,
    /// Always revalidate cached packuments, even inside their max-age.
    pub prefer_online: bool,
}

type PackumentFuture = Shared<BoxFuture<'static, Arc<Packument>>>;

pub struct Registry {
    client: reqwest::Client,
    cfg: RegistryConfig,
    sem: Arc<Semaphore>,
    cache: Mutex<HashMap<String, PackumentFuture>>,
}

fn strip_slash(s: &str) -> String {
    s.trim_end_matches('/').to_string()
}

impl Registry {
    pub fn new(cfg: RegistryConfig) -> Result<Arc<Registry>> {
        let client = reqwest::Client::builder()
            .user_agent(cfg.user_agent.clone())
            .gzip(true)
            .pool_max_idle_per_host(16)
            .build()
            .context("building HTTP client")?;
        let sem = Arc::new(Semaphore::new(cfg.concurrency.max(1)));
        Ok(Arc::new(Registry { client, cfg, sem, cache: Mutex::new(HashMap::new()) }))
    }

    fn registry_for(&self, name: &str) -> String {
        if let Some(scope) = name.strip_prefix('@').and_then(|rest| rest.split('/').next()) {
            if let Some(url) = self.cfg.scopes.get(&format!("@{scope}")) {
                return strip_slash(url);
            }
        }
        strip_slash(&self.cfg.registry)
    }

    fn auth_for(&self, registry: &str) -> Option<&String> {
        let reg = strip_slash(registry);
        self.cfg.tokens.get(&reg).or_else(|| {
            // tokens are usually keyed by `//host/path/`; try without scheme
            let no_scheme = reg.splitn(2, "//").nth(1).unwrap_or(&reg).to_string();
            self.cfg.tokens.get(&no_scheme)
        })
    }

    /// POST the bulk advisory request. Returns the parsed response object in
    /// the order the registry sent it.
    pub async fn bulk_advisories(
        &self,
        body: &IndexMap<String, Vec<String>>,
    ) -> Result<IndexMap<String, Vec<Value>>> {
        let registry = strip_slash(self.cfg.audit_registry.as_deref().unwrap_or(&self.cfg.registry));
        let url = format!("{registry}/-/npm/v1/security/advisories/bulk");
        let json = serde_json::to_vec(body)?;
        let gz = {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(&json)?;
            enc.finish()?
        };
        let mut req = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("content-encoding", "gzip")
            .header("accept", "application/json")
            .body(gz);
        if let Some(tok) = self.auth_for(&registry) {
            req = req.bearer_auth(tok);
        }
        let res = req.send().await.context("Failed to call npm bulk advisory API")?;
        let status = res.status();
        if !status.is_success() {
            let text = res.text().await.unwrap_or_default();
            anyhow::bail!("audit endpoint returned an error: {status} {text}");
        }
        let bytes = res.bytes().await?;
        let parsed: IndexMap<String, Vec<Value>> =
            serde_json::from_slice(&bytes).context("Failed to parse bulk advisory response")?;
        Ok(parsed)
    }

    /// Start fetching a packument (no-op if already started).
    pub fn prefetch(self: &Arc<Self>, name: &str) {
        let _ = self.packument_future(name);
    }

    /// Await the packument for `name`; failures resolve to an empty packument
    /// exactly like metavuln-calculator's `.catch(() => ({name, versions: {}}))`.
    pub async fn packument(self: &Arc<Self>, name: &str) -> Arc<Packument> {
        let fut = self.packument_future(name);
        fut.await
    }

    /// True if the packument for `name` has already arrived.
    pub fn packument_ready(self: &Arc<Self>, name: &str) -> bool {
        self.packument_future(name).peek().is_some()
    }

    fn packument_future(self: &Arc<Self>, name: &str) -> PackumentFuture {
        let mut cache = self.cache.lock().expect("packument cache");
        if let Some(f) = cache.get(name) {
            return f.clone();
        }
        let this = self.clone();
        let n = name.to_string();
        let handle = tokio::spawn(async move { this.fetch_packument(&n).await });
        let fut: BoxFuture<'static, Arc<Packument>> = async move {
            match handle.await {
                Ok(p) => p,
                Err(_) => Arc::new(Packument::default()),
            }
        }
        .boxed();
        let shared = fut.shared();
        cache.insert(name.to_string(), shared.clone());
        shared
    }

    async fn fetch_packument(&self, name: &str) -> Arc<Packument> {
        use std::sync::atomic::Ordering::Relaxed;
        let registry = self.registry_for(name);
        let escaped = name.replacen('/', "%2f", 1);
        let url = format!("{registry}/{escaped}");
        let paths = self.cache_paths(&registry, &escaped);

        // 1. a cached copy that is still within its max-age needs no request
        //    (this is what npm's make-fetch-happen cache does too).
        let mut cached: Option<(bytes::Bytes, CacheMeta)> = None;
        if let Some((body_p, meta_p)) = &paths {
            if let Ok(meta_bytes) = tokio::fs::read(meta_p).await {
                if let Ok(meta) = serde_json::from_slice::<CacheMeta>(&meta_bytes) {
                    if let Ok(body) = tokio::fs::read(body_p).await {
                        cached = Some((bytes::Bytes::from(body), meta));
                    }
                }
            }
        }
        if let Some((body, meta)) = &cached {
            let age = now_secs().saturating_sub(meta.fetched_at);
            if !self.cfg.prefer_online && age < meta.max_age {
                stats::CACHE_FRESH.fetch_add(1, Relaxed);
                return parse_packument(name, body.clone()).await;
            }
        }

        // 2. fetch, revalidating with If-None-Match when we have an ETag
        let _permit = self.sem.acquire().await;
        let t0 = std::time::Instant::now();
        let mut req = self.client.get(&url).header("accept", CORGI_ACCEPT);
        if let Some(tok) = self.auth_for(&registry) {
            req = req.bearer_auth(tok);
        }
        if let Some((_, meta)) = &cached {
            if let Some(etag) = &meta.etag {
                req = req.header("if-none-match", etag.as_str());
            }
        }
        let res = match req.send().await {
            Ok(r) => r,
            Err(_) => {
                stats::FAILED.fetch_add(1, Relaxed);
                return Arc::new(Packument::empty(name));
            }
        };
        let max_age = parse_max_age(res.headers().get("cache-control"));
        let etag = res
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if res.status() == reqwest::StatusCode::NOT_MODIFIED {
            if let Some((body, meta)) = cached {
                stats::CACHE_REVALIDATED.fetch_add(1, Relaxed);
                stats::NET_NS.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
                if let Some((_, meta_p)) = &paths {
                    let new_meta = CacheMeta {
                        etag: etag.or(meta.etag),
                        fetched_at: now_secs(),
                        max_age,
                    };
                    write_meta(meta_p.clone(), new_meta);
                }
                return parse_packument(name, body).await;
            }
        }
        if !res.status().is_success() {
            stats::FAILED.fetch_add(1, Relaxed);
            return Arc::new(Packument::empty(name));
        }
        let bytes = match res.bytes().await {
            Ok(b) => b,
            Err(_) => {
                stats::FAILED.fetch_add(1, Relaxed);
                return Arc::new(Packument::empty(name));
            }
        };
        drop(_permit);
        stats::NET_NS.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
        stats::FETCHED.fetch_add(1, Relaxed);
        stats::BYTES.fetch_add(bytes.len() as u64, Relaxed);
        if let Some((body_p, meta_p)) = paths {
            let body = bytes.clone();
            let meta = CacheMeta { etag, fetched_at: now_secs(), max_age };
            tokio::task::spawn_blocking(move || {
                if let Some(dir) = body_p.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let tmp = body_p.with_extension("json.tmp");
                if std::fs::write(&tmp, &body).is_ok() && std::fs::rename(&tmp, &body_p).is_ok() {
                    let _ = std::fs::write(&meta_p, serde_json::to_vec(&meta).unwrap_or_default());
                }
            });
        }
        parse_packument(name, bytes).await
    }

    /// Names of every packument currently in the on-disk cache.
    pub fn cached_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        let Some(dir) = self.cfg.cache_dir.as_ref() else { return out };
        let Ok(hosts) = std::fs::read_dir(dir.join("packuments")) else { return out };
        for host in hosts.flatten() {
            let Ok(files) = std::fs::read_dir(host.path()) else { continue };
            for f in files.flatten() {
                let name = f.file_name();
                let name = name.to_string_lossy();
                if let Some(stem) = name.strip_suffix(".json") {
                    if stem.ends_with(".meta") {
                        continue;
                    }
                    out.push(stem.replacen("%2f", "/", 1));
                }
            }
        }
        out
    }

    fn cache_paths(&self, registry: &str, escaped: &str) -> Option<(PathBuf, PathBuf)> {
        let dir = self.cfg.cache_dir.as_ref()?;
        let host = registry
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .replace(['/', ':'], "_");
        let base = dir.join("packuments").join(host);
        Some((base.join(format!("{escaped}.json")), base.join(format!("{escaped}.meta.json"))))
    }
}

#[derive(serde::Serialize, Deserialize, Debug, Clone)]
struct CacheMeta {
    etag: Option<String>,
    fetched_at: u64,
    max_age: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_max_age(h: Option<&reqwest::header::HeaderValue>) -> u64 {
    let Some(v) = h.and_then(|v| v.to_str().ok()) else { return 0 };
    for part in v.split(',') {
        let part = part.trim();
        if let Some(n) = part.strip_prefix("max-age=") {
            return n.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn write_meta(path: PathBuf, meta: CacheMeta) {
    tokio::task::spawn_blocking(move || {
        let _ = std::fs::write(&path, serde_json::to_vec(&meta).unwrap_or_default());
    });
}

async fn parse_packument(name: &str, bytes: bytes::Bytes) -> Arc<Packument> {
    use std::sync::atomic::Ordering::Relaxed;
    let n = name.to_string();
    let parsed = tokio::task::spawn_blocking(move || {
        let t = std::time::Instant::now();
        let p = serde_json::from_slice::<Packument>(&bytes).unwrap_or_else(|_| Packument::empty(&n));
        stats::PARSE_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
        p
    })
    .await;
    match parsed {
        Ok(p) => Arc::new(p),
        Err(_) => Arc::new(Packument::empty(name)),
    }
}
