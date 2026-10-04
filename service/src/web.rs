//! web — local console HTTP (frontend control-panel demo)
//!
//! Second local-client surface: `serve-web` binds 127.0.0.1 and serves the console.
//! Session keys unlock in-process; the page talks to the local API. Keys never leave the machine.
//!
//! Endpoints:
//!   GET  /                         → single-page console (embedded HTML/JS)
//!   GET  /api/status               → {count, remote_configured, max_updated_at}
//!   GET  /api/memories?q=&limit=   → semantic search / list
//!   POST /api/memories             → create (JSON)
//!   DELETE /api/memories/{id}      → tombstone delete
//!   POST /api/sync                 → two-way sync
//!   GET  /api/keys                 → recovery material (Account Secret, local only)

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use tiny_http::{Header, Method, Response, Server, StatusCode};

use respire::memory::bge::BgeEmbedder;
use respire::memory::model::{Kind, MemoryEntry, MemoryQuery};
use respire::memory::{MemoryEngine, SessionKeys};
use respire::sync::{build_remote_from_env, remote_configured, sync_all};
use respire::transport::local::LocalStore;
use respire::transport::MemoryTransport;

/// Local console runtime.
pub struct WebService {
    keys: SessionKeys,
    store: LocalStore,
    embedder: BgeEmbedder,
}

impl WebService {
    pub fn open(db: &Path, keys: SessionKeys) -> Result<Self> {
        Ok(Self {
            keys,
            store: LocalStore::open(db)?,
            // Use the same Core model and dimensions as the CLI.
            // Missing model is an error (message includes ONEMEMORY_MODEL_DIR); no hash fallback.
            embedder: BgeEmbedder::load()?,
        })
    }

    fn api_status(&self) -> serde_json::Value {
        serde_json::json!({
            "count": self.store.count().unwrap_or(0),
            "remote_configured": remote_configured(),
            "max_updated_at": self.store.max_updated_at().ok().flatten(),
        })
    }

    fn api_memories(&self, q: &str, limit: usize) -> Result<Vec<MemoryEntry>> {
        let mut query = MemoryQuery::new(q).limit(limit);
        if q.trim().is_empty() {
            query = MemoryQuery::default().limit(limit);
        }
        let all = self.store.all(false)?;
        MemoryEngine::recall_local(&self.keys, &self.embedder, &all, &query)
    }

    fn api_create(&self, body: &CreateIn) -> Result<MemoryEntry> {
        let stamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let entry = MemoryEntry {
            id: uuid::Uuid::new_v4().to_string(),
            kind: Kind::from_str(&body.kind),
            tags: body
                .tags
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            title: body.title.clone(),
            content: body.content.clone(),
            user: body.user.clone(),
            computer: body.computer.clone(),
            device: respire::service::device_tag(),
            modified_by: respire::service::device_tag(),
            project: body.project.clone(),
            created_at: stamp.clone(),
            updated_at: stamp,
            emotion: body.emotion,
            parent_id: body.parent_id.clone(),
            importance: body.importance.clone().unwrap_or_else(|| "trivial".to_owned()),
        };
        let stored = MemoryEngine::seal(&self.keys, &self.embedder, &entry, &entry.user)?;
        self.store.put(&stored)?;
        self.auto_sync();
        Ok(entry)
    }

    fn api_delete(&self, id: &str) -> Result<bool> {
        let deleted = self.store.forget(id)?;
        if deleted {
            self.auto_sync();
        }
        Ok(deleted)
    }

    /// Auto-sync after writes (create and delete). Skip if remote is unset; autosync_enabled decides; failures warn only.
    fn auto_sync(&self) {
        if !remote_configured() {
            return;
        }
        if !respire::service::autosync_enabled() {
            return;
        }
        match build_remote_from_env().and_then(|remote| sync_all(&self.keys, &self.store, &remote)) {
            Ok(stats) => println!("auto-sync: pulled {} pushed {}", stats.pulled, stats.pushed),
            Err(e) => eprintln!("auto-sync failed (local write kept, retry later): {e}"),
        }
    }

    fn api_sync(&self) -> Result<serde_json::Value> {
        let remote = build_remote_from_env()?;
        let stats = sync_all(&self.keys, &self.store, &remote)?;
        Ok(serde_json::json!({
            "pulled": stats.pulled,
            "pushed": stats.pushed,
        }))
    }

    fn api_keys(&self) -> serde_json::Value {
        // Recovery material from local session.json (same path as CLI build_session)
        let home = dirs::home_dir().unwrap_or_default();
        let path = home.join(".onememory").join("session.json");
        let data = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .unwrap_or_default();
        serde_json::json!({
            "account_secret": data["secret"].as_str().unwrap_or("(no session.json)"),
            "kdf_salt": data["kdf_salt"].as_str().unwrap_or(""),
        })
    }
}

#[derive(Debug, Deserialize)]
struct CreateIn {
    #[serde(default)]
    content: String,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default)]
    tags: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    computer: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    parent_id: String,
    #[serde(default = "default_emotion")]
    emotion: f32,
    #[serde(default)]
    importance: Option<String>,
}

fn default_kind() -> String {
    "context".to_owned()
}

fn default_emotion() -> f32 {
    -1.0
}

fn json(status: u16, body: impl serde::Serialize) -> (u16, String) {
    (
        status,
        serde_json::to_string(&body).unwrap_or_else(|_| "{\"error\":\"encode\"}".to_owned()),
    )
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for part in query.split('&') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn extract_path(url: &str) -> (String, String) {
    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    (path.to_owned(), query.to_owned())
}

fn extract_token(headers: &[Header]) -> Option<String> {
    for header in headers {
        let name = header.field.as_str().as_str();
        if name.eq_ignore_ascii_case("authorization") {
            let value = header.value.as_str();
            return Some(value.strip_prefix("Bearer ").unwrap_or(value).trim().to_owned());
        }
    }
    None
}

fn method_name(method: &Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Delete => "DELETE",
        _ => "OTHER",
    }
}

/// Start the local console. Bind 127.0.0.1 (trusted host; change bind to expose remotely).
pub fn serve(bind: &str, db: &Path, keys: SessionKeys) -> Result<()> {
    let service = Arc::new(WebService::open(db, keys)?);
    let server = Server::http(bind).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    println!("respire console: http://{bind}");
    println!("session unlocked, keys in memory; page uses the local API; keys stay on this machine");
    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let (path, query) = extract_path(&url);
        let body = {
            let mut body = String::new();
            std::io::Read::read_to_string(&mut request.as_reader(), &mut body).ok();
            body
        };
        let method = method_name(request.method());
        let _ = extract_token(request.headers());
        let (status, reply, content_type) = route(&service, method, &path, &query, &body);
        let mut response = Response::from_string(reply)
            .with_status_code(StatusCode(status))
            .with_header(
                Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
                    .map_err(|_| anyhow::anyhow!("failed to build Content-Type header"))?,
            );
        // Allow same-machine cross-port access (e.g. a 5173 dev-server proxy)
        response.add_header(
            Header::from_bytes(&b"Access-Control-Allow-Origin"[..], b"*")
                .map_err(|_| anyhow::anyhow!("failed to build CORS header"))?,
        );
        request.respond(response).ok();
    }
    Ok(())
}

fn route(service: &WebService, method: &str, path: &str, query: &str, body: &str) -> (u16, String, &'static str) {
    match (method, path) {
        ("GET", "/") => (200, PAGE_HTML.to_owned(), "text/html; charset=utf-8"),
        ("GET", "/api/status") => json(200, service.api_status()).into_json(),
        ("GET", "/api/memories") => {
            let q = query_param(query, "q").unwrap_or_default();
            let limit = query_param(query, "limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(20);
            match service.api_memories(&q, limit) {
                Ok(memories) => json(200, serde_json::json!({"memories": memories})).into_json(),
                Err(e) => json(500, serde_json::json!({"error": e.to_string()})).into_json(),
            }
        }
        ("POST", "/api/memories") => {
            let Ok(parsed) = serde_json::from_str::<CreateIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"})).into_json();
            };
            match service.api_create(&parsed) {
                Ok(entry) => json(200, serde_json::json!({"memory": entry})).into_json(),
                Err(e) => json(500, serde_json::json!({"error": e.to_string()})).into_json(),
            }
        }
        ("DELETE", path) if path.starts_with("/api/memories/") => {
            let id = &path["/api/memories/".len()..];
            match service.api_delete(id) {
                Ok(deleted) => json(200, serde_json::json!({"deleted": deleted})).into_json(),
                Err(e) => json(500, serde_json::json!({"error": e.to_string()})).into_json(),
            }
        }
        ("POST", "/api/sync") => match service.api_sync() {
            Ok(stats) => json(200, stats).into_json(),
            Err(e) => json(500, serde_json::json!({"error": e.to_string()})).into_json(),
        },
        ("GET", "/api/keys") => json(200, service.api_keys()).into_json(),
        _ => json(404, serde_json::json!({"error": "not found"})).into_json(),
    }
}

trait IntoJson {
    fn into_json(self) -> (u16, String, &'static str);
}

impl IntoJson for (u16, String) {
    fn into_json(self) -> (u16, String, &'static str) {
        (self.0, self.1, "application/json; charset=utf-8")
    }
}

/// Embedded single-page console (zero build, vanilla JS).
const PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>respire console</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 860px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  .row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; margin: .8rem 0; }
  input[type=text], textarea, select { padding: .4rem .6rem; border-radius: 6px; border: 1px solid #888; flex: 1; min-width: 120px; }
  button { padding: .4rem .9rem; border-radius: 6px; border: 1px solid #888; cursor: pointer; }
  .card { border: 1px solid #666; border-radius: 8px; padding: .8rem 1rem; margin: .6rem 0; }
  .card h3 { margin: 0 0 .3rem; font-size: 1rem; }
  .tag { font-size: .75rem; color: #999; }
  .content { white-space: pre-wrap; margin: .4rem 0; }
  .meta { font-size: .8rem; color: #888; }
  .del { color: #c33; }
  #keys { background: #222; color: #9f9; padding: .6rem .9rem; border-radius: 6px; font-size: .85rem; word-break: break-all; }
</style>
</head>
<body>
<h1>respire console <small id="status"></small></h1>

<div class="row">
  <input type="text" id="q" placeholder="semantic search (Enter)" onkeydown="if(event.key==='Enter')load()">
  <button onclick="load()">Search</button>
  <button onclick="syncNow()">Sync</button>
  <button onclick="showKeys()">Keys</button>
</div>

<div class="row">
  <textarea id="content" rows="2" placeholder="new memory content…"></textarea>
  <div style="display:flex;flex-direction:column;gap:.3rem;min-width:200px">
    <input type="text" id="title" placeholder="title">
    <input type="text" id="tags" placeholder="tags (comma-separated)">
    <div style="display:flex;gap:.3rem">
      <select id="kind">
        <option value="context">context</option>
        <option value="decision">decision</option>
        <option value="preference">preference</option>
        <option value="task">task</option>
        <option value="emotion">emotion</option>
        <option value="time">time</option>
        <option value="skill">skill</option>
      </select>
      <button onclick="create()">Save</button>
    </div>
  </div>
</div>

<div id="keys" style="display:none"></div>
<div id="list"></div>

<script>
async function api(url, opts) {
  const r = await fetch(url, opts);
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.status);
  return j;
}
async function load() {
  const q = document.getElementById('q').value.trim();
  const url = '/api/memories?limit=20' + (q ? '&q=' + encodeURIComponent(q) : '');
  try {
    const { memories } = await api(url);
    render(memories);
  } catch (e) { alert('search failed: ' + e.message); }
}
function render(list) {
  const el = document.getElementById('list');
  el.innerHTML = '';
  if (!list.length) { el.innerHTML = '<p>no memories</p>'; return; }
  for (const m of list) {
    const div = document.createElement('div');
    div.className = 'card';
    div.innerHTML = `
      <h3>${esc(m.title || '(untitled)')} <span class="tag">[${m.kind}]</span></h3>
      <div class="meta">#${esc(m.id)} · ${esc((m.tags||[]).join(','))} · ${esc((m.created_at||'').slice(0,10))}</div>
      <div class="content">${esc(m.content || '')}</div>
      <button class="del" onclick="del('${m.id}')">Delete</button>`;
    el.appendChild(div);
  }
}
async function create() {
  const content = document.getElementById('content').value.trim();
  if (!content) return alert('content is empty');
  const body = {
    content,
    title: document.getElementById('title').value.trim(),
    tags: document.getElementById('tags').value.trim(),
    kind: document.getElementById('kind').value,
  };
  try {
    await api('/api/memories', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    document.getElementById('content').value = '';
    document.getElementById('title').value = '';
    document.getElementById('tags').value = '';
    load();
  } catch (e) { alert('save failed: ' + e.message); }
}
async function del(id) {
  if (!confirm('Delete this memory? (tombstone, propagates on sync)')) return;
  try { await api('/api/memories/' + id, { method: 'DELETE' }); load(); }
  catch (e) { alert('delete failed: ' + e.message); }
}
async function syncNow() {
  try {
    const s = await api('/api/sync', { method: 'POST' });
    alert('sync done: pulled ' + s.pulled + ', pushed ' + s.pushed);
    load();
  } catch (e) { alert('sync failed (needs ONEMEMORY_ADDR/TOKEN): ' + e.message); }
}
async function showKeys() {
  const el = document.getElementById('keys');
  if (el.style.display !== 'none') { el.style.display = 'none'; return; }
  try {
    const k = await api('/api/keys');
    el.style.display = 'block';
    el.textContent = 'Account Secret (recovery key — back up offline): ' + k.account_secret;
  } catch (e) { alert('read failed: ' + e.message); }
}
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
load();
setInterval(() => api('/api/status').then(s => {
  document.getElementById('status').textContent = '· ' + s.count + ' memories' + (s.remote_configured ? ' · cloud configured' : '');
}).catch(()=>{}), 30000);
</script>
</body>
</html>"#;
