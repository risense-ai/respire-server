//! Loopback read-only tool API. Grant tokens only; no console, keys, or sync routes.
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use respire::memory::bge::BgeEmbedder;
use respire::memory::model::{MemoryEntry, MemoryQuery};
use respire::memory::{MemoryEngine, SessionKeys};
use respire::transport::local::LocalStore;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server, StatusCode};

fn hide_outside_parent(entry: &mut MemoryEntry, members: &HashSet<String>) {
    if !members.contains(&entry.parent_id) { entry.parent_id.clear(); }
}

pub fn serve(bind: &str, db: &Path, keys: SessionKeys) -> Result<()> {
    let address: SocketAddr = bind.parse()?;
    if !address.ip().is_loopback() { bail!("read-only tool API must bind a loopback address"); }
    let store = LocalStore::open(db)?;
    let database = std::fs::canonicalize(db)?;
    let index_root = database.parent().context("selected database has no library directory")?;
    respire::core_sdk::set_index_root(index_root)?;
    let server = Server::http(address).map_err(|error| anyhow!("start read-only API failed: {error}"))?;
    let mut embedder = None;
    eprintln!("read-only tool API listening on {address}");
    for request in server.incoming_requests() {
        let result = (|| -> Result<(u16, Value)> {
            let token = request.headers().iter()
                .find(|header| header.field.equiv("Authorization"))
                .and_then(|header| header.value.as_str().strip_prefix("Bearer "));
            let Some(token) = token else { return Ok((401, json!({"error":"unauthorized"}))); };
            let Some(candidates) = store.grant_snapshot(token)? else {
                return Ok((401, json!({"error":"unauthorized"})));
            };
            if request.method() != &Method::Get {
                return Ok((405, json!({"error":"read_only"})));
            }
            let (path, query) = request.url().split_once('?').unwrap_or((request.url(), ""));
            let members: HashSet<String> = candidates.iter().map(|entry| entry.id.clone()).collect();
            if let Some(id) = path.strip_prefix("/api/memories/") {
                let Some(stored) = candidates.iter().find(|entry| entry.id == id) else {
                    return Ok((404, json!({"error":"not_found"})));
                };
                let mut entry = MemoryEngine::open(&keys, stored)?;
                hide_outside_parent(&mut entry, &members);
                return Ok((200, json!({"entry":entry})));
            }
            if path != "/api/memories" && path != "/api/recall" {
                return Ok((404, json!({"error":"not_found"})));
            }
            let params = match url_params(query) {
                Ok(params) => params,
                Err(_) => return Ok((400, json!({"error":"invalid_query_encoding"}))),
            };
            let limit = match params.iter().find(|(name, _)| name == "limit") {
                Some((_, value)) => match value.parse::<usize>() {
                    Ok(value) if (1..=100).contains(&value) => value,
                    _ => return Ok((400, json!({"error":"limit must be 1..100"}))),
                },
                None => 20,
            };
            let mut entries = if path == "/api/recall" {
                let text = params.iter().find(|(name, _)| name == "q").map(|(_, value)| value.as_str()).unwrap_or("");
                if text.trim().is_empty() || text.len() > 8192 {
                    return Ok((400, json!({"error":"q must be 1..8192 bytes"})));
                }
                if embedder.is_none() { embedder = Some(BgeEmbedder::load()?); }
                let model = embedder.as_ref().ok_or_else(|| anyhow!("embedder not loaded"))?;
                MemoryEngine::recall_local(&keys, model, &candidates, &MemoryQuery::new(text).limit(limit))?
            } else {
                let mut list = candidates.iter().map(|stored| MemoryEngine::open(&keys, stored))
                    .collect::<Result<Vec<_>>>()?;
                list.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
                list.truncate(limit);
                list
            };
            for entry in &mut entries { hide_outside_parent(entry, &members); }
            Ok((200, json!({"entries":entries})))
        })();
        let (status, value) = match result {
            Ok(result) => result,
            Err(error) => {
                eprintln!("read-only request failed: {error:#}");
                (500, json!({"error":"request_failed"}))
            }
        };
        let response = Response::from_string(serde_json::to_string(&value)?)
            .with_status_code(StatusCode(status))
            .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").map_err(|_| anyhow!("invalid response header"))?)
            .with_header(Header::from_bytes("Cache-Control", "no-store").map_err(|_| anyhow!("invalid response header"))?);
        if let Err(error) = request.respond(response) {
            eprintln!("send read-only response failed: {error}");
        }
    }
    Ok(())
}

fn url_params(query: &str) -> Result<Vec<(String, String)>> {
    query.split('&').filter(|part| !part.is_empty()).map(|part| {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        Ok((decode(key)?, decode(value)?))
    }).collect()
}

fn decode(value: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        bytes.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = input.next().and_then(|b| char::from(b).to_digit(16));
                let low = input.next().and_then(|b| char::from(b).to_digit(16));
                match (high, low) {
                    (Some(high), Some(low)) => (high * 16 + low) as u8,
                    _ => bail!("invalid query-string escape"),
                }
            }
            byte => byte,
        });
    }
    Ok(String::from_utf8(bytes)?)
}
