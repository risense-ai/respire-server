//! Ciphertext sync: v1 push/pull and v2 snapshot/conflicts.

use crate::store::{BlobRepo, BlobWrite};

use super::dto::{push_item_error, BatchPushIn, ForgetIn, PushIn, MAX_PUSH_BATCH};
use super::json::{json, query_param_u64, server_error};

pub(super) fn route(
    repo: &BlobRepo,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
    user: &str,
) -> (u16, String) {
    match (method, path) {
        ("POST", "/push") => {
            let Ok(parsed) = serde_json::from_str::<PushIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            if let Some(msg) = push_item_error(&parsed) {
                return json(400, serde_json::json!({"error": msg}));
            }
            match repo.put(
                user,
                &BlobWrite {
                    id: &parsed.id,
                    ciphertext: &parsed.ciphertext,
                    nonce: &parsed.nonce,
                    embedding_enc: &parsed.embedding_enc,
                    updated_at: &parsed.updated_at,
                    deleted: parsed.deleted,
                },
            ) {
                Ok(replaced) => json(200, serde_json::json!({"replaced": replaced})),
                Err(e) => server_error(e),
            }
        }
        ("POST", "/push/batch") => {
            let Ok(parsed) = serde_json::from_str::<BatchPushIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            if parsed.items.len() > MAX_PUSH_BATCH {
                return json(
                    413,
                    serde_json::json!({"error": format!("batch too large: {} > {MAX_PUSH_BATCH}", parsed.items.len())}),
                );
            }
            for (idx, item) in parsed.items.iter().enumerate() {
                if let Some(msg) = push_item_error(item) {
                    return json(400, serde_json::json!({"error": format!("item {idx}: {msg}")}));
                }
            }
            let writes: Vec<BlobWrite<'_>> = parsed
                .items
                .iter()
                .map(|p| BlobWrite {
                    id: &p.id,
                    ciphertext: &p.ciphertext,
                    nonce: &p.nonce,
                    embedding_enc: &p.embedding_enc,
                    updated_at: &p.updated_at,
                    deleted: p.deleted,
                })
                .collect();
            match repo.put_batch(user, &writes) {
                Ok(replaced) => json(200, serde_json::json!({"replaced": replaced})),
                Err(e) => server_error(e),
            }
        }
        ("GET", "/sync/capabilities") => match repo.sync_capabilities(user) {
            Ok(cap) => json(200, serde_json::json!(cap)),
            Err(e) => server_error(e),
        },
        ("POST", "/v2/push/batch") => {
            use respire::transport::protocol::{PushRequest, BATCH_BYTES, PUSH_ITEMS};
            let Ok(request) = serde_json::from_str::<PushRequest>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            if request.items.len() > PUSH_ITEMS || body.len() > BATCH_BYTES {
                return json(413, serde_json::json!({"error": "batch too large"}));
            }
            for op in &request.items {
                let b = &op.blob;
                if op.op_id.is_empty()
                    || op.op_id.len() > 128
                    || b.id.trim().is_empty()
                    || chrono::DateTime::parse_from_rfc3339(&b.updated_at).is_err()
                    || (!b.deleted && (b.ciphertext.is_empty() || b.nonce.is_empty()))
                {
                    return json(400, serde_json::json!({"error": "invalid operation"}));
                }
            }
            match repo.sync_write(user, Some(&request.epoch), &request.items) {
                Ok(reply) => json(200, serde_json::json!(reply)),
                Err(e) if e.is::<postgres::Error>() => server_error(e),
                Err(e) => json(409, serde_json::json!({"error": e.to_string()})),
            }
        }
        ("POST", "/v2/conflicts/resolve") => {
            use respire::transport::protocol::{ResolveRequest, BATCH_BYTES};
            if body.len() > BATCH_BYTES {
                return json(413, serde_json::json!({"error": "batch too large"}));
            }
            let Ok(request) = serde_json::from_str::<ResolveRequest>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            match repo.resolve_conflicts(user, &request) {
                Ok(reply) => json(200, serde_json::json!(reply)),
                Err(e) if e.is::<postgres::Error>() => server_error(e),
                Err(e) => json(409, serde_json::json!({"error": e.to_string()})),
            }
        }
        ("GET", "/v2/pull" | "/v2/snapshot" | "/v2/conflicts/resolutions") => {
            let value = |name: &str| {
                query
                    .split('&')
                    .find_map(|p| p.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
            };
            let Some(epoch) = value("epoch") else {
                return json(400, serde_json::json!({"error": "epoch required"}));
            };
            let Some(after) = value("after").and_then(|v| v.parse::<i64>().ok()) else {
                return json(400, serde_json::json!({"error": "after required"}));
            };
            let until = match value("until") {
                Some(v) => match v.parse::<i64>() {
                    Ok(n) => Some(n),
                    Err(_) => return json(400, serde_json::json!({"error": "bad until"})),
                },
                None => None,
            };
            if path == "/v2/conflicts/resolutions" {
                return match repo.resolution_page(user, epoch, after, until) {
                    Ok(page) => json(200, serde_json::json!(page)),
                    Err(e) if e.is::<postgres::Error>() => server_error(e),
                    Err(e) => json(409, serde_json::json!({"error": e.to_string()})),
                };
            }
            match repo.sync_page(user, epoch, after, until, path == "/v2/snapshot") {
                Ok(page) => json(200, serde_json::json!(page)),
                Err(e) if e.is::<postgres::Error>() => server_error(e),
                Err(e) => json(409, serde_json::json!({"error": e.to_string()})),
            }
        }
        ("GET", "/pull") => {
            let since = query_param_u64(query, "since");
            match repo.pull(user, since) {
                Ok((blobs, cursor, total, alive)) => json(
                    200,
                    serde_json::json!({"blobs": blobs, "cursor": cursor, "total": total, "alive": alive}),
                ),
                Err(e) => server_error(e),
            }
        }
        ("GET", "/max") => match repo.max_updated_at(user) {
            Ok(max) => json(200, serde_json::json!({"max": max})),
            Err(e) => server_error(e),
        },
        ("POST", "/forget") => {
            let Ok(parsed) = serde_json::from_str::<ForgetIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            match repo.forget(user, &parsed.id) {
                Ok(deleted) => json(200, serde_json::json!({"deleted": deleted})),
                Err(e) => server_error(e),
            }
        }
        ("GET", "/count") => match repo.count(user) {
            Ok(count) => json(200, serde_json::json!({"count": count})),
            Err(e) => server_error(e),
        },
        _ => json(404, serde_json::json!({"error": "not found"})),
    }
}
