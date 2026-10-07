//! Dispatch: public → auth → admin → self → sync.

use crate::store::BlobRepo;

use super::admin;
use super::auth;
use super::json::json;
use super::public::{public_route, ready_version};
use super::self_api;
use super::sync;

/// Route entry. admin_token is optional RSRS_ADMIN_TOKEN;
/// /admin/* accepts that value or super_admins.token. POST /admin/login is open.
#[cfg(test)]
pub(crate) fn handle_full(
    repo: &BlobRepo,
    method: &str,
    path: &str,
    body: &str,
    req_token: Option<&str>,
    admin_token: Option<&str>,
) -> (u16, String) {
    handle_conditional(repo, method, path, body, req_token, admin_token, false)
}

pub(crate) fn handle_conditional(
    repo: &BlobRepo, method: &str, path: &str, body: &str,
    req_token: Option<&str>, admin_token: Option<&str>, create_vault_only: bool,
) -> (u16, String) {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    if let Some(reply) = public_route(method, path) {
        return reply;
    }
    if let Err(error) = repo.ensure_connected() {
        eprintln!("database unavailable: {error}");
        return json(503, serde_json::json!({"error": "database unavailable"}));
    }
    if method == "GET" && path == "/ready" {
        return match repo.ready() {
            Ok(()) => json(200, serde_json::json!({"ok": true, "database": "ready", "version": ready_version()})),
            Err(_) => json(503, serde_json::json!({"ok": false, "error": "database unavailable or schema mismatch"})),
        };
    }
    if method == "GET" && path == "/auth/salt" {
        let parameters: std::collections::HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
        let user = parameters.get("user").map(String::as_str).unwrap_or("").trim();
        if user.is_empty() || user.len() > 256 {
            return json(400, serde_json::json!({"error":"user required"}));
        }
        return match repo.authentication_salt(user, parameters.get("kind").map(String::as_str) == Some("admin")) {
            Ok(salt) => json(200, serde_json::json!({"salt":salt})),
            Err(error) => super::json::server_error(error),
        };
    }
    if let Some(reply) = auth::unauthenticated(repo, method, path, body) {
        return reply;
    }
    if let Some(rest) = path.strip_prefix("/admin/") {
        let token = match req_token {
            Some(t) if !t.is_empty() => t,
            _ => return json(401, serde_json::json!({"error": "unauthorized: token missing"})),
        };
        let env_ok = admin_token.map(|a| a == token).unwrap_or(false);
        let (actor, role) = if env_ok {
            ("env".to_owned(), "owner".to_owned())
        } else {
            match repo.super_admin_from_token(token) {
                Ok(Some(identity)) => identity,
                Ok(None) => return json(403, serde_json::json!({"error": "forbidden: admin token required"})),
                Err(_) => return json(503, serde_json::json!({"error": "database unavailable"})),
            }
        };
        return admin::route(repo, method, rest, body, token, query, &actor, &role);
    }

    let token = match req_token {
        Some(t) if !t.is_empty() => t,
        _ => return json(401, serde_json::json!({"error": "unauthorized: token missing"})),
    };
    let user = match repo.try_user_from_token(token) {
        Ok(Some(u)) => u,
        Ok(None) => return json(401, serde_json::json!({"error": "unauthorized: token rejected"})),
        Err(_) => return json(503, serde_json::json!({"error": "database unavailable"})),
    };

    let readonly_session = repo.token_is_readonly(token).unwrap_or(false);
    if readonly_session {
        let is_revoke_self = method == "POST"
            && path.starts_with("/api/self/sessions/")
            && path.ends_with("/revoke");
        if method != "GET" && !is_revoke_self {
            return json(
                403,
                serde_json::json!({
                    "error": "readonly session: this session is read-only (recall-only teammate) — recall is allowed, write/update/delete are not",
                    "readonly": true,
                }),
            );
        }
    }

    if let Some(reply) = self_api::route(repo, method, path, body, &user, token, create_vault_only) {
        return reply;
    }
    sync::route(repo, method, path, query, body, &user)
}
