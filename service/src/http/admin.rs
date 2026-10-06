//! Super-admin console routes (`/admin/*` after the prefix is stripped).

use crate::store::BlobRepo;

use super::dto::{AdminCreateIn, AdminUpdateIn, PasswordIn, RegisterIn, SessionCreateIn, TotpIn};
use super::json::{can_manage_admins, can_write, json, parse_role, query_param, server_error};

pub(super) fn route(
    repo: &BlobRepo,
    method: &str,
    rest: &str,
    body: &str,
    _token: &str,
    query: &str,
    actor: &str,
    role: &str,
) -> (u16, String) {
    let self_ok = rest == "password"
        || rest == "totp/begin"
        || rest == "totp/confirm"
        || rest == "totp/disable"
        || rest == "me";
    if method != "GET" && !self_ok && !can_write(role) {
        return json(403, serde_json::json!({"error": "forbidden: read only"}));
    }
    if rest.starts_with("admins") && method != "GET" && !can_manage_admins(role) {
        return json(403, serde_json::json!({"error": "forbidden: owner only"}));
    }
    if rest.starts_with("admins") && method == "GET" && !can_write(role) {
        return json(403, serde_json::json!({"error": "forbidden"}));
    }
    if rest == "outbox" && !can_write(role) {
        return json(403, serde_json::json!({"error": "forbidden"}));
    }
    match (method, rest) {
        ("GET", "me") => {
            if actor == "env" {
                json(200, serde_json::json!({"user": "env", "kind": "env", "role": "owner", "totp": false, "email": ""}))
            } else {
                json(200, serde_json::json!({"user": actor, "kind": "super_admin", "role": role, "totp": repo.admin_has_totp(actor), "email": repo.admin_email(actor)}))
            }
        }
        ("POST", "password") => {
            if actor == "env" {
                return json(400, serde_json::json!({"error": "env admin has no password"}));
            }
            let Ok(parsed) = serde_json::from_str::<PasswordIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            if parsed.pass_hash.trim().is_empty() || parsed.salt.trim().is_empty() {
                return json(400, serde_json::json!({"error": "pass_hash/salt required"}));
            }
            match repo.super_admin_set_password(actor, &parsed.pass_hash, &parsed.salt) {
                Ok(true) => json(200, serde_json::json!({"updated": true, "user": actor})),
                Ok(false) => json(404, serde_json::json!({"error": "admin not found"})),
                Err(e) => server_error(e),
            }
        }
        ("GET", "users") => {
            let q = query_param(query, "q").unwrap_or("").to_owned();
            let page = query_param(query, "page").and_then(|s| s.parse::<u32>().ok()).unwrap_or(1).max(1);
            let limit = query_param(query, "limit").and_then(|s| s.parse::<u32>().ok()).unwrap_or(50).clamp(1, 100);
            let status = query_param(query, "status").unwrap_or("all");
            if !matches!(status, "all" | "ok" | "banned" | "deleted") {
                return json(400, serde_json::json!({"error": "invalid user status"}));
            }
            if query_param(query, "export").is_some() {
                return match repo.users_csv(&q) {
                    Ok(csv) => json(200, serde_json::json!({"csv": csv})),
                    Err(e) => server_error(e),
                };
            }
            match repo.list_users_filtered(&q, page, limit, status) {
                Ok((users, total)) => match repo.users_summary() {
                    Ok(summary) => json(200, serde_json::json!({"users": users, "total": total, "page": page, "limit": limit, "summary": summary})),
                    Err(e) => server_error(e),
                },
                Err(e) => server_error(e),
            }
        }
        ("GET", "audit") => {
            let q = query_param(query, "q").unwrap_or("").to_owned();
            let page = query_param(query, "page").and_then(|s| s.parse().ok()).unwrap_or(1);
            let limit = query_param(query, "limit").and_then(|s| s.parse().ok()).unwrap_or(20);
            match repo.list_audit(&q, page, limit) {
                Ok((items, total)) => json(200, serde_json::json!({"items": items, "total": total, "page": page})),
                Err(e) => server_error(e),
            }
        }
        ("GET", "stats") => {
            if !can_write(role) {
                return json(403, serde_json::json!({"error": "forbidden"}));
            }
            let days = match query_param(query, "days") {
                None => 30,
                Some(raw) => match raw.trim().parse::<u32>() {
                    Ok(n) if (7..=90).contains(&n) => n,
                    _ => return json(400, serde_json::json!({"error": "days must be an integer between 7 and 90"})),
                },
            };
            match repo.daily_stats(days) {
                Ok(stats) => json(200, stats),
                Err(e) => server_error(e),
            }
        }
        ("GET", "outbox") => {
            let page = query_param(query, "page").and_then(|s| s.parse().ok()).unwrap_or(1);
            match repo.list_outbox(page, 20) {
                Ok((items, total)) => json(200, serde_json::json!({"items": items, "total": total, "page": page})),
                Err(e) => server_error(e),
            }
        }
        ("GET", "admins") => match repo.list_admins() {
            Ok(admins) => json(200, serde_json::json!({"admins": admins})),
            Err(e) => server_error(e),
        },
        ("POST", "admins") => {
            let Ok(parsed) = serde_json::from_str::<AdminCreateIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            let user = parsed.user.trim();
            let Some(role) = parse_role(&parsed.role) else {
                return json(400, serde_json::json!({"error": "role must be owner/admin/viewer"}));
            };
            if user.is_empty() || parsed.pass_hash.trim().is_empty() {
                return json(400, serde_json::json!({"error": "user/pass_hash required"}));
            }
            match repo.create_admin(user, &parsed.pass_hash, &parsed.salt, role, parsed.email.trim()) {
                Ok(Some(())) => {
                    let _ = repo.audit(actor, "admin_create", user, role);
                    json(200, serde_json::json!({"user": user, "role": role}))
                }
                Ok(None) => json(409, serde_json::json!({"error": "admin exists"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", "totp/begin") => {
            if actor == "env" {
                return json(400, serde_json::json!({"error": "env admin has no totp"}));
            }
            match repo.totp_begin(actor, "admin_totp_setup") {
                Ok(v) => json(200, v),
                Err(e) => server_error(e),
            }
        }
        ("POST", "totp/confirm") => {
            let Ok(parsed) = serde_json::from_str::<TotpIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            match repo.totp_confirm("super_admins", actor, "admin_totp_setup", &parsed.code) {
                Ok(true) => {
                    let _ = repo.audit(actor, "totp_on", actor, "");
                    json(200, serde_json::json!({"totp": true}))
                }
                Ok(false) => json(400, serde_json::json!({"error": "bad totp"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", "totp/disable") => {
            let Ok(parsed) = serde_json::from_str::<TotpIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            match repo.totp_disable("super_admins", actor, &parsed.code) {
                Ok(true) => {
                    let _ = repo.audit(actor, "totp_off", actor, "");
                    json(200, serde_json::json!({"totp": false}))
                }
                Ok(false) => json(400, serde_json::json!({"error": "bad totp"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", "users") => {
            let Ok(parsed) = serde_json::from_str::<RegisterIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            let user = parsed.user.trim();
            if user.is_empty() || parsed.pass_hash.trim().is_empty() {
                return json(400, serde_json::json!({"error": "user/pass_hash required"}));
            }
            if user.contains('/') || user.contains('?') {
                return json(400, serde_json::json!({"error": "invalid user"}));
            }
            match repo.admin_create_user(user, &parsed.pass_hash, &parsed.salt) {
                Ok(Some(tok)) => {
                    if !parsed.email.trim().is_empty() {
                        let _ = repo.admin_update_user(user, None, None, None, Some(parsed.email.trim()));
                    }
                    let _ = repo.audit(actor, "user_create", user, "");
                    json(200, serde_json::json!({"user": user, "token": tok}))
                }
                Ok(None) => json(409, serde_json::json!({"error": "user exists"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("admins/") && p.ends_with("/update") => {
            let user = p.strip_prefix("admins/").and_then(|s| s.strip_suffix("/update")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            let Ok(parsed) = serde_json::from_str::<AdminUpdateIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            if parsed.disabled == Some(true) {
                if let Ok(n) = repo.owner_count() {
                    let role = repo.admin_role(user).ok().flatten().unwrap_or_default();
                    if role == "owner" && n <= 1 {
                        return json(400, serde_json::json!({"error": "cannot disable last owner"}));
                    }
                }
            }
            match repo.admin_update_admin(user, parsed.pass_hash.as_deref(), parsed.salt.as_deref(), parsed.disabled, parsed.email.as_deref()) {
                Ok(true) => {
                    let _ = repo.audit(actor, "admin_update", user, "");
                    json(200, serde_json::json!({"updated": true, "user": user}))
                }
                Ok(false) => json(404, serde_json::json!({"error": "admin not found"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("admins/") && p.ends_with("/revoke") => {
            let user = p.strip_prefix("admins/").and_then(|s| s.strip_suffix("/revoke")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            if user == actor {
                return json(400, serde_json::json!({"error": "cannot delete self"}));
            }
            match repo.delete_admin(user) {
                Ok(true) => {
                    let _ = repo.audit(actor, "admin_delete", user, "");
                    json(200, serde_json::json!({"deleted": true, "user": user}))
                }
                Ok(false) => json(400, serde_json::json!({"error": "cannot delete last owner or missing"})),
                Err(e) => server_error(e),
            }
        }
        ("GET", p) if p.starts_with("users/") && p.ends_with("/sessions") && !p.contains("/sessions/") => {
            let user = p.strip_prefix("users/").and_then(|s| s.strip_suffix("/sessions")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            match repo.list_user_sessions(user) {
                Ok(Some(sessions)) => json(200, serde_json::json!({"user": user, "sessions": sessions})),
                Ok(None) => json(404, serde_json::json!({"error": "user not found"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("users/") && p.ends_with("/sessions") && !p.contains("/sessions/") => {
            let user = p.strip_prefix("users/").and_then(|s| s.strip_suffix("/sessions")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            if !repo.exists_user(user) {
                return json(404, serde_json::json!({"error": "user not found"}));
            }
            let name = match serde_json::from_str::<SessionCreateIn>(body) {
                Ok(parsed) => parsed.device_name.unwrap_or_else(|| "admin".to_owned()),
                Err(_) if body.trim().is_empty() => "admin".to_owned(),
                Err(_) => return json(400, serde_json::json!({"error": "bad json"})),
            };
            let name = name.trim();
            if name.is_empty() || name.len() > 128 {
                return json(400, serde_json::json!({"error": "device_name must contain 1-128 bytes"}));
            }
            match repo.create_session(user, name) {
                Ok((tok, id)) => json(
                    200,
                    serde_json::json!({"token": tok, "session_id": id, "user": user, "device_name": name}),
                ),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("users/") && p.contains("/sessions/") && p.ends_with("/revoke") => {
            let Some(rest) = p.strip_prefix("users/") else {
                return json(404, serde_json::json!({"error": "not found"}));
            };
            let Some((user, sid_part)) = rest.split_once("/sessions/") else {
                return json(404, serde_json::json!({"error": "not found"}));
            };
            let Some(session_id) = sid_part.strip_suffix("/revoke") else {
                return json(404, serde_json::json!({"error": "not found"}));
            };
            let user = user.trim();
            let session_id = session_id.trim();
            if user.is_empty() || session_id.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            match repo.revoke_session(user, session_id) {
                Ok(true) => json(200, serde_json::json!({"revoked": true, "user": user, "session_id": session_id})),
                Ok(false) => json(404, serde_json::json!({"error": "session not found"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("users/") && p.ends_with("/update") && !p.contains("/sessions/") => {
            let user = p.strip_prefix("users/").and_then(|s| s.strip_suffix("/update")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            let Ok(parsed) = serde_json::from_str::<AdminUpdateIn>(body) else {
                return json(400, serde_json::json!({"error": "bad json"}));
            };
            match repo.admin_update_user(
                user,
                parsed.pass_hash.as_deref(),
                parsed.salt.as_deref(),
                parsed.disabled,
                parsed.email.as_deref(),
            ) {
                Ok(true) => {
                    let _ = repo.audit(actor, "user_update", user, "");
                    json(200, serde_json::json!({"updated": true, "user": user}))
                }
                Ok(false) => json(404, serde_json::json!({"error": "user not found"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("users/") && p.ends_with("/disable") => {
            let reply = admin_set_disabled(repo, p, true);
            if reply.0 == 200 {
                let _ = repo.audit(actor, "user_disable", p, "");
            }
            reply
        }
        ("POST", p) if p.starts_with("users/") && p.ends_with("/enable") => {
            let reply = admin_set_disabled(repo, p, false);
            if reply.0 == 200 {
                let _ = repo.audit(actor, "user_enable", p, "");
            }
            reply
        }
        ("POST", p) if p.starts_with("users/") && p.ends_with("/kick") && !p.contains("/sessions/") => {
            let user = p.strip_prefix("users/").and_then(|s| s.strip_suffix("/kick")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            match repo.kick_user(user) {
                Ok(true) => {
                    let _ = repo.audit(actor, "user_kick", user, "");
                    json(200, serde_json::json!({"kicked": true, "user": user}))
                }
                Ok(false) => json(404, serde_json::json!({"error": "user not found"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("users/") && p.ends_with("/delete") && !p.contains("/sessions/") => {
            let user = p.strip_prefix("users/").and_then(|s| s.strip_suffix("/delete")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            match repo.set_deleted(user, true) {
                Ok(true) => {
                    let _ = repo.audit(actor, "user_soft_delete", user, "");
                    json(200, serde_json::json!({"deleted": true, "user": user}))
                }
                Ok(false) => json(404, serde_json::json!({"error": "user not found"})),
                Err(e) => server_error(e),
            }
        }
        ("POST", p) if p.starts_with("users/") && p.ends_with("/restore") && !p.contains("/sessions/") => {
            let user = p.strip_prefix("users/").and_then(|s| s.strip_suffix("/restore")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            match repo.set_deleted(user, false) {
                Ok(true) => {
                    let _ = repo.audit(actor, "user_restore", user, "");
                    json(200, serde_json::json!({"restored": true, "user": user}))
                }
                Ok(false) => json(404, serde_json::json!({"error": "user not found"})),
                Err(e) => server_error(e),
            }
        }
        (m, p) if m == "POST" && p.starts_with("users/") && p.ends_with("/rotate") && !p.contains("/sessions/") => {
            let user = p.strip_prefix("users/").and_then(|s| s.strip_suffix("/rotate")).unwrap_or("").trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            match repo.rotate_token(user) {
                Ok(Some(token)) => json(200, serde_json::json!({"token": token, "user": user})),
                Ok(None) => json(404, serde_json::json!({"error": "user not found"})),
                Err(e) => server_error(e),
            }
        }
        (m, p) if m == "POST" && p.starts_with("users/") && (p.ends_with("/revoke") || p.ends_with("/purge")) && !p.contains("/sessions/") => {
            let rest = p.strip_prefix("users/").unwrap_or("");
            let user = rest
                .strip_suffix("/purge")
                .or_else(|| rest.strip_suffix("/revoke"))
                .unwrap_or("")
                .trim();
            if user.is_empty() {
                return json(404, serde_json::json!({"error": "not found"}));
            }
            match repo.revoke_user(user) {
                Ok((true, blobs)) => {
                    let _ = repo.audit(actor, "user_purge", user, "");
                    json(
                        200,
                        serde_json::json!({"purged": true, "deleted": true, "blobs_deleted": blobs, "user": user}),
                    )
                }
                Ok((false, _)) => json(404, serde_json::json!({"error": "user not found"})),
                Err(e) => server_error(e),
            }
        }
        _ => json(404, serde_json::json!({"error": "not found"})),
    }
}

fn admin_set_disabled(repo: &BlobRepo, path: &str, disabled: bool) -> (u16, String) {
    let action = if disabled { "/disable" } else { "/enable" };
    let user = path
        .strip_prefix("users/")
        .and_then(|s| s.strip_suffix(action))
        .unwrap_or("")
        .trim();
    if user.is_empty() {
        return json(404, serde_json::json!({"error": "not found"}));
    }
    match repo.set_disabled(user, disabled) {
        Ok(true) => json(200, serde_json::json!({"user": user, "disabled": disabled})),
        Ok(false) => json(404, serde_json::json!({"error": "user not found"})),
        Err(e) => server_error(e),
    }
}
