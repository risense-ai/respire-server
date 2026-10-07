//! Authenticated user self-service: `/api/self*`.

use crate::store::{mask_token, BlobRepo};

use super::dto::{EmailIn, PasswordIn, SessionCreateIn, TotpIn, VaultIn};
use super::json::{json, server_error};

pub(super) fn route(
    repo: &BlobRepo,
    method: &str,
    path: &str,
    body: &str,
    user: &str,
    token: &str,
    create_vault_only: bool,
) -> Option<(u16, String)> {
    if let Some(reply) = super::github::route(repo, method, path, body, Some(user)) {
        return Some(reply);
    }
    if let Some(code) = path.strip_prefix("/api/self/cli-authorization/") {
        if code.len()!=12 || !code.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Some(json(400, serde_json::json!({"error":"invalid authorization code"})));
        }
        let code = code.to_uppercase();
        if method == "GET" {
            return Some(match repo.cli_authorization_info(&code) {
                Ok(Some(info))=>json(200,info),
                Ok(None)=>json(404,serde_json::json!({"error":"authorization expired or unavailable"})),
                Err(error)=>server_error(error),
            });
        }
        if method == "POST" {
            #[derive(serde::Deserialize)]
            struct Decision { approve: bool }
            let Ok(input) = serde_json::from_str::<Decision>(body) else {
                return Some(json(400,serde_json::json!({"error":"bad json"})));
            };
            return Some(match repo.decide_cli_authorization(&code,user,input.approve) {
                Ok(true)=>json(200,serde_json::json!({"ok":true})),
                Ok(false)=>json(409,serde_json::json!({"error":"authorization expired, decided or belongs to another account"})),
                Err(error)=>server_error(error),
            });
        }
    }
    if method == "GET" && path == "/api/self/sessions" {
        return Some(match repo.list_sessions(user, token) {
            Ok(sessions) => json(200, serde_json::json!({"sessions": sessions})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" {
        if let Some(id) = path.strip_prefix("/api/self/sessions/").and_then(|rest| rest.strip_suffix("/revoke")) {
            return Some(match repo.revoke_session(user, id) {
                Ok(revoked) => json(200, serde_json::json!({"revoked": revoked, "session_id": id})),
                Err(e) => server_error(e),
            });
        }
    }
    if method == "GET" && path == "/api/self" {
        return Some(match repo.user_created_at(user) {
            Ok(Some(created_at)) => json(
                200,
                serde_json::json!({"user": user, "created_at": created_at, "token_masked": mask_token(token)}),
            ),
            Ok(None) => json(404, serde_json::json!({"error": "user gone"})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/rotate" {
        return Some(match repo.rotate_token(user) {
            Ok(Some(token)) => json(200, serde_json::json!({"token": token, "user": user})),
            Ok(None) => json(404, serde_json::json!({"error": "user gone"})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/sessions" {
        let (name, readonly) = match serde_json::from_str::<SessionCreateIn>(body) {
            Ok(parsed) => (
                parsed.device_name.unwrap_or_else(|| "web".to_owned()),
                parsed.readonly,
            ),
            Err(_) if body.trim().is_empty() => ("web".to_owned(), false),
            Err(_) => return Some(json(400, serde_json::json!({"error": "bad json"}))),
        };
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Some(json(400, serde_json::json!({"error": "device_name must contain 1-128 bytes"})));
        }
        if readonly && repo.token_is_readonly(token).unwrap_or(false) {
            return Some(json(403, serde_json::json!({"error": "readonly session cannot create sessions"})));
        }
        return Some(match repo.create_session_with(user, name, readonly) {
            Ok((tok, id)) => json(
                200,
                serde_json::json!({"token": tok, "session_id": id, "device_name": name, "readonly": readonly}),
            ),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/password" {
        let Ok(parsed) = serde_json::from_str::<PasswordIn>(body) else {
            return Some(json(400, serde_json::json!({"error": "bad json"})));
        };
        if parsed.pass_hash.trim().is_empty() || parsed.salt.trim().is_empty() {
            return Some(json(400, serde_json::json!({"error": "pass_hash/salt required"})));
        }
        return Some(match repo.user_set_password(user, &parsed.pass_hash, &parsed.salt) {
            Ok(true) => json(200, serde_json::json!({"updated": true})),
            Ok(false) => json(404, serde_json::json!({"error": "user gone"})),
            Err(e) => server_error(e),
        });
    }
    if method == "GET" && path == "/api/self/vault" {
        return Some(match repo.get_vault(user) {
            Ok(Some(v)) => json(200, v),
            Ok(None) => json(404, serde_json::json!({"error": "no vault"})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/vault" {
        let Ok(parsed) = serde_json::from_str::<VaultIn>(body) else {
            return Some(json(400, serde_json::json!({"error": "bad json"})));
        };
        let result = if create_vault_only {
            repo.create_vault(user, parsed.kdf_salt.trim(), parsed.wrapped_urk.trim(),
                parsed.urk_nonce.trim(), parsed.version)
        } else {
            repo.put_vault(user, parsed.kdf_salt.trim(), parsed.wrapped_urk.trim(),
                parsed.urk_nonce.trim(), parsed.version).map(|()| true)
        };
        return Some(match result {
            Ok(false) => json(412, serde_json::json!({"error":"vault already exists; original key material preserved"})),
            Ok(true) => {
                let _ = repo.audit(user, "vault_put", user, "");
                json(200, serde_json::json!({"ok": true}))
            }
            Err(e) if e.is::<postgres::Error>() => server_error(e),
            Err(e) => json(400, serde_json::json!({"error": e.to_string()})),
        });
    }
    if method == "GET" && path == "/api/self/keys" {
        return Some(match repo.user_keys(user, token) {
            Ok(value) => json(200, value),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/email" {
        let Ok(parsed) = serde_json::from_str::<EmailIn>(body) else {
            return Some(json(400, serde_json::json!({"error": "bad json"})));
        };
        let email = parsed.email.trim();
        if email.parse::<lettre::message::Mailbox>().is_err() {
            return Some(json(400, serde_json::json!({"error": "invalid email"})));
        }
        return Some(match repo.queue_email_code(user, email, "verify_email") {
            Ok(true) => {
                let _ = repo.audit(user, "email_code", user, email);
                json(200, serde_json::json!({"queued": true}))
            }
            Ok(false) => json(429, serde_json::json!({"error": "wait 60 seconds before requesting another code"})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/email/confirm" {
        let Ok(parsed) = serde_json::from_str::<TotpIn>(body) else {
            return Some(json(400, serde_json::json!({"error": "bad json"})));
        };
        return Some(match repo.confirm_email(user, &parsed.code) {
            Ok(true) => json(200, serde_json::json!({"updated": true})),
            Ok(false) => json(401, serde_json::json!({"error": "bad code"})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/totp/begin" {
        return Some(match repo.totp_begin(user, "user_totp_setup") {
            Ok(v) => json(200, v),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/totp/confirm" {
        let Ok(parsed) = serde_json::from_str::<TotpIn>(body) else {
            return Some(json(400, serde_json::json!({"error": "bad json"})));
        };
        return Some(match repo.totp_confirm("users", user, "user_totp_setup", &parsed.code) {
            Ok(true) => {
                let _ = repo.audit(user, "totp_on", user, "");
                json(200, serde_json::json!({"totp": true}))
            }
            Ok(false) => json(400, serde_json::json!({"error": "bad totp"})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/totp/disable" {
        let Ok(parsed) = serde_json::from_str::<TotpIn>(body) else {
            return Some(json(400, serde_json::json!({"error": "bad json"})));
        };
        return Some(match repo.totp_disable("users", user, &parsed.code) {
            Ok(true) => {
                let _ = repo.audit(user, "totp_off", user, "");
                json(200, serde_json::json!({"totp": false}))
            }
            Ok(false) => json(400, serde_json::json!({"error": "bad totp"})),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/purge" {
        let confirm = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("confirm").and_then(|c| c.as_str()).map(str::to_owned))
            .unwrap_or_default();
        if confirm.trim() != user {
            return Some(json(
                400,
                serde_json::json!({
                    "error": "purge requires confirm: body.confirm must equal the username",
                    "confirm_required": user,
                }),
            ));
        }
        return Some(match repo.revoke_user(user) {
            Ok((true, blobs)) => {
                let _ = repo.audit(user, "user_purge", user, "self");
                json(
                    200,
                    serde_json::json!({"purged": true, "blobs_deleted": blobs, "user": user}),
                )
            }
            Ok((false, _)) => json(404, serde_json::json!({"error": "user gone"})),
            Err(e) => server_error(e),
        });
    }
    None
}
