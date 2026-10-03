//! Unauthenticated auth: register, login, forgot, reset.

use super::dto::{ForgotIn, LoginIn, RegisterIn, ResetIn, TotpIn};
use super::json::{json, server_error};
use crate::store::BlobRepo;

pub(super) fn unauthenticated(
    repo: &BlobRepo,
    method: &str,
    path: &str,
    body: &str,
) -> Option<(u16, String)> {
    match (method, path) {
        ("POST", "/register") => {
            let Ok(parsed) = serde_json::from_str::<RegisterIn>(body) else {
                return Some(json(400, serde_json::json!({"error": "bad json"})));
            };
            if parsed.user.trim().is_empty() || parsed.pass_hash.trim().is_empty() {
                return Some(json(400, serde_json::json!({"error": "user/pass_hash required"})));
            }
            if parsed.device_name.as_deref().is_some_and(|name| name.trim().is_empty() || name.len() > 128) {
                return Some(json(400, serde_json::json!({"error": "device_name must contain 1-128 bytes"})));
            }
            Some(match repo.register_session(parsed.user.trim(), &parsed.pass_hash, &parsed.salt, parsed.device_name.as_deref()) {
                Ok(Some(response)) => json(200, response),
                Ok(None) => json(409, serde_json::json!({"error": "user exists"})),
                Err(e) => server_error(e),
            })
        }
        ("POST", "/login") => {
            let Ok(parsed) = serde_json::from_str::<LoginIn>(body) else {
                return Some(json(400, serde_json::json!({"error": "bad json"})));
            };
            let user = parsed.user.trim().to_owned();
            if parsed.device_name.as_deref().is_some_and(|name| name.trim().is_empty() || name.len() > 128) {
                return Some(json(400, serde_json::json!({"error": "device_name must contain 1-128 bytes"})));
            }
            Some(match repo.login_session(&user, &parsed.pass_hash, parsed.device_name.as_deref()) {
                Ok(Some(response)) => json(200, response),
                Ok(None) => json(401, serde_json::json!({"error": "bad credentials"})),
                Err(e) if e.to_string() == "disabled" => json(403, serde_json::json!({"error": "disabled"})),
                Err(e) if e.to_string() == "deleted" => json(403, serde_json::json!({"error": "deleted"})),
                Err(e) => server_error(e),
            })
        }
        ("POST", "/login/totp") => {
            let Ok(parsed) = serde_json::from_str::<TotpIn>(body) else {
                return Some(json(400, serde_json::json!({"error": "bad json"})));
            };
            Some(match repo.complete_user_totp(&parsed.ticket, &parsed.code, parsed.device_name.as_deref()) {
                Ok(Some(response)) => json(200, response),
                Ok(None) => json(401, serde_json::json!({"error": "bad totp"})),
                Err(e) => server_error(e),
            })
        }
        ("POST", "/forgot") => {
            let Ok(parsed) = serde_json::from_str::<ForgotIn>(body) else {
                return Some(json(400, serde_json::json!({"error": "bad json"})));
            };
            let user = parsed.user.trim();
            let email = match repo.user_email(user) {
                Ok(email) => email,
                Err(e) => return Some(server_error(e)),
            };
            if let Some(email) = email {
                if !email.is_empty() {
                    match repo.queue_email_code(user, &email, "reset_password") {
                        Ok(_) => { let _ = repo.audit(user, "forgot", user, ""); }
                        Err(e) => return Some(server_error(e)),
                    }
                }
            }
            Some(json(200, serde_json::json!({"ok": true})))
        }
        ("POST", "/reset") => {
            let Ok(parsed) = serde_json::from_str::<ResetIn>(body) else {
                return Some(json(400, serde_json::json!({"error": "bad json"})));
            };
            let user = parsed.user.trim();
            Some(match repo.reset_password(user, &parsed.code, &parsed.pass_hash, &parsed.salt) {
                Ok(true) => json(200, serde_json::json!({"updated": true})),
                Ok(false) => json(401, serde_json::json!({"error": "bad code"})),
                Err(e) => server_error(e),
            })
        }
        ("POST", "/admin/login") => {
            let Ok(parsed) = serde_json::from_str::<LoginIn>(body) else {
                return Some(json(400, serde_json::json!({"error": "bad json"})));
            };
            let user = parsed.user.trim();
            if user.is_empty() || parsed.pass_hash.trim().is_empty() {
                return Some(json(400, serde_json::json!({"error": "user/pass_hash required"})));
            }
            Some(match repo.super_admin_login(user, &parsed.pass_hash) {
                Ok(Some(response)) => json(200, response),
                Ok(None) => json(401, serde_json::json!({"error": "bad credentials"})),
                Err(e) if e.to_string() == "disabled" => json(403, serde_json::json!({"error": "disabled"})),
                Err(e) => server_error(e),
            })
        }
        ("POST", "/admin/login/totp") => {
            let Ok(parsed) = serde_json::from_str::<TotpIn>(body) else {
                return Some(json(400, serde_json::json!({"error": "bad json"})));
            };
            Some(match repo.complete_admin_totp(&parsed.ticket, &parsed.code) {
                Ok(Some(response)) => json(200, response),
                Ok(None) => json(401, serde_json::json!({"error": "bad totp"})),
                Err(e) => server_error(e),
            })
        }
        _ => None,
    }
}
