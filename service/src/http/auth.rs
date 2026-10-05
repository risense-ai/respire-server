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
        ("POST", "/oauth/device/code") => {
            let Some(input) = oauth_form(body) else { return Some(json(400, serde_json::json!({"error":"invalid_request"}))); };
            if input.get("client_id").map(String::as_str) != Some("respire-cli") { return Some(json(400, serde_json::json!({"error":"invalid_client"}))); }
            let device = input.get("device_name").map(String::as_str).unwrap_or("CLI");
            let user = input.get("expected_user").map(String::as_str).unwrap_or("");
            if device.trim().is_empty() || device.len()>128 || user.len()>256 { return Some(json(400, serde_json::json!({"error":"invalid_request"}))); }
            let dashboard = std::env::var("RESPIRE_DASHBOARD_URL").unwrap_or_else(|_| "https://dash.rsrs.rs".to_owned());
            let Ok(dashboard) = url::Url::parse(&dashboard) else { return Some(server_error(anyhow::anyhow!("invalid dashboard origin"))); };
            let loopback = matches!(dashboard.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
            if !(dashboard.scheme()=="https" || dashboard.scheme()=="http" && loopback) || !dashboard.username().is_empty() || dashboard.password().is_some() || dashboard.path()!="/" || dashboard.query().is_some() || dashboard.fragment().is_some() {
                return Some(server_error(anyhow::anyhow!("invalid dashboard origin")));
            }
            Some(match repo.start_cli_authorization(device.trim(), user.trim()) {
                Ok(mut reply)=> {
                    let code = reply["user_code"].as_str().unwrap_or_default().to_owned();
                    reply["verification_uri"] = serde_json::json!(format!("{}/#/authorize", dashboard.origin().ascii_serialization()));
                    reply["verification_uri_complete"] = serde_json::json!(format!("{}/#/authorize?code={code}", dashboard.origin().ascii_serialization()));
                    json(200,reply)
                }, Err(error)=>server_error(error),
            })
        }
        ("POST", "/oauth/token") => {
            let Some(input) = oauth_form(body) else { return Some(json(400, serde_json::json!({"error":"invalid_request"}))); };
            if input.get("client_id").map(String::as_str) != Some("respire-cli") { return Some(json(400, serde_json::json!({"error":"invalid_client"}))); }
            if input.get("grant_type").map(String::as_str) != Some("urn:ietf:params:oauth:grant-type:device_code") { return Some(json(400, serde_json::json!({"error":"unsupported_grant_type"}))); }
            let code = input.get("device_code").map(String::as_str).unwrap_or("");
            if code.len()!=64 || !code.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Some(json(400, serde_json::json!({"error":"invalid_request"}))); }
            Some(match repo.poll_cli_authorization(code) {
                Ok(reply) if reply["state"] == "authorized" => json(200,serde_json::json!({"access_token":reply["token"],"token_type":"Bearer","user":reply["user"],"session_id":reply["session_id"]})),
                Ok(reply) => {
                    let error = match reply["state"].as_str() { Some("pending")=>"authorization_pending", Some("slow_down")=>"slow_down", Some("denied")=>"access_denied", Some("expired")=>"expired_token", _=>"invalid_grant" };
                    json(400,serde_json::json!({"error":error}))
                }, Err(error)=>server_error(error),
            })
        }
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
            let email = match repo.recovery_email(user) {
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
            if user.is_empty() || parsed.pass_hash.trim().is_empty() || parsed.salt.trim().is_empty() {
                return Some(json(400, serde_json::json!({"error": "user/pass_hash/salt required"})));
            }
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

fn oauth_form(body: &str) -> Option<std::collections::BTreeMap<String, String>> {
    let mut form = std::collections::BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
        if form.insert(key.into_owned(), value.into_owned()).is_some() { return None; }
    }
    Some(form)
}
