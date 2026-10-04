//! Shared JSON replies and query helpers for HTTP routes.

pub(super) fn json(status: u16, body: impl serde::Serialize) -> (u16, String) {
    (
        status,
        serde_json::to_string(&body).unwrap_or_else(|_| "{\"error\":\"encode\"}".to_owned()),
    )
}

/// Keep unexpected backend details in server logs, not public JSON responses.
pub(super) fn server_error(error: anyhow::Error) -> (u16, String) {
    eprintln!("request failed: {error:#}");
    if error.is::<postgres::Error>() {
        json(503, serde_json::json!({"error":"database unavailable"}))
    } else {
        json(500, serde_json::json!({"error":"internal server error"}))
    }
}

pub(super) fn page_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

pub(super) fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(v);
        }
    }
    None
}

pub(super) fn query_param_u64(query: &str, key: &str) -> Option<u64> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return v.parse().ok();
        }
    }
    None
}

pub(super) fn parse_role(s: &str) -> Option<&'static str> {
    match s.trim() {
        "owner" => Some("owner"),
        "admin" => Some("admin"),
        "viewer" => Some("viewer"),
        _ => None,
    }
}

pub(super) fn can_write(role: &str) -> bool {
    role == "owner" || role == "admin"
}

pub(super) fn can_manage_admins(role: &str) -> bool {
    role == "owner"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_encodes_object() {
        let (status, body) = json(200, serde_json::json!({"ok": true}));
        assert_eq!(status, 200);
        assert!(body.contains("\"ok\":true") || body.contains("\"ok\": true"));
    }

    #[test]
    fn page_path_strips_trailing_slash() {
        assert_eq!(page_path("/admin/users/"), "/admin/users");
        assert_eq!(page_path("/"), "/");
        assert_eq!(page_path("/health"), "/health");
    }

    #[test]
    fn query_param_reads_values() {
        assert_eq!(query_param("a=1&b=2", "b"), Some("2"));
        assert_eq!(query_param("a=1", "missing"), None);
        assert_eq!(query_param_u64("since=12&x=1", "since"), Some(12));
        assert_eq!(query_param_u64("since=nope", "since"), None);
    }

    #[test]
    fn roles() {
        assert_eq!(parse_role("owner"), Some("owner"));
        assert_eq!(parse_role("admin"), Some("admin"));
        assert_eq!(parse_role("viewer"), Some("viewer"));
        assert_eq!(parse_role("nope"), None);
        assert!(can_write("owner") && can_write("admin") && !can_write("viewer"));
        assert!(can_manage_admins("owner") && !can_manage_admins("admin"));
    }

    #[test]
    fn server_error_hides_backend() {
        let (status, body) = server_error(anyhow::anyhow!("secret detail"));
        assert_eq!(status, 500);
        assert!(body.contains("internal server error"));
        assert!(!body.contains("secret detail"));
    }
}
