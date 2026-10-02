//! Unauthenticated API: /health. Site and SPA are a separate nginx deploy.

use super::json::{json, page_path};

const VERSION: &str = env!("CARGO_PKG_VERSION");

mod site_assets {
    include!(concat!(env!("OUT_DIR"), "/site_assets.rs"));
}
use site_assets::SITE_ASSETS;

/// Unauthenticated, DB-free routes. HTML pages are not served here.
pub(crate) fn public_route(method: &str, path: &str) -> Option<(u16, String)> {
    let path = page_path(path);
    match (method, path) {
        ("GET", "/health") => Some(json(
            200,
            serde_json::json!({"ok": true, "service": "respire", "version": VERSION}),
        )),
        _ => None,
    }
}

pub(crate) fn site_asset(path: &str) -> Option<(u16, &'static [u8], &'static str)> {
    let p = page_path(path);
    SITE_ASSETS
        .iter()
        .find(|(url, _, _)| *url == p)
        .map(|(_, mime, body)| (200u16, *body, *mime))
}

pub(super) fn ready_version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_is_public() {
        let Some((status, body)) = public_route("GET", "/health") else {
            panic!("health missing");
        };
        assert_eq!(status, 200);
        assert!(body.contains("respire"));
        assert!(body.contains("version"));
    }

    #[test]
    fn api_does_not_serve_html_pages() {
        assert!(public_route("GET", "/").is_none());
        assert!(public_route("GET", "/admin").is_none());
        assert!(public_route("GET", "/dashboard").is_none());
        assert!(public_route("GET", "/zh/").is_none());
        assert_eq!(public_route("POST", "/health"), None);
    }
}
