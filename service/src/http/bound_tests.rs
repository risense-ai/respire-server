//! Real TCP/HTTP tests, without live service credentials or a database dependency.
use super::*;
use anyhow::{anyhow, Context};
use std::io::{Read, Write};

type Handler = Box<dyn FnOnce(DbJob) + Send>;

fn exchange(request: &[u8], handler: Option<Handler>, body_timeout_ms: u64) -> Result<String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let (db_tx, db_rx) = mpsc::sync_channel::<DbJob>(1);
    let db_thread = handler.map(|handle| {
        std::thread::spawn(move || {
            // A preflight must never need this worker; the channel closes without a job.
            if let Ok(job) = db_rx.recv_timeout(Duration::from_secs(3)) {
                handle(job);
            }
        })
    });
    let app = Arc::new(App {
        cors: Cors::parse("https://dash.rsrs.rs,https://admin.rsrs.rs")?,
        db: db_tx,
        limits: Limits {
            max_body_bytes: 64,
            header_timeout: Duration::from_secs(2),
            body_timeout: Duration::from_millis(body_timeout_ms),
            connection_timeout: Duration::from_secs(3),
            max_connections: 1,
        },
    });
    let server = std::thread::spawn(move || -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        runtime.block_on(async move {
            let listener = TcpListener::from_std(listener)?;
            let (stream, peer) = listener.accept().await?;
            let permit = Arc::new(Semaphore::new(1)).acquire_owned().await?;
            serve_connection(stream, peer, app, Arc::new(permit)).await;
            Ok(())
        })
    });
    let mut stream = std::net::TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(request)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    server
        .join()
        .map_err(|_| anyhow!("HTTP test server panicked"))??;
    if let Some(thread) = db_thread {
        thread
            .join()
            .map_err(|_| anyhow!("HTTP test worker panicked"))?;
    }
    Ok(response)
}

fn request(method: &str, path: &str, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn assert_cors(response: &str, status: u16, origin: Option<&str>) {
    let lower = response.to_ascii_lowercase();
    assert!(
        lower.starts_with(&format!("http/1.1 {status} ")),
        "{response}"
    );
    assert!(lower.contains("vary: origin\r\n"), "{response}");
    assert!(
        !lower.contains("access-control-allow-credentials:"),
        "{response}"
    );
    if let Some(origin) = origin {
        assert!(
            lower.contains(&format!("access-control-allow-origin: {origin}\r\n")),
            "{response}"
        );
    } else {
        assert!(
            !lower.contains("access-control-allow-origin:"),
            "{response}"
        );
    }
}

#[test]
fn transport_preflight_needs_no_token_body_or_db() -> Result<()> {
    for path in [
        "/login",
        "/admin/login",
        "/api/self/profile",
        "/admin/users",
    ] {
        // Intentionally incomplete oversized body. Preflight responds before reading it.
        let raw = format!("OPTIONS {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: https://admin.rsrs.rs\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: AUTHORIZATION, content-type\r\nContent-Length: 1000\r\n\r\n");
        let response = exchange(raw.as_bytes(), None, 50)?;
        assert_cors(&response, 204, Some("https://admin.rsrs.rs"));
        assert!(response
            .to_ascii_lowercase()
            .contains("access-control-allow-methods: get, post\r\n"));
        assert!(response
            .to_ascii_lowercase()
            .contains("access-control-allow-headers: authorization, content-type\r\n"));
        assert!(response
            .to_ascii_lowercase()
            .contains("access-control-request-method, access-control-request-headers"));
    }
    Ok(())
}

#[test]
fn transport_denies_untrusted_and_malformed_preflights() -> Result<()> {
    for (origin, extra, status, allowed) in [
        (
            "https://dash.rsrs.rs.evil.test",
            "Access-Control-Request-Method: POST\r\n",
            403,
            false,
        ),
        (
            "null",
            "Access-Control-Request-Method: POST\r\n",
            403,
            false,
        ),
        (
            "https://preview.pages.dev",
            "Access-Control-Request-Method: POST\r\n",
            403,
            false,
        ),
        (
            "https://dash.rsrs.rs",
            "Access-Control-Request-Method: DELETE\r\n",
            405,
            true,
        ),
        (
            "https://dash.rsrs.rs",
            "Access-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: X-Api-Key\r\n",
            403,
            true,
        ),
        ("https://dash.rsrs.rs", "", 405, true),
        (
            "https://dash.rsrs.rs",
            "Access-Control-Request-Method: POST\r\nOrigin: https://dash.rsrs.rs\r\n",
            403,
            false,
        ),
    ] {
        let raw = request(
            "OPTIONS",
            "/login",
            &format!("Origin: {origin}\r\n{extra}"),
            "",
        );
        let response = exchange(&raw, None, 50)?;
        assert_cors(&response, status, allowed.then_some(origin));
        assert!(!response
            .to_ascii_lowercase()
            .contains("access-control-allow-methods:"));
    }
    let response = exchange(&request("OPTIONS", "/login", "", ""), None, 50)?;
    assert_cors(&response, 403, None);
    Ok(())
}

#[test]
fn transport_preserves_auth_tokens_paths_and_all_handler_statuses() -> Result<()> {
    for (create_only, path, condition) in [(false, "/api/self/profile?test=1", ""),
        (true, "/api/self/vault?test=1", "If-None-Match: *\r\n")] {
        for status in [200, 400, 401, 403, 412, 429, 500, 503] {
            let handler: Handler = Box::new(move |job| {
                assert_eq!(job.method, "POST");
                assert_eq!(job.route, path);
                assert_eq!(job.token.as_deref(), Some("synthetic-test-token"));
                assert_eq!(job.body, "{}");
                assert_eq!(job.create_vault_only, create_only);
                let _ = job.reply.send((status, "{\"fixture\":true}".into()));
            });
            let headers = format!("Origin: https://dash.rsrs.rs\r\nAuthorization: Bearer synthetic-test-token\r\nContent-Type: application/json\r\n{condition}");
            let response = exchange(&request("POST", path, &headers, "{}"), Some(handler), 50)?;
            assert_cors(&response, status, Some("https://dash.rsrs.rs"));
            assert!(response.contains("{\"fixture\":true}"));
        }
    }
    Ok(())
}

#[test]
fn transport_covers_body_limits_timeouts_and_worker_failure() -> Result<()> {
    let fixed = "POST /login HTTP/1.1\r\nHost: localhost\r\nOrigin: https://dash.rsrs.rs\r\nContent-Length: 65\r\n\r\n";
    assert_cors(
        &exchange(fixed.as_bytes(), None, 50)?,
        413,
        Some("https://dash.rsrs.rs"),
    );
    let chunked = format!("POST /login HTTP/1.1\r\nHost: localhost\r\nOrigin: https://dash.rsrs.rs\r\nTransfer-Encoding: chunked\r\n\r\n41\r\n{}\r\n0\r\n\r\n", "x".repeat(65));
    assert_cors(
        &exchange(chunked.as_bytes(), None, 50)?,
        413,
        Some("https://dash.rsrs.rs"),
    );
    let timeout = "POST /login HTTP/1.1\r\nHost: localhost\r\nOrigin: https://dash.rsrs.rs\r\nContent-Length: 2\r\n\r\n";
    assert_cors(
        &exchange(timeout.as_bytes(), None, 20)?,
        408,
        Some("https://dash.rsrs.rs"),
    );
    for condition in ["If-None-Match: quoted-tag\r\n", "If-None-Match: *\r\nIf-None-Match: *\r\n"] {
        let headers = format!("Origin: https://dash.rsrs.rs\r\n{condition}");
        assert_cors(&exchange(&request("POST", "/api/self/vault", &headers, "{}"), None, 50)?,
            400, Some("https://dash.rsrs.rs"));
    }
    let mut invalid = request("POST", "/login", "Origin: https://dash.rsrs.rs\r\n", "x");
    *invalid.last_mut().context("body byte")? = 0xff;
    assert_cors(
        &exchange(&invalid, None, 50)?,
        400,
        Some("https://dash.rsrs.rs"),
    );
    assert_cors(
        &exchange(
            &request("GET", "/ready", "Origin: https://dash.rsrs.rs\r\n", ""),
            None,
            50,
        )?,
        500,
        Some("https://dash.rsrs.rs"),
    );
    let dropped: Handler = Box::new(drop);
    assert_cors(
        &exchange(
            &request("GET", "/ready", "Origin: https://dash.rsrs.rs\r\n", ""),
            Some(dropped),
            50,
        )?,
        500,
        Some("https://dash.rsrs.rs"),
    );
    Ok(())
}

#[test]
fn transport_retains_native_and_old_same_origin_behavior() -> Result<()> {
    for origin in [None, Some("https://legacy.example.test")] {
        let headers = origin
            .map(|o| format!("Origin: {o}\r\n"))
            .unwrap_or_default();
        let handler: Handler = Box::new(|job| {
            assert!(job.token.is_none());
            let _ = job.reply.send((401, "{\"error\":\"unauthorized\"}".into()));
        });
        let response = exchange(
            &request("GET", "/api/self/profile", &headers, ""),
            Some(handler),
            50,
        )?;
        assert_cors(&response, 401, None);
    }
    let response = exchange(
        &request("GET", "/health", "Origin: https://dash.rsrs.rs\r\n", ""),
        None,
        50,
    )?;
    assert_cors(&response, 200, Some("https://dash.rsrs.rs"));
    Ok(())
}

/// The real router remains the authorization boundary even after a CORS preflight.
/// Like the existing store tests, this uses an isolated t<uuid> PostgreSQL database.
#[test]
fn cors_with_database_preserves_user_admin_and_readonly_authorization() -> Result<()> {
    let repo = crate::store::connect_unique()?;
    let user = repo
        .register("cors-fixture", "ab", "cd")?
        .context("fixture user")?;
    let (readonly, _) = repo.create_session_with("cors-fixture", "cors-reader", true)?;
    repo.create_admin("cors-viewer", "ab", "cd", "viewer", "")?;
    let viewer = repo.super_admin_issue_token("cors-viewer")?;
    for (method, path, token, expected) in [
        ("GET", "/api/self", None, 401),
        ("GET", "/api/self", Some("invalid-fixture-token"), 401),
        ("GET", "/api/self", Some(user.as_str()), 200),
        ("GET", "/admin/users", Some(user.as_str()), 403),
        ("GET", "/admin/users", Some(viewer.as_str()), 200),
        (
            "POST",
            "/admin/users/cors-fixture/disable",
            Some(viewer.as_str()),
            403,
        ),
        ("GET", "/count", Some(readonly.as_str()), 200),
        ("POST", "/forget", Some(readonly.as_str()), 403),
    ] {
        let db = BlobRepo::connect(&repo.url)?;
        let handler: Handler = Box::new(move |job| {
            let result = handle_conditional(
                &db,
                job.method,
                &job.route,
                &job.body,
                job.token.as_deref(),
                None,
                job.create_vault_only,
            );
            let _ = job.reply.send(result);
        });
        let token_header = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let response = exchange(
            &request(
                method,
                path,
                &format!("Origin: https://admin.rsrs.rs\r\n{token_header}"),
                "",
            ),
            Some(handler),
            200,
        )?;
        assert_cors(&response, expected, Some("https://admin.rsrs.rs"));
    }
    Ok(())
}
