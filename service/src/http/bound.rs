//! Bounded HTTP/1 transport for cloud `serve` (hyper 1 + tokio).
//!
//! One design: take a capacity permit on accept and share it via Arc with the
//! connection task and the database task; release only after both finish.
//! Request bodies are capped on async I/O. `handle_full` runs on a bounded
//! dedicated pool (Postgres). HTTP timeouts close the socket without dropping
//! in-flight database work.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use super::{cors::Cors, handle_full, public_route, BlobRepo};

const DEFAULT_MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_HEADER_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_BODY_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 70_000;
const DEFAULT_MAX_CONNECTIONS: u64 = 64;
const WORKER_THREADS: usize = 2;
const LOG_FIELD_MAX: usize = 96;

#[derive(Clone, Copy)]
struct Limits {
    max_body_bytes: usize,
    header_timeout: Duration,
    body_timeout: Duration,
    connection_timeout: Duration,
    max_connections: usize,
}

struct App {
    cors: Cors,
    db: SyncSender<DbJob>,
    limits: Limits,
}

struct DbJob {
    method: &'static str,
    route: String,
    body: String,
    token: Option<String>,
    permit: Arc<OwnedSemaphorePermit>,
    reply: oneshot::Sender<(u16, String)>,
}

pub fn check_config() -> Result<()> {
    super::github::check_config()?;
    Limits::from_env()?;
    Cors::from_env().map(|_| ())
}

pub fn serve(bind: &str, repo: BlobRepo, admin_token: Option<&str>) -> Result<()> {
    serve_with_ready(bind, repo, admin_token, None)
}

pub(crate) fn serve_with_ready(
    bind: &str,
    repo: BlobRepo,
    admin_token: Option<&str>,
    ready: Option<std::sync::mpsc::Sender<String>>,
) -> Result<()> {
    let limits = Limits::from_env()?;
    let cors = Cors::from_env()?;
    // postgres::Client owns a blocking runtime: open it before entering Tokio.
    let workers=std::env::var("ONEMEMORY_DB_WORKERS").ok()
        .map(|v|v.parse::<usize>()).transpose()?.unwrap_or(4);
    if !(1..=16).contains(&workers) {anyhow::bail!("ONEMEMORY_DB_WORKERS must be 1..16");}
    let mut repos=Vec::with_capacity(workers);
    for _ in 1..workers {repos.push(BlobRepo::connect(&repo.url)?);}
    repos.push(repo);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| anyhow::anyhow!("create HTTP runtime failed: {e}"))?;
    runtime.block_on(serve_async(bind, repos, admin_token, limits, cors, ready))
}

impl Limits {
    fn from_env() -> Result<Self> {
        let max_body_bytes = env_positive_u64("ONEMEMORY_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)?;
        let header_ms = env_positive_u64("ONEMEMORY_HEADER_TIMEOUT_MS", DEFAULT_HEADER_TIMEOUT_MS)?;
        let body_ms = env_positive_u64("ONEMEMORY_BODY_TIMEOUT_MS", DEFAULT_BODY_TIMEOUT_MS)?;
        let connection_ms =
            env_positive_u64("ONEMEMORY_CONNECTION_TIMEOUT_MS", DEFAULT_CONNECTION_TIMEOUT_MS)?;
        let max_connections = env_positive_u64("ONEMEMORY_MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS)?;
        let max_body_bytes = usize::try_from(max_body_bytes)
            .map_err(|_| anyhow::anyhow!("ONEMEMORY_MAX_BODY_BYTES exceeds platform usize"))?;
        let max_connections = usize::try_from(max_connections)
            .map_err(|_| anyhow::anyhow!("ONEMEMORY_MAX_CONNECTIONS exceeds platform usize"))?;
        if max_connections > Semaphore::MAX_PERMITS {
            return Err(anyhow::anyhow!(
                "ONEMEMORY_MAX_CONNECTIONS exceeds Semaphore::MAX_PERMITS ({})",
                Semaphore::MAX_PERMITS
            ));
        }
        Ok(Self {
            max_body_bytes,
            header_timeout: Duration::from_millis(header_ms),
            body_timeout: Duration::from_millis(body_ms),
            connection_timeout: Duration::from_millis(connection_ms),
            max_connections,
        })
    }
}

async fn serve_async(
    bind: &str,
    repos: Vec<BlobRepo>,
    admin_token: Option<&str>,
    limits: Limits,
    cors: Cors,
    ready: Option<std::sync::mpsc::Sender<String>>,
) -> Result<()> {
    let (db_tx, db_rx) = mpsc::sync_channel(limits.max_connections);
    let db_rx=Arc::new(Mutex::new(db_rx));
    for (index,repo) in repos.into_iter().enumerate() {
        let admin_for_db=admin_token.map(str::to_owned);
        let rx=Arc::clone(&db_rx);
        std::thread::Builder::new().name(format!("onememory-db-{index}"))
            .spawn(move || db_worker(repo,admin_for_db,rx))?;
    }

    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| anyhow::anyhow!("bind {bind} failed: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("read bound address failed: {e}"))?;
    if let Some(tx) = ready {
        let _ = tx.send(local.to_string());
    }
    let app = Arc::new(App {
        cors,
        db: db_tx,
        limits,
    });
    let permits = Arc::new(Semaphore::new(limits.max_connections));

    println!("respire serve: http://{local} (ciphertext store + auth domain)");
    println!("register: POST /register {{user, pass_hash, salt}} -> token");
    println!("frontend assets: respire-site; this process serves only the HTTP API");
    if admin_token.is_some() {
        println!("super-admin: super_admins table + ONEMEMORY_ADMIN_TOKEN");
    } else {
        println!("super-admin: super_admins table (env token unset)");
    }
    println!(
        "limits: max_body={}B header={}ms body={}ms conn={}ms max_conn={}",
        limits.max_body_bytes,
        limits.header_timeout.as_millis(),
        limits.body_timeout.as_millis(),
        limits.connection_timeout.as_millis(),
        limits.max_connections
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!(
                    "ingress accept-error err={} dur_ms=0",
                    safe_log(&e.to_string())
                );
                continue;
            }
        };
        let permit = match Arc::clone(&permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                eprintln!(
                    "reject connections peer={} max_conn={} reason=capacity",
                    safe_log(&peer.to_string()),
                    limits.max_connections
                );
                drop(stream);
                continue;
            }
            Err(TryAcquireError::Closed) => {
                return Err(anyhow::anyhow!("connection capacity semaphore is closed"));
            }
        };
        let app = Arc::clone(&app);
        tokio::spawn(async move {
            serve_connection(stream, peer, app, Arc::new(permit)).await;
        });
    }
}

fn db_worker(repo: BlobRepo, admin_token: Option<String>, rx: Arc<Mutex<Receiver<DbJob>>>) {
    loop {
        let job=match rx.lock() {
            Ok(receiver)=>receiver.recv(),
            Err(_)=>return,
        };
        let Ok(job)=job else {return;};
        let _permit = job.permit;
        let result = handle_full(
            &repo,
            job.method,
            &job.route,
            &job.body,
            job.token.as_deref(),
            admin_token.as_deref(),
        );
        let _ = job.reply.send(result);
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    app: Arc<App>,
    permit: Arc<OwnedSemaphorePermit>,
) {
    let started = Instant::now();
    if let Err(e) = stream.set_nodelay(true) {
        eprintln!(
            "ingress nodelay-error peer={} err={}",
            safe_log(&peer.to_string()),
            safe_log(&e.to_string())
        );
    }
    let io = TokioIo::new(stream);
    let app_svc = Arc::clone(&app);
    let permit_for_svc = Arc::clone(&permit);
    let mut http1 = hyper::server::conn::http1::Builder::new();
    http1.timer(TokioTimer::default());
    http1.header_read_timeout(app.limits.header_timeout);
    http1.keep_alive(false);
    let conn = http1.serve_connection(
        io,
        service_fn(move |req| {
            let app = Arc::clone(&app_svc);
            let permit = Arc::clone(&permit_for_svc);
            async move { handle_request(req, app, peer, permit).await }
        }),
    );
    match tokio::time::timeout(app.limits.connection_timeout, conn).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!(
                "ingress conn-error peer={} err={} dur_ms={}",
                safe_log(&peer.to_string()),
                safe_log(&e.to_string()),
                started.elapsed().as_millis()
            );
        }
        Err(_) => {
            eprintln!(
                "timeout connection peer={} dur_ms={}",
                safe_log(&peer.to_string()),
                started.elapsed().as_millis()
            );
        }
    }
    drop(permit);
}

async fn handle_request(
    req: Request<Incoming>,
    app: Arc<App>,
    peer: SocketAddr,
    permit: Arc<OwnedSemaphorePermit>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let origin = app.cors.allowed_origin(req.headers());
    let preflight = req.method() == Method::OPTIONS;
    let mut response = if preflight {
        let status = app.cors.preflight_status(req.headers());
        if status == 204 {
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::NO_CONTENT;
            response
        } else {
            json_status(status, "CORS preflight denied")
        }
    } else {
        handle_api_request(req, app, peer, permit).await?
    };
    Cors::decorate(&mut response, origin, preflight);
    Ok(response)
}

async fn handle_api_request(
    req: Request<Incoming>,
    app: Arc<App>,
    peer: SocketAddr,
    permit: Arc<OwnedSemaphorePermit>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let started = Instant::now();
    let method = method_name(req.method());
    let path_only = req.uri().path().to_owned();
    let route = match req.uri().path_and_query() {
        Some(pq) => pq.as_str().to_owned(),
        None => path_only.clone(),
    };
    let token = bearer_token(req.headers());
    let peer_s = safe_log(&peer.to_string());
    let path_s = safe_log(&path_only);

    if let Some(response) = reject_content_length(req.headers(), app.limits.max_body_bytes) {
        log_event(
            "ingress",
            method,
            &path_s,
            &peer_s,
            Some(response.status().as_u16()),
            started,
            "oversize-content-length",
        );
        return Ok(response);
    }

    let collected = match tokio::time::timeout(
        app.limits.body_timeout,
        Limited::new(req.into_body(), app.limits.max_body_bytes).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected,
        Ok(Err(err)) => {
            if is_length_limit(&*err) {
                log_event(
                    "ingress",
                    method,
                    &path_s,
                    &peer_s,
                    Some(413),
                    started,
                    "oversize-body",
                );
                return Ok(json_status(413, "payload too large"));
            }
            log_event(
                "ingress",
                method,
                &path_s,
                &peer_s,
                Some(400),
                started,
                "malformed-body",
            );
            return Ok(json_status(400, "bad request"));
        }
        Err(_) => {
            log_event(
                "timeout",
                method,
                &path_s,
                &peer_s,
                Some(408),
                started,
                "body",
            );
            return Ok(json_status(408, "request timeout"));
        }
    };

    let bytes = collected.to_bytes();
    let body = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            log_event(
                "ingress",
                method,
                &path_s,
                &peer_s,
                Some(400),
                started,
                "malformed-utf8",
            );
            return Ok(json_status(400, "bad request"));
        }
    };

    if let Some((status, reply)) = public_route(method, &path_only) {
        return Ok(build_response(status, reply, "application/json"));
    }

    let (reply_tx, reply_rx) = oneshot::channel();
    let job = DbJob {
        method,
        route,
        body,
        token,
        permit,
        reply: reply_tx,
    };
    match app.db.try_send(job) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            log_event(
                "ingress",
                method,
                &path_s,
                &peer_s,
                Some(503),
                started,
                "db-queue-full",
            );
            return Ok(json_status(503, "busy"));
        }
        Err(TrySendError::Disconnected(_)) => {
            log_event(
                "ingress",
                method,
                &path_s,
                &peer_s,
                Some(500),
                started,
                "db-thread-gone",
            );
            return Ok(json_status(500, "internal error"));
        }
    }

    let (status, reply) = match reply_rx.await {
        Ok(pair) => pair,
        Err(_) => {
            log_event(
                "respond",
                method,
                &path_s,
                &peer_s,
                Some(500),
                started,
                "db-reply-dropped",
            );
            return Ok(json_status(500, "internal error"));
        }
    };

    if status >= 500 {
        log_event(
            "respond",
            method,
            &path_s,
            &peer_s,
            Some(status),
            started,
            "handler-error",
        );
    }
    Ok(build_response(status, reply, "application/json"))
}

fn reject_content_length(
    headers: &hyper::HeaderMap,
    max_body_bytes: usize,
) -> Option<Response<Full<Bytes>>> {
    let value = headers.get(CONTENT_LENGTH)?;
    let raw = match value.to_str() {
        Ok(s) => s,
        Err(_) => return Some(json_status(400, "bad request")),
    };
    let len: u64 = match raw.parse() {
        Ok(n) => n,
        Err(_) => return Some(json_status(400, "bad request")),
    };
    if len > max_body_bytes as u64 {
        Some(json_status(413, "payload too large"))
    } else {
        None
    }
}

fn is_length_limit(err: &(dyn StdError + Send + Sync + 'static)) -> bool {
    if err.downcast_ref::<LengthLimitError>().is_some() {
        return true;
    }
    let mut source = err.source();
    while let Some(inner) = source {
        if inner.downcast_ref::<LengthLimitError>().is_some() {
            return true;
        }
        source = inner.source();
    }
    false
}

fn bearer_token(headers: &hyper::HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = match value.strip_prefix("Bearer ") {
        Some(rest) => rest.trim(),
        None => value.trim(),
    };
    if token.is_empty() {
        None
    } else {
        Some(token.to_owned())
    }
}

fn method_name(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        _ => "OTHER",
    }
}

fn json_status(status: u16, error: &str) -> Response<Full<Bytes>> {
    let body = match serde_json::to_string(&serde_json::json!({"error": error})) {
        Ok(s) => s,
        Err(_) => "{\"error\":\"encode\"}".to_owned(),
    };
    build_response(status, body, "application/json")
}

fn build_response(status: u16, body: String, content_type: &'static str) -> Response<Full<Bytes>> {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match Response::builder()
        .status(code)
        .header(CONTENT_TYPE, content_type)
        .body(Full::new(Bytes::from(body)))
    {
        Ok(response) => response,
        Err(_) => {
            let mut response = Response::new(Full::new(Bytes::from_static(
                b"{\"error\":\"encode\"}",
            )));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}

fn log_event(
    kind: &str,
    method: &str,
    path: &str,
    peer: &str,
    status: Option<u16>,
    started: Instant,
    detail: &str,
) {
    let dur_ms = started.elapsed().as_millis();
    match status {
        Some(status) => eprintln!(
            "{kind} {method} {path} status={status} dur_ms={dur_ms} peer={peer} detail={detail}"
        ),
        None => eprintln!("{kind} {method} {path} dur_ms={dur_ms} peer={peer} detail={detail}"),
    }
}

fn safe_log(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if out.len() >= LOG_FIELD_MAX {
            out.push('…');
            break;
        }
        if ch.is_ascii_graphic() || ch == ' ' {
            out.push(ch);
        } else {
            for part in ch.escape_default() {
                if out.len() >= LOG_FIELD_MAX {
                    out.push('…');
                    return out;
                }
                out.push(part);
            }
        }
    }
    out
}

fn env_positive_u64(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow::anyhow!("{name} is not valid UTF-8"))
        }
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(anyhow::anyhow!("{name} is empty"));
            }
            let parsed: u64 = trimmed
                .parse()
                .map_err(|_| anyhow::anyhow!("{name} is not a positive integer: {}", safe_log(trimmed)))?;
            if parsed == 0 {
                return Err(anyhow::anyhow!("{name} must be greater than 0"));
            }
            Ok(parsed)
        }
    }
}

#[cfg(test)]
#[path = "bound_tests.rs"]
mod tests;
