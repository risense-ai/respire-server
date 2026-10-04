//! Cloud HTTP: transport and API route modules.
//!
//! Layers:
//!   bound   — hyper/tokio accept loop
//!   public  — /health (frontend assets belong to respire-site)
//!   auth    — register/login/forgot/reset
//!   admin   — /admin/*
//!   self_api— /api/self/*
//!   sync    — push/pull/v1/v2
//!   router  — dispatch

mod admin;
mod auth;
mod bound;
mod cors;
mod dto;
mod json;
mod public;
mod router;
mod self_api;
mod sync;

pub(crate) use bound::{check_config, serve as serve_bound};
pub(crate) use public::public_route;
pub(crate) use router::handle_full;
pub(crate) use crate::store::BlobRepo;
#[cfg(test)]
pub(crate) use bound::serve_with_ready;

/// Start the service. Register/login yield a token; /admin/* accepts the super-admin table token or ONEMEMORY_ADMIN_TOKEN.
pub fn serve(bind: &str, database_url: &str, admin_token: Option<&str>) -> anyhow::Result<()> {
    check_config()?;
    let repo = crate::store::BlobRepo::connect(database_url)?;
    crate::mail::start(database_url)?;
    serve_bound(bind, repo, admin_token)
}

#[cfg(test)]
fn handle(
    repo: &BlobRepo,
    method: &str,
    path: &str,
    body: &str,
    req_token: Option<&str>,
) -> (u16, String) {
    handle_full(repo, method, path, body, req_token, None)
}

#[cfg(test)]
mod tests;
