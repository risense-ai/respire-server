//! Respire server — cloud service and local console.
//!
//! serve: ciphertext-only HTTP store (auth domain + per-user vaults; server never sees plaintext).
//! web: local console (browser talks to the local DB: browse/search/CRUD/sync/keys).
//! The memory CLI does not own any of this.

mod access;
mod http;
mod store;
mod totp;
mod web;

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "respire-server", version, about = "respire cloud service and local console")]
struct ServerCli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// After restoring a backup, invalidate v2 cursors without deleting history.
    SyncRotateEpoch {
        #[arg(long)] user: String,
    },
    /// Loopback read-only tool API (Bearer subtree grant; separate from console and cloud sync)
    Access {
        #[arg(long, default_value = "127.0.0.1:8789")]
        bind: String,
    },
    /// Start the HTTP ciphertext store (auth domain included)
    Serve {
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
    /// Local console UI (browser page)
    Web {
        #[arg(long, default_value = "127.0.0.1:8788")]
        bind: String,
    },
}

fn db_path(name: &str) -> Result<PathBuf> {
    // ONEMEMORY_DATA_DIR wins (isolated tests / multi-instance); default ~/.onememory
    if let Ok(dir) = std::env::var("ONEMEMORY_DATA_DIR") {
        let d = dir.trim();
        if !d.is_empty() {
            return Ok(PathBuf::from(d).join(name));
        }
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))?;
    Ok(home.join(".onememory").join(name))
}

fn main() -> Result<()> {
    match ServerCli::parse().command {
        Command::SyncRotateEpoch {user} => {
            let repo=crate::store::BlobRepo::connect(&crate::store::connect_url()?)?;
            let epoch=uuid::Uuid::new_v4().to_string();
            let n=repo.lock().execute("UPDATE sync_accounts SET epoch=$2 WHERE \"user\"=$1",&[&user,&epoch])?;
            if n==0 {return Err(anyhow!("account sync state not found"));}
            println!("{}",serde_json::json!({"user":user,"epoch":epoch}));
            Ok(())
        }
        Command::Access { bind } => {
            let session = respire::auth::load_local_session()?;
            crate::access::serve(&bind, &respire::service::data_dir().join("onememory.db"), session)
        }
        Command::Serve { bind } => {
            let admin = std::env::var("ONEMEMORY_ADMIN_TOKEN")
                .ok()
                .filter(|s| !s.is_empty());
            let url = crate::store::connect_url()?;
            crate::http::serve(&bind, &url, admin.as_deref())?;
            Ok(())
        }
        Command::Web { bind } => {
            let session = respire::auth::try_session()?.ok_or_else(|| {
                anyhow!("no local session — log in from the client, or run rsrs keygen")
            })?;
            crate::web::serve(&bind, &db_path("onememory.db")?, session)?;
            Ok(())
        }
    }
}
