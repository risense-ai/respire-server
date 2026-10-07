//! Respire server — cloud API and independent loopback read-only tool API.

//!
//! serve: ciphertext-only HTTP store (auth domain + per-user vaults; server never sees plaintext).
//! The memory CLI does not own any of this.

mod env;

mod access;
mod http;
mod mail;
mod store;
mod totp;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "respire-server", version, about = "respire cloud API and read-only tool API")]
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
            let database = respire::service::database_path(&respire::service::data_dir())?;
            crate::access::serve(&bind, &database, session)
        }
        Command::Serve { bind } => {
            let admin = crate::env::var("RSRS_ADMIN_TOKEN")
                .ok()
                .filter(|s| !s.is_empty());
            let url = crate::store::connect_url()?;
            crate::http::serve(&bind, &url, admin.as_deref())?;
            Ok(())
        }

    }
}


#[cfg(test)]
mod command_tests {
    use super::*;

    #[test]
    fn retired_local_console_command_is_not_available() {
        assert!(ServerCli::try_parse_from(["respire-server", "web"]).is_err());
    }

    #[test]
    fn independent_readonly_tool_api_remains_available() -> Result<()> {
        let cli = ServerCli::try_parse_from(["respire-server", "access"])?;
        assert!(matches!(cli.command, Command::Access { bind } if bind == "127.0.0.1:8789"));
        Ok(())
    }
}
