//! Postgres schema. Cloud opens DATABASE_URL only; SQLite is not used.

use anyhow::{anyhow, Result};
use postgres::{Client, Transaction};

pub(crate) const CURRENT_SCHEMA_VERSION: i32 = 6;

const SCHEMA_SQL: &str = include_str!("schema.sql");

pub(crate) fn apply(client: &mut Client) -> Result<()> {
    let mut tx = client
        .transaction()
        .map_err(|e| anyhow!("cannot begin schema transaction: {e}"))?;
    match migrate_in_transaction(&mut tx) {
        Ok(()) => tx
            .commit()
            .map_err(|e| anyhow!("commit schema failed: {e}"))?,
        Err(e) => {
            let _ = tx.rollback();
            return Err(e);
        }
    }
    Ok(())
}

fn migrate_in_transaction(tx: &mut Transaction<'_>) -> Result<()> {
    tx.batch_execute("SELECT pg_advisory_xact_lock(1869440357)")?;
    tx.batch_execute(SCHEMA_SQL)
        .map_err(|e| anyhow!("apply Postgres schema failed: {e}"))?;
    let stored = read_version(tx)?;
    if stored > CURRENT_SCHEMA_VERSION {
        return Err(anyhow!(
            "cloud schema version {stored} is newer than this binary supports ({CURRENT_SCHEMA_VERSION}); refusing to open"
        ));
    }
    if stored < 2 {
        tx.batch_execute(include_str!("sync_schema.sql"))?;
    }
    if stored < 3 {
        tx.batch_execute(include_str!("resolution_schema.sql"))?;
    }
    if stored < 4 {
        tx.batch_execute(include_str!("mail_schema.sql"))?;
    }
    if stored < 5 {
        tx.batch_execute(include_str!("device_auth_schema.sql"))?;
    }
    if stored < 6 {
        tx.batch_execute(include_str!("github_auth_schema.sql"))?;
    }
    seed_default_super_admin(tx)?;
    set_version(tx, CURRENT_SCHEMA_VERSION)?;
    Ok(())
}

fn read_version(tx: &mut Transaction<'_>) -> Result<i32> {
    let row = tx
        .query_opt("SELECT v FROM schema_meta WHERE k = 'version'", &[])
        .map_err(|e| anyhow!("read schema version failed: {e}"))?;
    match row {
        None => Ok(0),
        Some(r) => {
            let v: String = r.get(0);
            v.parse().map_err(|_| anyhow!("schema version is not an integer: {v}"))
        }
    }
}

fn set_version(tx: &mut Transaction<'_>, version: i32) -> Result<()> {
    tx.execute(
        "INSERT INTO schema_meta (k, v) VALUES ('version', $1)
         ON CONFLICT (k) DO UPDATE SET v = excluded.v",
        &[&version.to_string()],
    )
    .map_err(|e| anyhow!("write schema version failed: {e}"))?;
    Ok(())
}

fn seed_default_super_admin(tx: &mut Transaction<'_>) -> Result<()> {
    let n: i64 = tx
        .query_one("SELECT COUNT(*) FROM super_admins", &[])
        .map_err(|e| anyhow!("read super_admins count failed: {e}"))?
        .get(0);
    if n > 0 {
        return Ok(());
    }
    let salt = respire::memory::crypto::derive_auth_salt("admin")?;
    let pass_hash = respire::memory::crypto::derive_pass_hash("admin", &salt)
        .map_err(|e| anyhow!("derive default super-admin password hash failed: {e}"))?;
    let token = respire::memory::crypto::random_hex(32);
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    tx.execute(
        "INSERT INTO super_admins (\"user\", pass_hash, salt, token, created_at, role)
         VALUES ($1,$2,$3,$4,$5,'owner')",
        &[&"admin", &pass_hash, &salt, &token, &now],
    )
    .map_err(|e| anyhow!("insert default super-admin failed: {e}"))?;
    Ok(())
}
