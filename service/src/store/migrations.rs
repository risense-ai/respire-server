//! Postgres schema. Cloud opens DATABASE_URL only; SQLite is not used.
//!
//! Schema evolution: `schema.sql` is the idempotent baseline for fresh databases;
//! every further change is a `migrations/NNNN_name.sql` file embedded here. A new
//! migration is one SQL file plus one line in `MIGRATIONS` — no Rust constants to bump.

use anyhow::{anyhow, Result};
use postgres::{Client, Transaction};

/// Highest migration version this binary applies; databases above it are refused.
pub(crate) const CURRENT_SCHEMA_VERSION: i32 = 5;

const SCHEMA_SQL: &str = include_str!("schema.sql");

struct Migration {
    /// Version the database reaches once this file applies (filename prefix + 1:
    /// 0001 lifts the baseline to v2, matching the historical version counter).
    version: i32,
    name: &'static str,
    sql: &'static str,
}

/// Ordered by filename; `filename_order_is_version_order` pins that invariant.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 2,
        name: "0001_sync.sql",
        sql: include_str!("migrations/0001_sync.sql"),
    },
    Migration {
        version: 3,
        name: "0002_resolution.sql",
        sql: include_str!("migrations/0002_resolution.sql"),
    },
    Migration {
        version: 4,
        name: "0003_mail.sql",
        sql: include_str!("migrations/0003_mail.sql"),
    },
    Migration {
        version: 5,
        name: "0004_sessions_readonly.sql",
        sql: include_str!("migrations/0004_sessions_readonly.sql"),
    },
];

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
    migrate_with(tx, MIGRATIONS)
}

fn migrate_with(tx: &mut Transaction<'_>, migrations: &[Migration]) -> Result<()> {
    tx.batch_execute("SELECT pg_advisory_xact_lock(1869440357)")?;
    tx.batch_execute(SCHEMA_SQL)
        .map_err(|e| anyhow!("apply Postgres schema failed: {e}"))?;
    let mut stored = read_version(tx)?;
    if stored > CURRENT_SCHEMA_VERSION {
        return Err(anyhow!(
            "cloud schema version {stored} is newer than this binary supports ({CURRENT_SCHEMA_VERSION}); refusing to open"
        ));
    }
    // Historical databases at v2-v4 skip the migrations they already applied;
    // the files stay as the record of how each version step was produced.
    for migration in migrations {
        if migration.version <= stored {
            continue;
        }
        tx.batch_execute(migration.sql)
            .map_err(|e| anyhow!("migration {} failed: {e}", migration.name))?;
        stored = migration.version;
        set_version(tx, stored)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_order_is_version_order() {
        let mut names: Vec<&str> = MIGRATIONS.iter().map(|m| m.name).collect();
        names.sort_unstable();
        assert_eq!(names, MIGRATIONS.iter().map(|m| m.name).collect::<Vec<_>>());
        let first = MIGRATIONS.first().expect("at least one migration");
        assert_eq!(first.version, 2, "the first migration lifts the v1 baseline to v2");
        for pair in MIGRATIONS.windows(2) {
            let prefix: i32 = pair[1].name.split('_').next().and_then(|p| p.parse().ok())
                .unwrap_or_else(|| panic!("migration {} must be named NNNN_description.sql", pair[1].name));
            assert_eq!(pair[1].version, prefix + 1, "{} version must be prefix+1", pair[1].name);
            assert_eq!(pair[1].version, pair[0].version + 1, "versions must be contiguous");
        }
        assert_eq!(CURRENT_SCHEMA_VERSION, MIGRATIONS.last().expect("at least one migration").version);
    }

    #[test]
    fn fresh_database_applies_baseline_and_all_migrations() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        {
            let mut client = repo.lock();
            apply(&mut client)?;
            let stored = version_of(&mut client)?;
            assert_eq!(stored, CURRENT_SCHEMA_VERSION);
            // The v5 migration is a no-op on fresh databases (baseline already has the column).
            let readonly: i32 = client
                .query_one("SELECT readonly FROM sessions LIMIT 1", &[])
                .map(|row| row.get(0))
                .unwrap_or(0);
            assert_eq!(readonly, 0);
        }
        Ok(())
    }

    #[test]
    fn v1_database_backfills_sync_versions_from_blobs() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        {
            let mut client = repo.lock();
            // Simulate a v1 database: baseline tables without sync/resolution/mail objects.
            client.batch_execute(
                "DROP TABLE IF EXISTS sync_resolutions, sync_heads, sync_versions, sync_accounts,
                     mail_outbox, verify_codes, audit_log, super_admins, vault, sessions, blobs,
                     users, sync_counter, schema_meta CASCADE;",
            )?;
            client.batch_execute(SCHEMA_SQL)?;
            client.batch_execute(
                "INSERT INTO users (\"user\", pass_hash, salt, token, created_at)
                     VALUES ('legacy-user','h','s','t','2026-09-01T00:00:00.000Z');
                 INSERT INTO blobs (\"user\", id, ciphertext, nonce, updated_at, deleted, rev)
                     VALUES ('legacy-user','m1','ct','n','2026-09-01T01:00:00.000Z',0,1),
                            ('legacy-user','m2','ct','n','2026-09-01T02:00:00.000Z',1,2);",
            )?;
            assert!(version_of(&mut client).is_err(), "v1 database has no version row yet");
            apply(&mut client)?;
            assert_eq!(version_of(&mut client)?, CURRENT_SCHEMA_VERSION);
            let backfilled: i64 = client
                .query_one("SELECT COUNT(*) FROM sync_versions WHERE \"user\"='legacy-user'", &[])?
                .get(0);
            assert_eq!(backfilled, 2, "sync_versions must be backfilled from blobs");
            let mail_columns: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM information_schema.columns
                     WHERE table_name='mail_outbox' AND column_name IN ('status','attempts','sent_at')",
                    &[],
                )?
                .get(0);
            assert_eq!(mail_columns, 3, "v4 mail columns must exist after upgrade");
        }
        Ok(())
    }

    #[test]
    fn current_database_skips_all_migrations_without_rerunning_sql() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        {
            let mut client = repo.lock();
            let before: i64 = client.query_one("SELECT COUNT(*) FROM sync_versions", &[])?.get(0);
            // A probe migration older than the stored version must be skipped, not executed.
            let probe: &[Migration] = &[Migration {
                version: 2,
                name: "0000_probe.sql",
                sql: "INSERT INTO audit_log (at, actor, action) VALUES ('probe','probe','must-not-run')",
            }];
            {
                let mut tx = client
                    .transaction()
                    .map_err(|e| anyhow!("begin probe transaction: {e}"))?;
                migrate_with(&mut tx, probe)?;
                tx.commit().map_err(|e| anyhow!("commit probe transaction: {e}"))?;
            }
            let ran: i64 = client
                .query_one("SELECT COUNT(*) FROM audit_log WHERE action='must-not-run'", &[])?
                .get(0);
            assert_eq!(ran, 0, "applied-version migrations must not re-execute");
            assert_eq!(version_of(&mut client)?, CURRENT_SCHEMA_VERSION);
            let after: i64 = client.query_one("SELECT COUNT(*) FROM sync_versions", &[])?.get(0);
            assert_eq!(before, after);
        }
        Ok(())
    }

    #[test]
    fn failing_migration_rolls_back_schema_and_version() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        {
            let mut client = repo.lock();
            client.batch_execute("UPDATE schema_meta SET v='0' WHERE k='version'")?;
            client.batch_execute("INSERT INTO audit_log (at, actor, action) VALUES ('pre','rollback','sentinel')")?;
            let bad: &[Migration] = &[Migration {
                version: 2,
                name: "0000_bad.sql",
                sql: "INSERT INTO audit_log (at, actor, action) VALUES ('bad','rollback','ran'); SELECT 1/0;",
            }];
            let error = {
                let mut tx = client
                    .transaction()
                    .map_err(|e| anyhow!("begin failing transaction: {e}"))?;
                let error = match migrate_with(&mut tx, bad) {
                    Err(e) => e.to_string(),
                    Ok(()) => return Err(anyhow!("expected failing migration to error")),
                };
                let _ = tx.rollback();
                error
            };
            assert!(error.contains("0000_bad.sql failed"), "{error}");
            // The whole transaction rolled back: baseline, probe writes, and version writes.
            let version: Option<String> = client
                .query_opt("SELECT v FROM schema_meta WHERE k='version'", &[])?
                .map(|r| r.get(0));
            assert_eq!(version.as_deref(), Some("0"), "version write must roll back");
            let ran: i64 = client
                .query_one("SELECT COUNT(*) FROM audit_log WHERE action='ran'", &[])?
                .get(0);
            assert_eq!(ran, 0, "migration writes must roll back");
            let sentinel: i64 = client
                .query_one("SELECT COUNT(*) FROM audit_log WHERE action='sentinel'", &[])?
                .get(0);
            assert_eq!(sentinel, 1, "committed pre-migration data must survive");
            // The disposable database is left at version 0 on purpose: a version row that
            // lags reality is exactly the corrupted state this scenario simulates.
        }
        Ok(())
    }

    #[test]
    fn newer_database_refuses_to_open() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        {
            let mut client = repo.lock();
            client.batch_execute("UPDATE schema_meta SET v='6' WHERE k='version'")?;
        }
        let error = match crate::store::BlobRepo::connect(&repo.url) {
            Err(e) => e.to_string(),
            Ok(_) => return Err(anyhow!("expected newer schema to be rejected")),
        };
        assert!(error.contains("newer than this binary supports"), "{error}");
        Ok(())
    }

    fn version_of(client: &mut Client) -> Result<i32> {
        let row = client
            .query_opt("SELECT v FROM schema_meta WHERE k = 'version'", &[])?
            .ok_or_else(|| anyhow!("no version row"))?;
        let v: String = row.get(0);
        v.parse().map_err(|e| anyhow!("bad version: {e}"))
    }
}
