//! Conflict dispositions have their own ordered stream, so v1/v2 content cursors
//! and immutable historical versions keep their original meaning.
use super::db::BlobRepo;
use anyhow::{bail, Result};
use respire::transport::protocol::*;
use postgres::{IsolationLevel, Row};

fn read_resolution(row: &Row) -> Resolution {
    Resolution {
        seq: row.get("seq"),
        conflict_rev: row.get("conflict_rev"),
        id: row.get("id"),
        action: row.get("action"),
        head_rev: row.get("head_rev"),
        restore_op_id: row.get("restore_op_id"),
        processed_at: row.get("processed_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::BlobWrite;

    #[test]
    fn encrypted_two_client_closed_loop_preserves_unique_legacy_edits() -> Result<()> {
        use respire::transport::{local::LocalStore, MemoryTransport};
        use respire::{MemoryEngine, SessionKeys, StoredMemory};
        struct Remote<'a>(&'a BlobRepo);
        impl MemoryTransport for Remote<'_> {
            fn capabilities(&self) -> Result<Option<Capabilities>> {
                Ok(Some(self.0.sync_capabilities("u")?))
            }
            fn push_v2(&self, r: &PushRequest) -> Result<PushReply> {
                self.0.sync_write("u", Some(&r.epoch), &r.items)
            }
            fn pull_v2(&self, e: &str, a: i64, h: Option<i64>, s: bool) -> Result<Page> {
                self.0.sync_page("u", e, a, h, s)
            }
            fn resolve_conflicts(&self, r: &ResolveRequest) -> Result<ResolveReply> {
                self.0.resolve_conflicts("u", r)
            }
            fn fetch_resolutions(&self, e: &str, a: i64, h: Option<i64>) -> Result<ResolutionPage> {
                self.0.resolution_page("u", e, a, h)
            }
            fn put(&self, b: &StoredMemory) -> Result<bool> {
                self.0.put(
                    "u",
                    &BlobWrite {
                        id: &b.id,
                        ciphertext: &b.ciphertext,
                        nonce: &b.nonce,
                        embedding_enc: &b.embedding_enc,
                        updated_at: &b.updated_at,
                        deleted: b.deleted,
                    },
                )
            }
            fn all(&self, _deleted: bool) -> Result<Vec<StoredMemory>> {
                Ok(self.0.pull("u", None)?.0)
            }
            fn max_updated_at(&self) -> Result<Option<String>> {
                self.0.max_updated_at("u")
            }
            fn forget(&self, id: &str) -> Result<bool> {
                self.0.forget("u", id)
            }
            fn count(&self) -> Result<i64> {
                self.0.count("u")
            }
        }
        let repo = crate::store::connect_unique()?;
        repo.register("u", "hash", "salt")?;
        let remote = Remote(&repo);
        let keys = SessionKeys::from_urk([7; 32])?;
        struct TestEmbedder;
        impl respire::memory::search::Embedder for TestEmbedder {
            fn dims(&self) -> usize {
                1
            }
            fn model_name(&self) -> &str {
                "test-hash:1"
            }
            fn prepare(&self, _entry: &respire::MemoryEntry) -> Result<respire::core_sdk::Prepared> {
                // This encrypted transport fixture does not exercise local retrieval.
                Ok(respire::core_sdk::Prepared {
                    artifact: Vec::new(),
                })
            }
        }
        let seal = |content: &str, time: &str| -> Result<StoredMemory> {
            let entry: respire::MemoryEntry = serde_json::from_value(
                serde_json::json!({"id":"entry","kind":"Context","tags":[],
                "title":"record","content":content,"user":"u","computer":"test","project":"sync",
                "created_at":"2026-09-19T00:00:00.000Z","updated_at":time,"emotion":-1.0,"parent_id":""}),
            )?;
            MemoryEngine::seal(&keys, &TestEmbedder, &entry, "u")
        };
        remote.put(&seal("current", "2026-09-19T00:00:00.003Z")?)?;
        assert!(!remote.put(&seal("current", "2026-09-19T00:00:00.001Z")?)?);
        let dir = tempfile::tempdir()?;
        let a = LocalStore::open(&dir.path().join("a.db"))?;
        let b = LocalStore::open(&dir.path().join("b.db"))?;
        let stats = respire::sync::sync_all(&keys, &a, &remote)?;
        assert_eq!(stats.conflicts, 0);
        assert_eq!(stats.processed_conflicts, 1);
        assert_eq!(stats.conflict_history, 1);
        let stats = respire::sync::sync_all(&keys, &b, &remote)?;
        assert_eq!(stats.processed_conflicts, 1);
        assert_eq!(stats.conflicts, 0);
        assert!(!remote.put(&seal("unique old edit", "2026-09-19T00:00:00.002Z")?)?);
        assert_eq!(respire::sync::sync_all(&keys, &a, &remote)?.conflicts, 1);
        let epoch = repo.sync_capabilities("u")?.epoch;
        let candidate = repo
            .sync_page("u", &epoch, 0, None, false)?
            .changes
            .last()
            .ok_or_else(|| anyhow::anyhow!("missing history"))?
            .rev;
        a.queue_conflict_resolution(
            &keys,
            &epoch,
            candidate,
            1,
            "merge",
            Some("current plus unique old edit"),
        )?;
        assert_eq!(respire::sync::sync_all(&keys, &a, &remote)?.conflicts, 0);
        let other = respire::sync::sync_all(&keys, &b, &remote)?;
        assert_eq!(other.conflicts, 0);
        assert_eq!(other.processed_conflicts, 2);
        assert_eq!(
            MemoryEngine::open(&keys, &b.all(false)?[0])?.content,
            "current plus unique old edit"
        );
        assert_eq!(
            repo.sync_page("u", &epoch, 0, None, false)?.changes.len(),
            4
        );
        Ok(())
    }

    fn setup() -> Result<(BlobRepo, String, i64)> {
        let repo = crate::store::connect_unique()?;
        repo.register("u", "hash", "salt")?;
        repo.put(
            "u",
            &BlobWrite {
                id: "entry",
                ciphertext: "current",
                nonce: "n",
                embedding_enc: "",
                updated_at: "2026-09-19T00:00:00.003Z",
                deleted: false,
            },
        )?;
        repo.put(
            "u",
            &BlobWrite {
                id: "entry",
                ciphertext: "old",
                nonce: "n",
                embedding_enc: "",
                updated_at: "2026-09-19T00:00:00.001Z",
                deleted: false,
            },
        )?;
        let epoch = repo.sync_capabilities("u")?.epoch;
        let page = repo.sync_page("u", &epoch, 0, None, false)?;
        let rev = page.changes[1].rev;
        Ok((repo, epoch, rev))
    }

    #[test]
    fn decisions_are_idempotent_cross_connection_and_do_not_change_content_cursors() -> Result<()> {
        let (repo, epoch, rev) = setup()?;
        let before = repo.pull("u", None)?.1;
        let req = ResolveRequest {
            epoch: epoch.clone(),
            items: vec![ResolutionDecision {
                conflict_rev: rev,
                expected_head_rev: 1,
                action: "keep_current".into(),
                restore_op_id: None,
            }],
        };
        let first = repo.resolve_conflicts("u", &req)?;
        let other = BlobRepo::connect(&repo.url)?;
        let repeated = other.resolve_conflicts("u", &req)?;
        assert_eq!(
            serde_json::to_value(first)?,
            serde_json::to_value(repeated)?
        );
        assert_eq!(repo.pull("u", None)?.1, before);
        assert_eq!(
            repo.sync_page("u", &epoch, 0, None, false)?.changes.len(),
            2
        );
        let feed = other.resolution_page("u", &epoch, 0, None)?;
        assert_eq!(feed.resolutions.len(), 1);
        assert_eq!(feed.cursor, 1);
        assert!(other
            .resolution_page("u", &epoch, 1, None)?
            .resolutions
            .is_empty());
        Ok(())
    }

    #[test]
    fn stale_decisions_and_unapplied_restoration_cannot_close_versions() -> Result<()> {
        let (repo, epoch, rev) = setup()?;
        repo.put(
            "u",
            &BlobWrite {
                id: "entry",
                ciphertext: "newer",
                nonce: "n",
                embedding_enc: "",
                updated_at: "2026-09-19T00:00:00.004Z",
                deleted: false,
            },
        )?;
        let req = ResolveRequest {
            epoch: epoch.clone(),
            items: vec![ResolutionDecision {
                conflict_rev: rev,
                expected_head_rev: 1,
                action: "keep_current".into(),
                restore_op_id: None,
            }],
        };
        assert_eq!(
            repo.resolve_conflicts("u", &req)?.results[0].outcome,
            "stale"
        );
        assert_eq!(repo.resolution_page("u", &epoch, 0, None)?.cursor, 0);
        let mut candidate = respire::StoredMemory::new_pending("entry".into(), "u".into());
        candidate.ciphertext = "restore".into();
        candidate.nonce = "n".into();
        candidate.updated_at = "2026-09-19T00:00:00.005Z".into();
        let op = Operation {
            op_id: "restore-op".into(),
            base_rev: Some(1),
            parent_op_id: None,
            blob: candidate,
        };
        assert_eq!(
            repo.sync_write("u", Some(&epoch), &[op])?.results[0].status,
            "conflict_saved"
        );
        let failed = ResolveRequest {
            epoch: epoch.clone(),
            items: vec![ResolutionDecision {
                conflict_rev: rev,
                expected_head_rev: 0,
                action: "restore".into(),
                restore_op_id: Some("restore-op".into()),
            }],
        };
        assert_eq!(
            repo.resolve_conflicts("u", &failed)?.results[0].outcome,
            "stale"
        );
        assert_eq!(repo.resolution_page("u", &epoch, 0, None)?.cursor, 0);
        let wrong_epoch = ResolveRequest {
            epoch: "wrong".into(),
            items: req.items,
        };
        assert!(repo.resolve_conflicts("u", &wrong_epoch).is_err());
        Ok(())
    }

    #[test]
    fn schema_two_upgrade_keeps_old_versions_and_starts_empty_resolution_stream() -> Result<()> {
        let (repo, epoch, _) = setup()?;
        let cursor = repo.pull("u", None)?.1;
        // Reconstruct the actual version-2 schema, including the pre-worker email table.
        repo.lock().batch_execute("DROP TABLE sync_resolutions;
            ALTER TABLE sync_accounts DROP COLUMN resolution_rev;
            ALTER TABLE mail_outbox DROP COLUMN status, DROP COLUMN attempts,
                DROP COLUMN next_attempt_at, DROP COLUMN expires_at, DROP COLUMN attempted_at,
                DROP COLUMN sent_at, DROP COLUMN last_error, DROP COLUMN code_id;
            ALTER TABLE users DROP COLUMN email_verified;
            ALTER TABLE verify_codes DROP COLUMN failed_attempts;
            UPDATE schema_meta SET v='2' WHERE k='version';")?;
        crate::store::migrations::apply(&mut repo.lock())?;
        assert_eq!(repo.pull("u", None)?.1, cursor);
        assert_eq!(
            repo.sync_page("u", &epoch, 0, None, false)?.changes.len(),
            2
        );
        assert_eq!(repo.resolution_page("u", &epoch, 0, None)?.cursor, 0);
        Ok(())
    }
}

impl BlobRepo {
    /// First committed decision wins. Duplicate requests return that decision.
    /// A keep/equivalent decision must still refer to the head inspected by the user.
    /// Restore/merge is acknowledged only after its content operation was applied.
    pub(crate) fn resolve_conflicts(
        &self,
        user: &str,
        request: &ResolveRequest,
    ) -> Result<ResolveReply> {
        if request.items.len() > PUSH_ITEMS {
            bail!("too many resolutions");
        }
        let mut c = self.lock();
        let mut tx = c.transaction()?;
        let state = tx
            .query_opt(
                "SELECT epoch,resolution_rev FROM sync_accounts WHERE \"user\"=$1 FOR UPDATE",
                &[&user],
            )?
            .ok_or_else(|| anyhow::anyhow!("synchronize account first"))?;
        if state.get::<_, String>(0) != request.epoch {
            bail!("sync epoch changed; snapshot required");
        }
        let mut seq: i64 = state.get(1);
        let mut results = Vec::new();
        for decision in &request.items {
            if !matches!(
                decision.action.as_str(),
                "equivalent" | "keep_current" | "restore" | "take_incoming" | "merge"
            ) {
                bail!("invalid resolution action");
            }
            let candidate = tx
                .query_opt(
                    "SELECT id,status FROM sync_versions WHERE \"user\"=$1 AND rev=$2",
                    &[&user, &decision.conflict_rev],
                )?
                .ok_or_else(|| anyhow::anyhow!("retained version not found"))?;
            if !matches!(
                candidate.get::<_, String>("status").as_str(),
                "conflict_saved" | "legacy_rejected"
            ) {
                bail!("version is not a conflict or rejected write");
            }
            let id: String = candidate.get("id");
            if let Some(row) = tx.query_opt(
                "SELECT * FROM sync_resolutions WHERE \"user\"=$1 AND conflict_rev=$2",
                &[&user, &decision.conflict_rev],
            )? {
                results.push(ResolutionResult {
                    conflict_rev: decision.conflict_rev,
                    outcome: "processed".into(),
                    resolution: Some(read_resolution(&row)),
                });
                continue;
            }
            let head: i64 = tx
                .query_opt(
                    "SELECT rev FROM sync_heads WHERE \"user\"=$1 AND id=$2",
                    &[&user, &id],
                )?
                .map(|r| r.get(0))
                .unwrap_or(0);
            let accepted = if matches!(
                decision.action.as_str(),
                "restore" | "take_incoming" | "merge"
            ) {
                let op = decision
                    .restore_op_id
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("restoration operation required"))?;
                let receipt = tx
                    .query_opt(
                        "SELECT id,status,rev FROM sync_versions WHERE \"user\"=$1 AND op_id=$2",
                        &[&user, &op],
                    )?
                    .ok_or_else(|| anyhow::anyhow!("restoration operation not received"))?;
                if receipt.get::<_, String>("id") != id {
                    bail!("restoration belongs to another object");
                }
                receipt.get::<_, String>("status") == "applied"
                    && receipt.get::<_, i64>("rev") > decision.conflict_rev
            } else {
                if decision.restore_op_id.is_some() {
                    bail!("unexpected restoration operation");
                }
                head > 0 && head == decision.expected_head_rev
            };
            if !accepted {
                results.push(ResolutionResult {
                    conflict_rev: decision.conflict_rev,
                    outcome: "stale".into(),
                    resolution: None,
                });
                continue;
            }
            seq = seq
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("resolution cursor exhausted"))?;
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let row=tx.query_one("INSERT INTO sync_resolutions(\"user\",conflict_rev,seq,id,action,head_rev,restore_op_id,processed_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
                &[&user,&decision.conflict_rev,&seq,&id,&decision.action,&head,&decision.restore_op_id,&now])?;
            results.push(ResolutionResult {
                conflict_rev: decision.conflict_rev,
                outcome: "processed".into(),
                resolution: Some(read_resolution(&row)),
            });
        }
        tx.execute(
            "UPDATE sync_accounts SET resolution_rev=$2 WHERE \"user\"=$1",
            &[&user, &seq],
        )?;
        tx.commit()?;
        Ok(ResolveReply { results })
    }

    /// Immutable disposition pages are committed locally separately from content.
    pub(crate) fn resolution_page(
        &self,
        user: &str,
        epoch: &str,
        after: i64,
        until: Option<i64>,
    ) -> Result<ResolutionPage> {
        let mut c = self.lock();
        let mut tx = c
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let state = tx
            .query_opt(
                "SELECT epoch,resolution_rev FROM sync_accounts WHERE \"user\"=$1",
                &[&user],
            )?
            .ok_or_else(|| anyhow::anyhow!("synchronize account first"))?;
        let current: i64 = state.get(1);
        let high = until.unwrap_or(current);
        if state.get::<_, String>(0) != epoch {
            bail!("sync epoch changed; snapshot required");
        }
        if after < 0 || high < after || high > current {
            bail!("invalid resolution cursor");
        }
        let rows=tx.query("SELECT * FROM sync_resolutions WHERE \"user\"=$1 AND seq>$2 AND seq<=$3 ORDER BY seq LIMIT $4",
            &[&user,&after,&high,&((PAGE_ITEMS+1) as i64)])?;
        let has_more = rows.len() > PAGE_ITEMS;
        let resolutions: Vec<_> = rows.iter().take(PAGE_ITEMS).map(read_resolution).collect();
        let cursor = if has_more {
            resolutions.last().map_or(after, |r| r.seq)
        } else {
            high
        };
        tx.commit()?;
        Ok(ResolutionPage {
            epoch: epoch.into(),
            cursor,
            until: high,
            has_more,
            resolutions,
        })
    }
}
