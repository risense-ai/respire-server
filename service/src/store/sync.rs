//! Shared v1/v2 write path. Account locks protect versions; the legacy counter
//! is reserved once per batch, in the same transaction as all visible writes.
use std::collections::HashMap;

use anyhow::{bail, Result};
use postgres::{IsolationLevel, Row};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::db::{BlobRepo, BlobWrite};
use respire::memory::model::StoredMemory;
use respire::transport::{compare_timestamps, protocol::*};

fn blob(row: &Row, user: &str) -> StoredMemory {
    StoredMemory {
        id: row.get("id"),
        user: user.to_owned(),
        ciphertext: row.get("ciphertext"),
        nonce: row.get("nonce"),
        embedding_enc: row.get("embedding_enc"),
        updated_at: row.get("updated_at"),
        deleted: row.get::<_, i32>("deleted") != 0,
        ..StoredMemory::new_pending(String::new(), String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_one_upgrade_preserves_legacy_cursor() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        repo.register("u", "hash", "salt")?;
        // This database belongs only to this test. Reconstruct the pre-v2 schema.
        repo.lock().batch_execute(
            "DROP TABLE sync_resolutions,sync_heads,sync_versions,sync_accounts;
            ALTER TABLE mail_outbox DROP COLUMN status, DROP COLUMN attempts,
                DROP COLUMN next_attempt_at, DROP COLUMN expires_at, DROP COLUMN attempted_at,
                DROP COLUMN sent_at, DROP COLUMN last_error, DROP COLUMN code_id;
            ALTER TABLE users DROP COLUMN email_verified;
            ALTER TABLE verify_codes DROP COLUMN failed_attempts;
            UPDATE schema_meta SET v='1' WHERE k='version';
            INSERT INTO blobs(\"user\",id,ciphertext,nonce,updated_at,deleted,rev)
            VALUES ('u','old','aa','11','2026-09-19T00:00:00.001Z',0,4000);
            UPDATE sync_counter SET val=4000 WHERE id=1;",
        )?;
        crate::store::migrations::apply(&mut repo.lock())?;
        let cap = repo.sync_capabilities("u")?;
        let snapshot = repo.sync_page("u", &cap.epoch, 0, None, true)?;
        assert_eq!(snapshot.changes.len(), 1);
        assert_eq!(repo.pull("u", Some(3999))?.0.len(), 1);
        assert_eq!(repo.pull("u", Some(4000))?.1, 4000);
        let mut next = operation(
            "old",
            "new",
            Some(snapshot.changes[0].rev),
            "2026-09-19T00:00:00.002Z",
        );
        next.blob.ciphertext = "bb".into();
        repo.sync_write("u", Some(&cap.epoch), &[next])?;
        let (blobs, cursor, _, _) = repo.pull("u", Some(4000))?;
        assert_eq!(blobs.len(), 1);
        assert_eq!(cursor, 4001);
        Ok(())
    }

    fn operation(id: &str, op: &str, base: Option<i64>, stamp: &str) -> Operation {
        let mut b = StoredMemory::new_pending(id.to_owned(), "u".to_owned());
        b.ciphertext = op.to_owned();
        b.nonce = "nonce".into();
        b.updated_at = stamp.to_owned();
        Operation {
            op_id: op.into(),
            base_rev: base,
            parent_op_id: None,
            blob: b,
        }
    }

    #[test]
    fn mixed_protocol_retries_conflicts_and_fixed_pages() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        repo.register("u", "hash", "salt")?;
        let cap = repo.sync_capabilities("u")?;
        let a = operation("a", "op-a", None, "2026-09-19T00:00:01.000Z");
        let receipt = repo.sync_write("u", Some(&cap.epoch), std::slice::from_ref(&a))?;
        assert_eq!(receipt.results[0].status, "applied");
        let again = repo.sync_write("u", Some(&cap.epoch), std::slice::from_ref(&a))?;
        assert_eq!(receipt.results[0].stored_rev, again.results[0].stored_rev);
        let mut reused = a.clone();
        reused.blob.ciphertext = "different".into();
        assert!(repo.sync_write("u", Some(&cap.epoch), &[reused]).is_err());
        let stale = operation("a", "offline", None, "2026-09-19T00:00:02.000Z");
        let conflict = repo.sync_write("u", Some(&cap.epoch), &[stale])?;
        assert_eq!(conflict.results[0].status, "conflict_saved");
        let first = repo.sync_page("u", &cap.epoch, 0, None, false)?;
        assert_eq!(first.changes.len(), 2);
        assert!(!repo.put(
            "u",
            &BlobWrite {
                id: "a",
                ciphertext: "old",
                nonce: "n",
                embedding_enc: "",
                updated_at: "2026-09-19T00:00:00.000Z",
                deleted: false
            }
        )?);
        let fixed = repo.sync_page("u", &cap.epoch, 0, Some(first.until), false)?;
        assert_eq!(fixed.changes.len(), 2);
        let next = repo.sync_page("u", &cap.epoch, first.cursor, None, false)?;
        assert_eq!(next.changes.len(), 1);
        assert_eq!(next.changes[0].status, "legacy_rejected");
        assert_eq!(repo.pull("u", None)?.0[0].ciphertext, "op-a");
        assert!(repo.sync_write("u", Some("wrong"), &[a]).is_err());
        Ok(())
    }

    #[test]
    fn concurrent_connections_preserve_both_edits() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        repo.register("u", "hash", "salt")?;
        let epoch = repo.sync_capabilities("u")?.epoch;
        let other = BlobRepo::connect(&repo.url)?;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let guard = barrier.clone();
        let e = epoch.clone();
        let handle = std::thread::spawn(move || -> Result<PushReply> {
            guard.wait();
            other.sync_write(
                "u",
                Some(&e),
                &[operation("same", "b", None, "2026-09-19T00:00:02.000Z")],
            )
        });
        barrier.wait();
        let a = repo.sync_write(
            "u",
            Some(&epoch),
            &[operation("same", "a", None, "2026-09-19T00:00:01.000Z")],
        )?;
        let b = handle
            .join()
            .map_err(|_| anyhow::anyhow!("worker panicked"))??;
        assert_ne!(a.results[0].status, b.results[0].status);
        assert_eq!(
            repo.sync_page("u", &epoch, 0, None, false)?.changes.len(),
            2
        );
        Ok(())
    }

    #[test]
    fn pagination_and_batch_throughput_preserve_every_version() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        repo.register("u", "hash", "salt")?;
        let epoch = repo.sync_capabilities("u")?.epoch;
        let batch: Vec<_> = (0..250)
            .map(|i| {
                operation(
                    &format!("id-{i}"),
                    &format!("op-{i}"),
                    None,
                    "2026-09-19T00:00:00.001Z",
                )
            })
            .collect();
        let start = std::time::Instant::now();
        for chunk in batch.chunks(PUSH_ITEMS) {
            repo.sync_write("u", Some(&epoch), chunk)?;
        }
        eprintln!(
            "sync benchmark: 250 writes / 3 batches = {} ms",
            start.elapsed().as_millis()
        );
        let first = repo.sync_page("u", &epoch, 0, None, true)?;
        assert!(first.has_more);
        assert_eq!(first.changes.len(), PAGE_ITEMS);
        repo.sync_write(
            "u",
            Some(&epoch),
            &[operation(
                "later",
                "later-op",
                None,
                "2026-09-19T00:00:00.002Z",
            )],
        )?;
        let second = repo.sync_page("u", &epoch, first.cursor, Some(first.until), true)?;
        assert!(!second.has_more);
        assert_eq!(second.changes.len(), 50);
        let incremental = repo.sync_page("u", &epoch, second.cursor, None, false)?;
        assert_eq!(incremental.changes.len(), 1);
        Ok(())
    }
}

fn same(a: &StoredMemory, b: &StoredMemory) -> bool {
    a.ciphertext == b.ciphertext && a.nonce == b.nonce && a.deleted == b.deleted
}

impl BlobRepo {
    /// Capability probing creates only the account cursor, never a content edit.
    pub(crate) fn sync_capabilities(&self, user: &str) -> Result<Capabilities> {
        let mut c = self.lock();
        c.execute(
            "INSERT INTO sync_accounts (\"user\",epoch) VALUES ($1,$2) ON CONFLICT DO NOTHING",
            &[&user, &uuid::Uuid::new_v4().to_string()],
        )?;
        let epoch: String = c
            .query_one(
                "SELECT epoch FROM sync_accounts WHERE \"user\"=$1",
                &[&user],
            )?
            .get(0);
        Ok(Capabilities {
            protocols: vec![1, 2],
            epoch,
            push_items: PUSH_ITEMS,
            push_bytes: BATCH_BYTES,
            conflict_resolution: true,
        })
    }

    /// Legacy inputs keep their LWW result while even rejected versions are archived.
    pub(crate) fn sync_legacy(&self, user: &str, items: &[BlobWrite<'_>]) -> Result<Vec<bool>> {
        let ops: Vec<Operation> = items
            .iter()
            .map(|b| Operation {
                op_id: String::new(),
                base_rev: None,
                parent_op_id: None,
                blob: StoredMemory {
                    id: b.id.to_owned(),
                    user: user.to_owned(),
                    ciphertext: b.ciphertext.to_owned(),
                    nonce: b.nonce.to_owned(),
                    embedding_enc: b.embedding_enc.to_owned(),
                    updated_at: b.updated_at.to_owned(),
                    deleted: b.deleted,
                    ..StoredMemory::new_pending(String::new(), String::new())
                },
            })
            .collect();
        Ok(self
            .sync_write(user, None, &ops)?
            .results
            .iter()
            .map(|r| r.status == "applied")
            .collect())
    }

    /// One transaction records immutable versions, receipt identities and both cursors.
    pub(crate) fn sync_write(
        &self,
        user: &str,
        epoch: Option<&str>,
        ops: &[Operation],
    ) -> Result<PushReply> {
        let mut c = self.lock();
        let mut tx = c.transaction()?;
        tx.execute(
            "INSERT INTO sync_accounts (\"user\",epoch) VALUES ($1,$2) ON CONFLICT DO NOTHING",
            &[&user, &uuid::Uuid::new_v4().to_string()],
        )?;
        let state = tx.query_one(
            "SELECT epoch,rev FROM sync_accounts WHERE \"user\"=$1 FOR UPDATE",
            &[&user],
        )?;
        let actual_epoch: String = state.get(0);
        if epoch.is_some_and(|e| e != actual_epoch) {
            bail!("sync epoch changed; snapshot required");
        }
        let mut rev: i64 = state.get(1);
        let ids: Vec<String> = ops.iter().map(|o| o.blob.id.clone()).collect();
        let mut heads: HashMap<String, (i64, StoredMemory)> = tx.query(
            "SELECT v.* FROM sync_heads h JOIN sync_versions v USING (\"user\",rev) WHERE h.\"user\"=$1 AND h.id=ANY($2)",
            &[&user, &ids])?.iter().map(|r| (r.get("id"), (r.get("rev"), blob(r,user)))).collect();
        let op_ids: Vec<String> = ops
            .iter()
            .flat_map(|o| std::iter::once(o.op_id.clone()).chain(o.parent_op_id.clone()))
            .collect();
        let mut known: HashMap<String, (String, Receipt, String)> = tx.query(
            "SELECT op_id,fingerprint,status,rev,head_rev,id FROM sync_versions WHERE \"user\"=$1 AND op_id=ANY($2)",
            &[&user,&op_ids])?.iter().map(|r| {
                let op_id: String = r.get("op_id");
                (op_id.clone(), (r.get("fingerprint"), Receipt { op_id, status:r.get("status"),
                    stored_rev:r.get("rev"), head_rev:r.get("head_rev") },r.get("id")))
            }).collect();
        let mut versions = Vec::new();
        let mut applied = Vec::new();
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            let mut b = op.blob.clone();
            b.user = user.to_owned();
            let fingerprint = format!("{:x}", Sha256::digest(serde_json::to_vec(op)?));
            if epoch.is_some() {
                if let Some((previous, result, _)) = known.get(&op.op_id) {
                    if previous != &fingerprint {
                        bail!("op_id reused with different content");
                    }
                    results.push(result.clone());
                    continue;
                }
            }
            let head = heads.get(&b.id);
            let head_rev = head.map_or(0, |h| h.0);
            let mut base = op.base_rev;
            let mut parent_conflict = false;
            if epoch.is_some() {
                if let Some(parent) = &op.parent_op_id {
                    let Some((_, receipt, id)) = known.get(parent) else {
                        bail!("parent operation not acknowledged");
                    };
                    if id != &b.id {
                        bail!("parent operation belongs to another object");
                    }
                    base = Some(receipt.stored_rev);
                    parent_conflict = receipt.status != "applied";
                }
            }
            let identical = head.is_some_and(|h| same(&h.1, &b) && h.1.updated_at == b.updated_at);
            let timestamp_ok = match head {
                Some(h) => !compare_timestamps(&h.1.updated_at, &b.updated_at)?.is_gt(),
                None => true,
            };
            let accepted = if epoch.is_none() {
                timestamp_ok
            } else {
                !parent_conflict
                    && (identical
                        || (base == Some(head_rev) && timestamp_ok)
                        || (head.is_none() && base.is_none()))
            };
            let status = if accepted {
                "applied"
            } else if epoch.is_none() {
                "legacy_rejected"
            } else {
                "conflict_saved"
            };
            rev = rev
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("sync revision exhausted"))?;
            if accepted {
                // Preserve old vector ciphertext only for unchanged content. New clients
                // never depend on a legacy embedding for a newly edited payload.
                if b.embedding_enc.is_empty() {
                    if let Some((_, old)) = head {
                        b.embedding_enc.clone_from(&old.embedding_enc);
                    }
                }
                heads.insert(b.id.clone(), (rev, b.clone()));
            }
            let receipt = Receipt {
                op_id: op.op_id.clone(),
                status: status.to_owned(),
                stored_rev: rev,
                head_rev: if accepted { rev } else { head_rev },
            };
            let event = json!({"rev":rev,"id":b.id,"op_id":if epoch.is_some(){Some(&op.op_id)}else{None},
                "fingerprint":fingerprint,"status":status,"head_rev":receipt.head_rev,
                "ciphertext":b.ciphertext,"nonce":b.nonce,"embedding_enc":b.embedding_enc,
                "updated_at":b.updated_at,"deleted":i32::from(b.deleted)});
            if accepted {
                applied.push(event.clone());
            }
            versions.push(event);
            if epoch.is_some() {
                known.insert(op.op_id.clone(), (fingerprint, receipt.clone(), b.id));
            }
            results.push(receipt);
        }
        if !versions.is_empty() {
            let data = serde_json::to_string(&versions)?;
            tx.execute("INSERT INTO sync_versions (\"user\",rev,id,op_id,fingerprint,status,head_rev,ciphertext,nonce,embedding_enc,updated_at,deleted)
                SELECT $1,v.* FROM jsonb_to_recordset($2::text::jsonb) AS v(rev bigint,id text,op_id text,fingerprint text,status text,head_rev bigint,ciphertext text,nonce text,embedding_enc text,updated_at text,deleted integer)", &[&user,&data])?;
            tx.execute(
                "UPDATE sync_accounts SET rev=$2 WHERE \"user\"=$1",
                &[&user, &rev],
            )?;
        }
        if !applied.is_empty() {
            let count = applied.len() as i64;
            let last: i64 = tx
                .query_one(
                    "UPDATE sync_counter SET val=val+$1 WHERE id=1 RETURNING val",
                    &[&count],
                )?
                .get(0);
            for (i, v) in applied.iter_mut().enumerate() {
                v["legacy_rev"] = json!(last - count + 1 + i as i64);
            }
            let data = serde_json::to_string(&applied)?;
            tx.execute("INSERT INTO blobs (\"user\",id,ciphertext,nonce,embedding_enc,updated_at,deleted,rev)
                SELECT $1,id,ciphertext,nonce,embedding_enc,updated_at,deleted,legacy_rev FROM (
                SELECT DISTINCT ON(id) * FROM jsonb_to_recordset($2::text::jsonb)
                AS v(id text,ciphertext text,nonce text,embedding_enc text,updated_at text,deleted integer,legacy_rev bigint)
                ORDER BY id,legacy_rev DESC) AS latest
                ON CONFLICT (\"user\",id) DO UPDATE SET ciphertext=excluded.ciphertext,nonce=excluded.nonce,
                embedding_enc=excluded.embedding_enc,updated_at=excluded.updated_at,deleted=excluded.deleted,rev=excluded.rev", &[&user,&data])?;
            tx.execute("INSERT INTO sync_heads (\"user\",id,rev)
                SELECT $1,id,max(rev) FROM jsonb_to_recordset($2::text::jsonb) AS v(id text,rev bigint) GROUP BY id
                ON CONFLICT (\"user\",id) DO UPDATE SET rev=excluded.rev", &[&user,&data])?;
        }
        tx.commit()?;
        Ok(PushReply { results })
    }

    /// A stable upper bound plus immutable rows allows bounded pages during writes.
    pub(crate) fn sync_page(
        &self,
        user: &str,
        epoch: &str,
        after: i64,
        until: Option<i64>,
        snapshot: bool,
    ) -> Result<Page> {
        self.sync_capabilities(user)?;
        let mut c = self.lock();
        let mut tx = c
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let state = tx.query_one(
            "SELECT epoch,rev FROM sync_accounts WHERE \"user\"=$1",
            &[&user],
        )?;
        let actual: String = state.get(0);
        let current: i64 = state.get(1);
        if epoch != actual {
            bail!("sync epoch changed; snapshot required");
        }
        let high = until.unwrap_or(current);
        if after < 0 || high < after || high > current {
            bail!("invalid sync cursor");
        }
        let rows=tx.query("SELECT v.* FROM sync_versions v WHERE v.\"user\"=$1 AND v.rev>$2 AND v.rev<=$3
            AND (NOT $4 OR v.status<>'applied' OR NOT EXISTS (
              SELECT 1 FROM sync_versions n WHERE n.\"user\"=v.\"user\" AND n.id=v.id AND n.status='applied' AND n.rev>v.rev AND n.rev<=$3))
            ORDER BY v.rev LIMIT $5", &[&user,&after,&high,&snapshot,&((PAGE_ITEMS+1) as i64)])?;
        let mut changes = Vec::new();
        let mut bytes = 0;
        for r in rows.iter().take(PAGE_ITEMS) {
            let change = Change {
                rev: r.get("rev"),
                status: r.get("status"),
                op_id: r.get("op_id"),
                blob: blob(r, user),
            };
            let size = serde_json::to_vec(&change)?.len();
            if !changes.is_empty() && bytes + size > BATCH_BYTES {
                break;
            }
            bytes += size;
            changes.push(change);
        }
        let more = rows.len() > changes.len();
        let cursor = if more {
            changes.last().map_or(after, |v| v.rev)
        } else {
            high
        };
        let counts = tx.query_one(
            "SELECT count(*),count(*) FILTER (WHERE deleted=0) FROM blobs WHERE \"user\"=$1",
            &[&user],
        )?;
        let total: i64 = counts.get(0);
        let alive: i64 = counts.get(1);
        tx.commit()?;
        Ok(Page {
            epoch: actual,
            until: high,
            cursor,
            has_more: more,
            changes,
            total: total as u64,
            alive: alive as u64,
        })
    }
}
