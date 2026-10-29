-- Deletion is final for an object ID. Keep only its empty head as evidence for
-- old clients; neither retries nor rejected resurrection attempts add history.
ALTER TABLE sync_accounts ADD COLUMN IF NOT EXISTS history_floor BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS sync_heads_revision ON sync_heads("user", rev);
-- Decisions contain no payload and must survive removal of their ciphertext.
ALTER TABLE sync_resolutions DROP CONSTRAINT IF EXISTS sync_resolutions_user_conflict_rev_fkey;

CREATE OR REPLACE FUNCTION compact_sync_history(account TEXT) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE removed BIGINT;
BEGIN
    UPDATE blobs SET ciphertext='', nonce='', embedding_enc=''
    WHERE "user"=account AND deleted<>0
      AND (ciphertext<>'' OR nonce<>'' OR embedding_enc<>'');
    UPDATE sync_versions v SET ciphertext='', nonce='', embedding_enc='', fingerprint=''
    FROM sync_heads h
    WHERE h."user"=account AND v."user"=h."user" AND v.rev=h.rev AND v.deleted<>0
      AND (v.ciphertext<>'' OR v.nonce<>'' OR v.embedding_enc<>'' OR v.fingerprint<>'');
    DELETE FROM sync_versions v USING sync_heads h, sync_versions head
    WHERE h."user"=account AND head."user"=h."user" AND head.rev=h.rev
      AND head.deleted<>0 AND v."user"=h."user" AND v.id=h.id AND v.rev<>h.rev;
    GET DIAGNOSTICS removed = ROW_COUNT;
    IF removed>0 THEN
        UPDATE sync_accounts SET history_floor=rev WHERE "user"=account;
    END IF;

    -- Current heads are required for synchronization. Everything else, including
    -- unresolved conflicts and operation receipts, shares a 1,000-row budget.
    DELETE FROM sync_versions v USING (
        SELECT history.rev FROM sync_versions history
        WHERE history."user"=account AND NOT EXISTS (
            SELECT 1 FROM sync_heads h WHERE h."user"=account AND h.rev=history.rev
        ) ORDER BY history.rev DESC OFFSET 1000
    ) expired
    WHERE v."user"=account AND v.rev=expired.rev;
    GET DIAGNOSTICS removed = ROW_COUNT;
    IF removed>0 THEN
        UPDATE sync_accounts SET history_floor=rev WHERE "user"=account;
    END IF;
END;
$$;

-- Upgrade existing deletions and oversized histories before serving requests.
SELECT compact_sync_history("user") FROM sync_accounts;
