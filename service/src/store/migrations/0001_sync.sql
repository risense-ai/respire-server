-- The legacy global cursor is deliberately unchanged.
CREATE TABLE IF NOT EXISTS sync_accounts (
    "user" TEXT PRIMARY KEY REFERENCES users("user") ON DELETE CASCADE,
    epoch TEXT NOT NULL,
    rev BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sync_versions (
    "user" TEXT NOT NULL REFERENCES users("user") ON DELETE CASCADE,
    rev BIGINT NOT NULL,
    id TEXT NOT NULL,
    op_id TEXT,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    head_rev BIGINT NOT NULL,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    embedding_enc TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    deleted INTEGER NOT NULL,
    PRIMARY KEY ("user", rev),
    UNIQUE ("user", op_id)
);
CREATE INDEX IF NOT EXISTS sync_versions_object ON sync_versions("user", id, rev DESC);
CREATE TABLE IF NOT EXISTS sync_heads (
    "user" TEXT NOT NULL REFERENCES users("user") ON DELETE CASCADE,
    id TEXT NOT NULL,
    rev BIGINT NOT NULL,
    PRIMARY KEY ("user", id)
);
-- Startup holds the schema lock and finishes before HTTP starts. Existing versions
-- are a baseline, not invented historical edits. Tombstones are included.
INSERT INTO sync_accounts ("user", epoch)
SELECT "user", md5(random()::text || clock_timestamp()::text || "user") FROM users
ON CONFLICT DO NOTHING;
INSERT INTO sync_versions
    ("user", rev, id, fingerprint, status, head_rev, ciphertext, nonce, embedding_enc, updated_at, deleted)
SELECT b."user", row_number() OVER (PARTITION BY b."user" ORDER BY b.id), b.id, '', 'applied',
       row_number() OVER (PARTITION BY b."user" ORDER BY b.id),
       b.ciphertext, b.nonce, b.embedding_enc, b.updated_at, b.deleted
FROM blobs b WHERE NOT EXISTS (SELECT 1 FROM sync_versions v WHERE v."user"=b."user")
ON CONFLICT DO NOTHING;
INSERT INTO sync_heads ("user", id, rev)
SELECT "user", id, max(rev) FROM sync_versions WHERE status='applied' GROUP BY "user", id
ON CONFLICT DO NOTHING;
UPDATE sync_accounts a SET rev=GREATEST(a.rev, v.rev)
FROM (SELECT "user", max(rev) AS rev FROM sync_versions GROUP BY "user") v
WHERE a."user"=v."user";
