ALTER TABLE sync_accounts ADD COLUMN IF NOT EXISTS resolution_rev BIGINT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS sync_resolutions (
    "user" TEXT NOT NULL REFERENCES users("user") ON DELETE CASCADE,
    conflict_rev BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('equivalent','keep_current','restore','take_incoming','merge')),
    head_rev BIGINT NOT NULL,
    restore_op_id TEXT,
    processed_at TEXT NOT NULL,
    PRIMARY KEY ("user",conflict_rev),
    UNIQUE ("user",seq),
    FOREIGN KEY ("user",conflict_rev) REFERENCES sync_versions("user",rev) ON DELETE CASCADE
);
