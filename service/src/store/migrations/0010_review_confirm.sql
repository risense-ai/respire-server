ALTER TABLE vault_passkey_ceremonies DROP CONSTRAINT vault_passkey_ceremonies_kind_check;
ALTER TABLE vault_passkey_ceremonies ADD CONSTRAINT vault_passkey_ceremonies_kind_check
    CHECK (kind IN ('register','test','activate','unlock','review-confirm'));

-- No claim, evidence, plaintext memory, or URK is retained here.
CREATE TABLE review_confirmations (
    event_id TEXT PRIMARY KEY,
    "user" TEXT NOT NULL REFERENCES users("user") ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    key_generation BIGINT NOT NULL,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    binding TEXT NOT NULL,
    confirmed_at TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    revocation_reason TEXT
);
CREATE INDEX idx_review_confirmations_user ON review_confirmations("user");
