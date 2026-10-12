-- Only opaque URK wrappers are persisted. PRF output never leaves the browser.
ALTER TABLE vault ADD COLUMN account_id TEXT NOT NULL DEFAULT gen_random_uuid()::text;
ALTER TABLE vault ADD COLUMN key_generation BIGINT NOT NULL DEFAULT 1
    CHECK (key_generation BETWEEN 1 AND 9007199254740991);
CREATE UNIQUE INDEX idx_vault_account_id ON vault(account_id);

CREATE TABLE vault_passkeys (
    credential_id TEXT PRIMARY KEY,
    "user" TEXT NOT NULL REFERENCES users("user") ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    key_generation BIGINT NOT NULL,
    label TEXT NOT NULL,
    passkey TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    prf_salt TEXT NOT NULL,
    wrapper TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX idx_vault_passkeys_user ON vault_passkeys("user");

-- Serialized WebAuthn state is exclusively server-side, never a client token.
CREATE TABLE vault_passkey_ceremonies (
    id TEXT PRIMARY KEY,
    "user" TEXT NOT NULL REFERENCES users("user") ON DELETE CASCADE,
    session_hash TEXT NOT NULL,
    account_id TEXT NOT NULL,
    key_generation BIGINT NOT NULL,
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('register','test','activate','unlock')),
    state TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX idx_vault_passkey_ceremonies_user ON vault_passkey_ceremonies("user");
CREATE INDEX idx_vault_passkey_ceremonies_expiry ON vault_passkey_ceremonies(expires_at);
