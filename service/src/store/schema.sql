CREATE TABLE IF NOT EXISTS schema_meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    "user" TEXT PRIMARY KEY,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL DEFAULT '',
    token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    email TEXT NOT NULL DEFAULT '',
    totp_secret TEXT NOT NULL DEFAULT '',
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    "user" TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    -- Read-only session: team members may recall but cannot write.
    -- Enforced on write endpoints server-side (not just hidden in the client); existing rows default to 0.
    readonly INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions("user");

CREATE TABLE IF NOT EXISTS blobs (
    "user" TEXT NOT NULL,
    id TEXT NOT NULL,
    ciphertext TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    embedding_enc TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    deleted INTEGER NOT NULL DEFAULT 0,
    rev BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY ("user", id)
);
CREATE INDEX IF NOT EXISTS idx_blobs_user_updated ON blobs("user", updated_at);
CREATE INDEX IF NOT EXISTS idx_blobs_user_rev ON blobs("user", rev);

CREATE TABLE IF NOT EXISTS sync_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    val BIGINT NOT NULL DEFAULT 0
);
INSERT INTO sync_counter (id, val) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS super_admins (
    "user" TEXT PRIMARY KEY,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    disabled INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at);

CREATE TABLE IF NOT EXISTS mail_outbox (
    id BIGSERIAL PRIMARY KEY,
    at TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verify_codes (
    id TEXT PRIMARY KEY,
    audience TEXT NOT NULL,
    purpose TEXT NOT NULL,
    code_hash TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault (
    "user" TEXT PRIMARY KEY,
    kdf_salt TEXT NOT NULL,
    wrapped_urk TEXT NOT NULL,
    urk_nonce TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 2,
    updated_at TEXT NOT NULL
);
