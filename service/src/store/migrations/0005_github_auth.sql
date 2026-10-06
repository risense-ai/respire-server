-- GitHub's numeric ID is stable across login-name changes. Never link by email.
CREATE TABLE IF NOT EXISTS github_identities (
    github_id BIGINT PRIMARY KEY CHECK (github_id > 0),
    "user" TEXT NOT NULL UNIQUE REFERENCES users("user") ON DELETE CASCADE,
    github_login TEXT NOT NULL,
    linked_at TEXT NOT NULL
);

-- Short-lived authorization state and PKCE verifier; no provider access token.
CREATE TABLE IF NOT EXISTS github_authorizations (
    state_hash TEXT PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (purpose IN ('login', 'bind')),
    owner_user TEXT NOT NULL DEFAULT '',
    verifier TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_github_authorizations_expiry ON github_authorizations(expires_at);
