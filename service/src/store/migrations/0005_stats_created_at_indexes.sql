-- admin-ops-stats daily_stats scans users and sessions by day over created_at.
-- These are plain column indexes because the query's range predicate compares the
-- text directly: created_at is always written in the server's uniform RFC3339 UTC
-- format (now_rfc), where text order equals chronological order. An expression
-- index on created_at::timestamptz is not possible here (the cast is STABLE, and
-- index expressions must be IMMUTABLE). users is partial to match that query's
-- deleted = 0 filter exactly.
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at) WHERE deleted = 0;
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions (created_at);
