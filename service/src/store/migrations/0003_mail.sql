-- Historical rows were never delivered and must not be replayed.
ALTER TABLE mail_outbox ADD COLUMN status TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE mail_outbox ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mail_outbox ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE mail_outbox ADD COLUMN expires_at TIMESTAMPTZ;
ALTER TABLE mail_outbox ADD COLUMN attempted_at TIMESTAMPTZ;
ALTER TABLE mail_outbox ADD COLUMN sent_at TIMESTAMPTZ;
ALTER TABLE mail_outbox ADD COLUMN last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE mail_outbox ADD COLUMN code_id TEXT;
UPDATE mail_outbox SET body = '' WHERE status = 'legacy';
CREATE INDEX mail_outbox_pending ON mail_outbox(next_attempt_at, id) WHERE status = 'pending';

ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE verify_codes ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
