-- sessions.readonly shipped without a recorded migration: existing databases
-- received it from the baseline ALTER that this migration replaces. IF NOT EXISTS
-- keeps it a no-op for fresh databases, whose baseline already creates the column.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS readonly INTEGER NOT NULL DEFAULT 0;
