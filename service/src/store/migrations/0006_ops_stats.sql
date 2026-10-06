-- Anonymous event totals survive edits, logout, and account deletion.
-- Old blobs have no trustworthy creation time: never infer it from client LWW time.
CREATE TABLE ops_daily_stats (
    day DATE PRIMARY KEY,
    registrations BIGINT NOT NULL DEFAULT 0 CHECK (registrations >= 0),
    memories BIGINT NOT NULL DEFAULT 0 CHECK (memories >= 0),
    sessions BIGINT NOT NULL DEFAULT 0 CHECK (sessions >= 0)
);
INSERT INTO schema_meta (k, v) VALUES (
    'ops_stats_started_at', to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
);
-- Historical registrations/sessions can only cover records retained at upgrade.
INSERT INTO ops_daily_stats (day, registrations)
SELECT (created_at::timestamptz AT TIME ZONE 'Asia/Shanghai')::date, COUNT(*)
FROM users GROUP BY 1;
INSERT INTO ops_daily_stats (day, sessions)
SELECT (created_at::timestamptz AT TIME ZONE 'Asia/Shanghai')::date, COUNT(*)
FROM sessions GROUP BY 1
ON CONFLICT (day) DO UPDATE SET sessions = excluded.sessions;

CREATE FUNCTION record_ops_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event_day DATE;
BEGIN
    IF TG_TABLE_NAME = 'blobs' THEN
        IF NEW.deleted <> 0 THEN RETURN NEW; END IF;
        event_day := (clock_timestamp() AT TIME ZONE 'Asia/Shanghai')::date;
        INSERT INTO ops_daily_stats (day, memories) VALUES (event_day, 1)
        ON CONFLICT (day) DO UPDATE SET memories = ops_daily_stats.memories + 1;
    ELSIF TG_TABLE_NAME = 'users' THEN
        event_day := (NEW.created_at::timestamptz AT TIME ZONE 'Asia/Shanghai')::date;
        INSERT INTO ops_daily_stats (day, registrations) VALUES (event_day, 1)
        ON CONFLICT (day) DO UPDATE SET registrations = ops_daily_stats.registrations + 1;
    ELSE
        event_day := (NEW.created_at::timestamptz AT TIME ZONE 'Asia/Shanghai')::date;
        INSERT INTO ops_daily_stats (day, sessions) VALUES (event_day, 1)
        ON CONFLICT (day) DO UPDATE SET sessions = ops_daily_stats.sessions + 1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER ops_user_insert AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION record_ops_insert();
CREATE TRIGGER ops_blob_insert AFTER INSERT ON blobs FOR EACH ROW EXECUTE FUNCTION record_ops_insert();
CREATE TRIGGER ops_session_insert AFTER INSERT ON sessions FOR EACH ROW EXECUTE FUNCTION record_ops_insert();
