//! Cloud storage: Postgres. serve does not open SQLite.

use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use postgres::{Client, NoTls, Row};
use sha2::{Digest, Sha256};

use respire::memory::crypto::random_hex;
use respire::memory::model::StoredMemory;

pub(crate) struct BlobWrite<'a> {
    pub id: &'a str,
    pub ciphertext: &'a str,
    pub nonce: &'a str,
    pub embedding_enc: &'a str,
    pub updated_at: &'a str,
    pub deleted: bool,
}

pub(crate) struct BlobRepo {
    client: Mutex<Client>,
    pub(crate) url: String,
}

fn now_rfc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn is_expired(rfc: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(rfc)
        .map(|t| t.with_timezone(&chrono::Utc) < chrono::Utc::now())
        .unwrap_or(true)
}

pub(crate) fn mask_token(token: &str) -> String {
    if token.len() <= 10 {
        return "…".to_owned();
    }
    format!("{}…{}", &token[..6], &token[token.len() - 4..])
}

#[cfg(test)]
fn db_name_url(base: &str, name: &str) -> String {
    let (prefix, _) = base.rsplit_once('/').unwrap_or((base, ""));
    format!("{prefix}/{name}")
}

impl BlobRepo {
    fn connect_client(url: &str) -> Result<Client> {
        let mut config: postgres::Config = url.parse()?;
        config.connect_timeout(std::time::Duration::from_secs(5));
        config.connect(NoTls).context("connect Postgres failed")
    }

    pub(crate) fn connect(url: &str) -> Result<Self> {
        let mut client = Self::connect_client(url)?;
        crate::store::migrations::apply(&mut client)?;
        Ok(Self {
            client: Mutex::new(client),
            url: url.to_owned(),
        })
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.client.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reconnect before a new HTTP request, never replay a possibly committed write.
    pub(crate) fn ensure_connected(&self) -> Result<()> {
        let mut client = self.lock();
        if client.is_closed() {
            *client = Self::connect_client(&self.url)?;
        }
        Ok(())
    }

    /// Readiness includes the database and expected schema; /health remains liveness.
    pub(crate) fn ready(&self) -> Result<()> {
        self.ensure_connected()?;
        let version: String = self.lock().query_one("SELECT v FROM schema_meta WHERE k='version'", &[])?.get(0);
        if version != crate::store::migrations::CURRENT_SCHEMA_VERSION.to_string() {
            anyhow::bail!("database schema does not match this server");
        }
        Ok(())
    }

    pub(crate) fn exists_user(&self, user: &str) -> bool {
        self.lock()
            .query_opt(r#"SELECT 1 FROM users WHERE "user"=$1"#, &[&user])
            .ok()
            .flatten()
            .is_some()
    }

    fn arrival_seq(&self) -> Result<u64> {
        let row = self
            .lock()
            .query_one("SELECT val FROM sync_counter WHERE id = 1", &[])
            .map_err(anyhow::Error::from)?;
        let val: i64 = row.get(0);
        Ok(val as u64)
    }

    pub(crate) fn session_response(
        &self,
        user: &str,
        legacy_token: String,
        device_name: Option<&str>,
    ) -> Result<serde_json::Value> {
        if let Some(name) = device_name {
            let (token, id) = self.create_session(user, name.trim())?;
            Ok(serde_json::json!({"user":user,"token":token,"session_id":id}))
        } else {
            Ok(serde_json::json!({"user":user,"token":legacy_token}))
        }
    }

    pub(crate) fn register_session(
        &self,
        user: &str,
        pass_hash: &str,
        salt: &str,
        name: Option<&str>,
    ) -> Result<Option<serde_json::Value>> {
        let Some(token) = self.register(user, pass_hash, salt)? else {
            return Ok(None);
        };
        Ok(Some(self.session_response(user, token, name)?))
    }

    pub(crate) fn login_session(
        &self,
        user: &str,
        pass_hash: &str,
        name: Option<&str>,
    ) -> Result<Option<serde_json::Value>> {
        let Some(token) = self.login(user, pass_hash)? else {
            return Ok(None);
        };
        let totp: String = self
            .lock()
            .query_one(r#"SELECT totp_secret FROM users WHERE "user"=$1"#, &[&user])
            .map_err(anyhow::Error::from)?
            .get(0);
        if !totp.is_empty() {
            let ticket = self.issue_ticket(user, "user_totp")?;
            return Ok(Some(serde_json::json!({"totp_required": true, "ticket": ticket, "user": user})));
        }
        Ok(Some(self.session_response(user, token, name)?))
    }

    pub(crate) fn register(&self, user: &str, pass_hash: &str, salt: &str) -> Result<Option<String>> {
        if self.exists_user(user) {
            return Ok(None);
        }
        let token = random_hex(32);
        let now = now_rfc();
        self.lock()
            .execute(
                r#"INSERT INTO users ("user", pass_hash, salt, token, created_at) VALUES ($1,$2,$3,$4,$5)"#,
                &[&user, &pass_hash, &salt, &token, &now],
            )
            .map_err(anyhow::Error::from)?;
        Ok(Some(token))
    }

    pub(crate) fn login(&self, user: &str, pass_hash: &str) -> Result<Option<String>> {
        let row = self.lock().query_opt(
            r#"SELECT pass_hash, token, disabled, deleted FROM users WHERE "user"=$1"#,
            &[&user],
        )?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_hash: String = row.get(0);
        let token: String = row.get(1);
        let disabled: i32 = row.get(2);
        let deleted: i32 = row.get(3);
        if deleted != 0 {
            return Err(anyhow!("deleted"));
        }
        if disabled != 0 {
            return Err(anyhow!("disabled"));
        }
        // Empty hashes mark provider-only accounts, never valid password credentials.
        if stored_hash.is_empty() || pass_hash.is_empty() {
            return Ok(None);
        }
        if stored_hash == pass_hash {
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn create_session(&self, user: &str, device_name: &str) -> Result<(String, String)> {
        self.create_session_with(user, device_name, false)
    }

    /// Create a session, optionally read-only (team member who may recall but not write; enforced server-side).
    pub(crate) fn create_session_with(
        &self,
        user: &str,
        device_name: &str,
        readonly: bool,
    ) -> Result<(String, String)> {
        let id = uuid::Uuid::new_v4().to_string();
        let token = random_hex(32);
        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let created_at = now_rfc();
        let readonly_flag: i32 = if readonly { 1 } else { 0 };
        self.lock()
            .execute(
                r#"INSERT INTO sessions (id,"user",token_hash,device_name,created_at,readonly)
                   VALUES ($1,$2,$3,$4,$5,$6)"#,
                &[&id, &user, &token_hash, &device_name, &created_at, &readonly_flag],
            )
            .map_err(anyhow::Error::from)?;
        Ok((token, id))
    }

    /// Whether this token is a read-only session (non-session / user primary tokens are false).
    ///
    /// Reject read-only team members server-side,
    /// not merely hidden in the client. Read-only is a **session** property, not a user
    /// property — one account may hold a read-write session (the owner) and a read-only
    /// session (a recall-only teammate) at the same time.
    pub(crate) fn token_is_readonly(&self, token: &str) -> Result<bool> {
        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let row = self.lock().query_opt(
            r#"SELECT readonly FROM sessions WHERE token_hash=$1"#,
            &[&token_hash],
        )?;
        Ok(row.map(|r| r.get::<_, i32>(0) != 0).unwrap_or(false))
    }

    pub(crate) fn list_sessions(&self, user: &str, token: &str) -> Result<Vec<serde_json::Value>> {
        let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let rows = self.lock().query(
            r#"SELECT id,device_name,created_at,token_hash FROM sessions WHERE "user"=$1 ORDER BY created_at,id"#,
            &[&user],
        )?;
        Ok(rows
            .iter()
            .map(|row| {
                let th: String = row.get(3);
                serde_json::json!({
                    "id": row.get::<_, String>(0),
                    "device_name": row.get::<_, String>(1),
                    "created_at": row.get::<_, String>(2),
                    "current": th == hash,
                })
            })
            .collect())
    }

    pub(crate) fn revoke_session(&self, user: &str, id: &str) -> Result<bool> {
        Ok(self.lock().execute(
            r#"DELETE FROM sessions WHERE "user"=$1 AND id=$2"#,
            &[&user, &id],
        )? > 0)
    }

    pub(crate) fn try_user_from_token(&self, token: &str) -> Result<Option<String>> {
        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        Ok(self.lock()
            .query_opt(
                r#"SELECT "user" FROM users WHERE token=$1 AND disabled=0 AND deleted=0
                   UNION ALL SELECT s."user" FROM sessions s JOIN users u ON u."user"=s."user"
                   WHERE s.token_hash=$2 AND u.disabled=0 AND u.deleted=0 LIMIT 1"#,
                &[&token, &token_hash],
            )?
            .map(|row| row.get(0)))
    }

    #[cfg(test)]
    pub(crate) fn user_from_token(&self, token: &str) -> Result<Option<String>> {
        self.try_user_from_token(token)
    }

    pub(crate) fn list_users(&self, q: &str, page: u32, limit: u32) -> Result<(Vec<serde_json::Value>, i64)> {
        self.list_users_filtered(q, page, limit, "all")
    }

    pub(crate) fn users_summary(&self) -> Result<serde_json::Value> {
        let row = self.lock().query_one(
            r#"SELECT COUNT(*),
                      COUNT(*) FILTER (WHERE deleted = 0 AND disabled = 0),
                      COUNT(*) FILTER (WHERE deleted = 0 AND disabled <> 0),
                      COUNT(*) FILTER (WHERE deleted <> 0),
                      (SELECT COUNT(*) FROM sessions s JOIN users u ON u."user" = s."user"
                       WHERE u.deleted = 0 AND u.disabled = 0),
                      (SELECT COUNT(*) FROM blobs WHERE deleted = 0)
               FROM users"#,
            &[],
        )?;
        Ok(serde_json::json!({
            "all": row.get::<_, i64>(0), "ok": row.get::<_, i64>(1),
            "banned": row.get::<_, i64>(2), "deleted": row.get::<_, i64>(3),
            "sessions": row.get::<_, i64>(4), "ciphertext": row.get::<_, i64>(5),
        }))
    }

    /// Anonymous insert totals; old memory creation dates are unknown, not zero.
    pub(crate) fn daily_stats(&self, days: u32) -> Result<serde_json::Value> {
        let today = (chrono::Utc::now() + chrono::Duration::hours(8)).date_naive();
        self.daily_stats_until(days, today)
    }

    fn daily_stats_until(&self, days: u32, today: chrono::NaiveDate) -> Result<serde_json::Value> {
        let days = days.max(1);
        let start = today - chrono::Duration::days(days as i64 - 1);
        let mut counts: std::collections::HashMap<String, [i64; 3]> = std::collections::HashMap::new();
        let tracking_since = {
            let mut client = self.lock();
            for row in client.query(
                "SELECT day::text, registrations, memories, sessions FROM ops_daily_stats
                 WHERE day >= $1::text::date AND day <= $2::text::date ORDER BY day",
                &[&start.to_string(), &today.to_string()],
            )? {
                counts.insert(row.get(0), [row.get(1), row.get(2), row.get(3)]);
            }
            let timestamp: String = client.query_one(
                "SELECT v FROM schema_meta WHERE k='ops_stats_started_at'", &[],
            )?.get(0);
            (chrono::DateTime::parse_from_rfc3339(&timestamp)? + chrono::Duration::hours(8)).date_naive()
        };
        let mut series = Vec::with_capacity(days as usize);
        let mut date = start;
        while date <= today {
            let key = date.format("%Y-%m-%d").to_string();
            let c = counts.get(&key).copied().unwrap_or([0, 0, 0]);
            series.push(serde_json::json!({
                "date": key,
                "registrations": c[0],
                "memories": if date < tracking_since { None } else { Some(c[1]) },
                "sessions": c[2],
            }));
            date += chrono::Duration::days(1);
        }
        Ok(serde_json::json!({
            "days": days, "timezone": "Asia/Shanghai", "memory_tracking_since": tracking_since.to_string(),
            "historical_baseline": "retained_registrations_and_sessions", "series": series,
        }))
    }

    pub(crate) fn list_users_filtered(&self, q: &str, page: u32, limit: u32, status: &str) -> Result<(Vec<serde_json::Value>, i64)> {
        let limit = limit.clamp(1, 100) as i64;
        let page = page.max(1) as i64;
        let offset = (page - 1) * limit;
        let total: i64 = self
            .lock()
            .query_one(
                r#"SELECT COUNT(*) FROM users u
                   WHERE ($1 = '' OR position(lower($1) in lower(u."user")) > 0
                      OR position(lower($1) in lower(u.email)) > 0)
                     AND ($2 = 'all' OR ($2 = 'ok' AND u.deleted = 0 AND u.disabled = 0)
                          OR ($2 = 'banned' AND u.deleted = 0 AND u.disabled <> 0)
                          OR ($2 = 'deleted' AND u.deleted <> 0))"#,
                &[&q, &status],
            )?
            .get(0);
        let rows = self.lock().query(
            r#"SELECT u."user", u.created_at, u.token, u.disabled, u.email, u.deleted,
                      COUNT(CASE WHEN b.deleted = 0 THEN 1 END) AS active,
                      (SELECT COUNT(*) FROM sessions s WHERE s."user" = u."user") AS sessions
               FROM users u LEFT JOIN blobs b ON b."user" = u."user"
               WHERE ($1 = '' OR position(lower($1) in lower(u."user")) > 0
                  OR position(lower($1) in lower(u.email)) > 0)
                 AND ($4 = 'all' OR ($4 = 'ok' AND u.deleted = 0 AND u.disabled = 0)
                      OR ($4 = 'banned' AND u.deleted = 0 AND u.disabled <> 0)
                      OR ($4 = 'deleted' AND u.deleted <> 0))
               GROUP BY u."user", u.created_at, u.token, u.disabled, u.email, u.deleted
               ORDER BY u.created_at ASC, u."user" ASC LIMIT $2 OFFSET $3"#,
            &[&q, &limit, &offset, &status],
        )?;
        let users = rows
            .iter()
            .map(|row| {
                let disabled: i32 = row.get(3);
                let deleted: i32 = row.get(5);
                serde_json::json!({
                    "user": row.get::<_, String>(0),
                    "created_at": row.get::<_, String>(1),
                    "token_masked": mask_token(&row.get::<_, String>(2)),
                    "disabled": disabled != 0,
                    "email": row.get::<_, String>(4),
                    "deleted": deleted != 0,
                    "active": row.get::<_, i64>(6),
                    "session_count": row.get::<_, i64>(7),
                })
            })
            .collect();
        Ok((users, total))
    }

    pub(crate) fn list_user_sessions(&self, user: &str) -> Result<Option<Vec<serde_json::Value>>> {
        if !self.exists_user(user) {
            return Ok(None);
        }
        let rows = self.lock().query(
            r#"SELECT id,device_name,created_at FROM sessions WHERE "user"=$1 ORDER BY created_at,id"#,
            &[&user],
        )?;
        Ok(Some(
            rows.iter()
                .map(|row| {
                    serde_json::json!({
                        "id": row.get::<_, String>(0),
                        "device_name": row.get::<_, String>(1),
                        "created_at": row.get::<_, String>(2),
                    })
                })
                .collect(),
        ))
    }

    pub(crate) fn set_disabled(&self, user: &str, disabled: bool) -> Result<bool> {
        let v = disabled as i32;
        Ok(self.lock().execute(
            r#"UPDATE users SET disabled=$2 WHERE "user"=$1"#,
            &[&user, &v],
        )? > 0)
    }

    pub(crate) fn set_deleted(&self, user: &str, deleted: bool) -> Result<bool> {
        let v = deleted as i32;
        let n = self.lock().execute(
            r#"UPDATE users SET deleted=$2 WHERE "user"=$1"#,
            &[&user, &v],
        )?;
        if n == 0 {
            return Ok(false);
        }
        if deleted {
            let _ = self.rotate_token(user)?;
        }
        Ok(true)
    }

    pub(crate) fn kick_user(&self, user: &str) -> Result<bool> {
        Ok(self.rotate_token(user)?.is_some())
    }

    pub(crate) fn super_admin_from_token(&self, token: &str) -> Result<Option<(String, String)>> {
        Ok(self.lock()
            .query_opt(
                r#"SELECT "user", role FROM super_admins WHERE token=$1 AND disabled=0"#,
                &[&token],
            )?
            .map(|row| (row.get(0), row.get(1))))
    }

    pub(crate) fn super_admin_issue_token(&self, user: &str) -> Result<String> {
        let token = random_hex(32);
        self.lock().execute(
            r#"UPDATE super_admins SET token=$2 WHERE "user"=$1"#,
            &[&user, &token],
        )?;
        Ok(token)
    }

    pub(crate) fn super_admin_login(&self, user: &str, pass_hash: &str) -> Result<Option<serde_json::Value>> {
        let row = self.lock().query_opt(
            r#"SELECT pass_hash, disabled, totp_secret FROM super_admins WHERE "user"=$1"#,
            &[&user],
        )?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored: String = row.get(0);
        let disabled: i32 = row.get(1);
        let totp: String = row.get(2);
        if disabled != 0 {
            return Err(anyhow!("disabled"));
        }
        if stored != pass_hash {
            return Ok(None);
        }
        if !totp.is_empty() {
            let ticket = self.issue_ticket(user, "admin_totp")?;
            return Ok(Some(serde_json::json!({"totp_required": true, "ticket": ticket, "user": user})));
        }
        let token = self.super_admin_issue_token(user)?;
        Ok(Some(serde_json::json!({"token": token, "user": user})))
    }

    pub(crate) fn super_admin_set_password(&self, user: &str, pass_hash: &str, salt: &str) -> Result<bool> {
        Ok(self.lock().execute(
            r#"UPDATE super_admins SET pass_hash=$2, salt=$3 WHERE "user"=$1"#,
            &[&user, &pass_hash, &salt],
        )? > 0)
    }

    pub(crate) fn audit(&self, actor: &str, action: &str, target: &str, detail: &str) -> Result<()> {
        let at = now_rfc();
        self.lock().execute(
            "INSERT INTO audit_log (at, actor, action, target, detail) VALUES ($1,$2,$3,$4,$5)",
            &[&at, &actor, &action, &target, &detail],
        )?;
        Ok(())
    }

    pub(crate) fn list_audit(&self, q: &str, page: u32, limit: u32) -> Result<(Vec<serde_json::Value>, i64)> {
        let limit = limit.clamp(1, 100) as i64;
        let page = page.max(1) as i64;
        let offset = (page - 1) * limit;
        let total: i64 = self
            .lock()
            .query_one(
                "SELECT COUNT(*) FROM audit_log WHERE $1 = '' OR position(lower($1) in lower(action)) > 0 OR position(lower($1) in lower(actor)) > 0",
                &[&q],
            )?
            .get(0);
        let rows = self.lock().query(
            "SELECT id, at, actor, action, target, detail FROM audit_log
             WHERE $1 = '' OR position(lower($1) in lower(action)) > 0 OR position(lower($1) in lower(actor)) > 0
             ORDER BY id DESC LIMIT $2 OFFSET $3",
            &[&q, &limit, &offset],
        )?;
        let items = rows
            .iter()
            .map(|row| {
                let id: i64 = row.get(0);
                serde_json::json!({
                    "id": id,
                    "at": row.get::<_, String>(1),
                    "actor": row.get::<_, String>(2),
                    "action": row.get::<_, String>(3),
                    "target": row.get::<_, String>(4),
                    "detail": row.get::<_, String>(5),
                })
            })
            .collect();
        Ok((items, total))
    }

    #[cfg(test)]
    pub(crate) fn mail_outbox(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        let at = now_rfc();
        self.lock().execute(
            "INSERT INTO mail_outbox (at, to_addr, subject, body) VALUES ($1,$2,$3,$4)",
            &[&at, &to, &subject, &body],
        )?;
        Ok(())
    }

    pub(crate) fn list_outbox(&self, page: u32, limit: u32) -> Result<(Vec<serde_json::Value>, i64)> {
        let limit = limit.max(1) as i64;
        let page = page.max(1) as i64;
        let offset = (page - 1) * limit;
        let total: i64 = self.lock().query_one("SELECT COUNT(*) FROM mail_outbox", &[])?.get(0);
        let rows = self.lock().query(
            "SELECT id, at, to_addr, subject, status, attempts, last_error FROM mail_outbox ORDER BY id DESC LIMIT $1 OFFSET $2",
            &[&limit, &offset],
        )?;
        let items = rows
            .iter()
            .map(|row| {
                let id: i64 = row.get(0);
                serde_json::json!({
                    "id": id,
                    "at": row.get::<_, String>(1),
                    "to": row.get::<_, String>(2),
                    "subject": row.get::<_, String>(3),
                    "status": row.get::<_, String>(4),
                    "attempts": row.get::<_, i32>(5),
                    "last_error": row.get::<_, String>(6),
                })
            })
            .collect();
        Ok((items, total))
    }

    pub(crate) fn issue_ticket(&self, audience: &str, purpose: &str) -> Result<String> {
        let id = random_hex(16);
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.lock().execute(
            "INSERT INTO verify_codes (id, audience, purpose, code_hash, email, expires_at) VALUES ($1,$2,$3,'','',$4)",
            &[&id, &audience, &purpose, &exp],
        )?;
        Ok(id)
    }

    pub(crate) fn take_ticket(&self, id: &str, purpose: &str) -> Result<Option<String>> {
        let row = self.lock().query_opt(
            "SELECT audience, expires_at FROM verify_codes WHERE id=$1 AND purpose=$2",
            &[&id, &purpose],
        )?;
        let Some(row) = row else {
            return Ok(None);
        };
        let audience: String = row.get(0);
        let exp: String = row.get(1);
        self.lock().execute("DELETE FROM verify_codes WHERE id=$1", &[&id])?;
        if is_expired(&exp) {
            return Ok(None);
        }
        Ok(Some(audience))
    }

    #[cfg(test)]
    pub(crate) fn issue_email_code(&self, audience: &str, email: &str, purpose: &str) -> Result<String> {
        self.enqueue_email_code(audience, email, purpose, false)?.context("email code was not queued")
    }

    pub(crate) fn queue_email_code(&self, audience: &str, email: &str, purpose: &str) -> Result<bool> {
        Ok(self.enqueue_email_code(audience, email, purpose, true)?.is_some())
    }

    fn enqueue_email_code(&self, audience: &str, email: &str, purpose: &str, throttle: bool) -> Result<Option<String>> {
        let subject = match purpose {
            "verify_email" => "Respire email verification",
            "reset_password" => "Respire password reset",
            _ => anyhow::bail!("unsupported email verification purpose"),
        };
        let _: lettre::message::Mailbox = email.parse().context("invalid email address")?;
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        tx.query_one("SELECT pg_advisory_xact_lock(hashtextextended($1, 1869440359))", &[&audience])?;
        if throttle && purpose == "reset_password" && tx.query_opt(
            r#"SELECT 1 FROM users WHERE "user"=$1 AND email=$2 AND email_verified=TRUE AND disabled=0 AND deleted=0"#,
            &[&audience, &email],
        )?.is_none() {
            return Ok(None);
        }
        if throttle && tx.query_opt("SELECT 1 FROM mail_outbox WHERE to_addr=$1 AND subject=$2
            AND at::timestamptz > NOW()-INTERVAL '60 seconds' LIMIT 1", &[&email, &subject])?.is_some() {
            return Ok(None);
        }
        let id = random_hex(16);
        let n = (uuid::Uuid::new_v4().as_u128() % 1_000_000) as u32;
        let code = format!("{n:06}");
        let hash = format!("{:x}", Sha256::digest(code.as_bytes()));
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        tx.execute("DELETE FROM verify_codes WHERE audience=$1 AND purpose=$2", &[&audience, &purpose])?;
        tx.execute(
            "INSERT INTO verify_codes (id, audience, purpose, code_hash, email, expires_at) VALUES ($1,$2,$3,$4,$5,$6)",
            &[&id, &audience, &purpose, &hash, &email, &exp],
        )?;
        let body = format!("Your Respire verification code is {code}.\n\nIt expires in 10 minutes. If you did not request this email, you can ignore it.");
        tx.execute("INSERT INTO mail_outbox (at, to_addr, subject, body, status, expires_at, code_id)
            VALUES ($1,$2,$3,$4,'pending',$5::text::timestamptz,$6)", &[&now_rfc(), &email, &subject, &body, &exp, &id])?;
        tx.commit()?;
        Ok(Some(code))
    }

    #[cfg(test)]
    pub(crate) fn check_email_code(&self, audience: &str, purpose: &str, code: &str) -> Result<bool> {
        let hash = format!("{:x}", Sha256::digest(code.trim().as_bytes()));
        let row = self.lock().query_opt(
            "SELECT id, expires_at FROM verify_codes WHERE audience=$1 AND purpose=$2 AND code_hash=$3
             ORDER BY expires_at DESC LIMIT 1",
            &[&audience, &purpose, &hash],
        )?;
        let Some(row) = row else {
            return Ok(false);
        };
        let id: String = row.get(0);
        let exp: String = row.get(1);
        self.lock().execute("DELETE FROM verify_codes WHERE id=$1", &[&id])?;
        if is_expired(&exp) {
            return Ok(false);
        }
        Ok(true)
    }

    pub(crate) fn list_admins(&self) -> Result<Vec<serde_json::Value>> {
        let rows = self.lock().query(
            r#"SELECT "user", role, disabled, email, created_at, totp_secret FROM super_admins ORDER BY created_at"#,
            &[],
        )?;
        Ok(rows
            .iter()
            .map(|row| {
                let totp: String = row.get(5);
                let disabled: i32 = row.get(2);
                serde_json::json!({
                    "user": row.get::<_, String>(0),
                    "role": row.get::<_, String>(1),
                    "disabled": disabled != 0,
                    "email": row.get::<_, String>(3),
                    "created_at": row.get::<_, String>(4),
                    "totp": !totp.is_empty(),
                })
            })
            .collect())
    }

    pub(crate) fn create_admin(
        &self,
        user: &str,
        pass_hash: &str,
        salt: &str,
        role: &str,
        email: &str,
    ) -> Result<Option<()>> {
        if self
            .lock()
            .query_opt(r#"SELECT 1 FROM super_admins WHERE "user"=$1"#, &[&user])?
            .is_some()
        {
            return Ok(None);
        }
        let token = random_hex(32);
        let now = now_rfc();
        self.lock().execute(
            r#"INSERT INTO super_admins ("user", pass_hash, salt, token, created_at, role, disabled, totp_secret, email)
               VALUES ($1,$2,$3,$4,$5,$6,0,'',$7)"#,
            &[&user, &pass_hash, &salt, &token, &now, &role, &email],
        )?;
        Ok(Some(()))
    }

    pub(crate) fn owner_count(&self) -> Result<i64> {
        Ok(self
            .lock()
            .query_one(
                "SELECT COUNT(*) FROM super_admins WHERE role='owner' AND disabled=0",
                &[],
            )?
            .get(0))
    }

    pub(crate) fn admin_update_admin(
        &self,
        user: &str,
        pass_hash: Option<&str>,
        salt: Option<&str>,
        disabled: Option<bool>,
        email: Option<&str>,
    ) -> Result<bool> {
        if self
            .lock()
            .query_opt(r#"SELECT 1 FROM super_admins WHERE "user"=$1"#, &[&user])?
            .is_none()
        {
            return Ok(false);
        }
        if let (Some(hash), Some(s)) = (pass_hash, salt) {
            if !hash.is_empty() && !s.is_empty() {
                self.super_admin_set_password(user, hash, s)?;
            }
        }
        if let Some(flag) = disabled {
            let v = flag as i32;
            self.lock().execute(
                r#"UPDATE super_admins SET disabled=$2 WHERE "user"=$1"#,
                &[&user, &v],
            )?;
        }
        if let Some(email) = email {
            let e = email.trim();
            self.lock().execute(
                r#"UPDATE super_admins SET email=$2 WHERE "user"=$1"#,
                &[&user, &e],
            )?;
        }
        Ok(true)
    }

    pub(crate) fn delete_admin(&self, user: &str) -> Result<bool> {
        let role: String = match self.lock().query_opt(
            r#"SELECT role FROM super_admins WHERE "user"=$1"#,
            &[&user],
        )? {
            Some(r) => r.get(0),
            None => return Ok(false),
        };
        if role == "owner" && self.owner_count()? <= 1 {
            return Ok(false);
        }
        Ok(self.lock().execute(r#"DELETE FROM super_admins WHERE "user"=$1"#, &[&user])? > 0)
    }

    pub(crate) fn admin_role(&self, user: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_opt(r#"SELECT role FROM super_admins WHERE "user"=$1"#, &[&user])?
            .map(|row| row.get(0)))
    }

    pub(crate) fn user_created_at(&self, user: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_opt(r#"SELECT created_at FROM users WHERE "user"=$1"#, &[&user])?
            .map(|row| row.get(0)))
    }

    #[cfg(test)]
    pub(crate) fn user_email(&self, user: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_opt(r#"SELECT email FROM users WHERE "user"=$1"#, &[&user])?
            .map(|row| row.get(0)))
    }

    pub(crate) fn confirm_email(&self, user: &str, code: &str) -> Result<bool> {
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        let row = tx.query_opt(
            "SELECT id, email, expires_at, code_hash FROM verify_codes WHERE audience=$1 AND purpose='verify_email'
             ORDER BY expires_at DESC LIMIT 1 FOR UPDATE",
            &[&user],
        )?;
        let Some(row) = row else {
            return Ok(false);
        };
        let id: String = row.get(0);
        let email: String = row.get(1);
        let exp: String = row.get(2);
        let stored: String = row.get(3);
        let hash = format!("{:x}", Sha256::digest(code.trim().as_bytes()));
        if stored != hash {
            tx.execute("UPDATE verify_codes SET failed_attempts=failed_attempts+1 WHERE id=$1", &[&id])?;
            tx.execute("DELETE FROM verify_codes WHERE id=$1 AND failed_attempts >= 5", &[&id])?;
            tx.commit()?;
            return Ok(false);
        }
        if is_expired(&exp) {
            return Ok(false);
        }
        tx.execute("DELETE FROM verify_codes WHERE id=$1", &[&id])?;
        tx.execute(r#"UPDATE users SET email=$2, email_verified=TRUE WHERE "user"=$1"#, &[&user, &email])?;
        tx.commit()?;
        drop(client);
        self.audit(user, "email_verify", user, &email)?;
        Ok(true)
    }

    pub(crate) fn recovery_email(&self, user: &str) -> Result<Option<String>> {
        Ok(self.lock().query_opt(
            r#"SELECT email FROM users WHERE "user"=$1 AND email_verified=TRUE AND email<>'' AND disabled=0 AND deleted=0"#,
            &[&user],
        )?.map(|row| row.get(0)))
    }

    pub(crate) fn reset_password(&self, user: &str, code: &str, pass_hash: &str, salt: &str) -> Result<bool> {
        if pass_hash.trim().is_empty() || salt.trim().is_empty() {
            return Ok(false);
        }
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        tx.query_one("SELECT pg_advisory_xact_lock(hashtextextended($1, 1869440359))", &[&user])?;
        let row = tx.query_opt(
            r#"SELECT v.id, v.code_hash, v.expires_at FROM verify_codes v JOIN users u ON u."user"=v.audience
               WHERE v.audience=$1 AND v.purpose='reset_password' AND v.email=u.email
               AND u.email_verified=TRUE AND u.disabled=0 AND u.deleted=0
               ORDER BY v.expires_at DESC LIMIT 1 FOR UPDATE OF v,u"#,
            &[&user],
        )?;
        let Some(row) = row else { return Ok(false); };
        let id: String = row.get(0);
        let stored: String = row.get(1);
        let expiry: String = row.get(2);
        if is_expired(&expiry) {
            tx.execute("DELETE FROM verify_codes WHERE id=$1", &[&id])?;
            tx.commit()?;
            return Ok(false);
        }
        let hash = format!("{:x}", Sha256::digest(code.trim().as_bytes()));
        if stored != hash {
            tx.execute("UPDATE verify_codes SET failed_attempts=failed_attempts+1 WHERE id=$1", &[&id])?;
            tx.execute("DELETE FROM verify_codes WHERE id=$1 AND failed_attempts>=5", &[&id])?;
            tx.commit()?;
            return Ok(false);
        }
        let token = random_hex(32);
        tx.execute(r#"UPDATE users SET pass_hash=$2, salt=$3, token=$4 WHERE "user"=$1"#, &[&user, &pass_hash, &salt, &token])?;
        tx.execute(r#"DELETE FROM sessions WHERE "user"=$1"#, &[&user])?;
        tx.execute("DELETE FROM verify_codes WHERE audience=$1 AND purpose IN ('reset_password','user_totp')", &[&user])?;
        tx.execute("INSERT INTO audit_log (at, actor, action, target, detail) VALUES ($1,$2,'reset_password',$2,'')", &[&now_rfc(), &user])?;
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn complete_user_totp(
        &self,
        ticket: &str,
        code: &str,
        device: Option<&str>,
    ) -> Result<Option<serde_json::Value>> {
        let Some(user) = self.verify_totp_ticket(ticket, code, "users", "user_totp")? else {
            return Ok(None);
        };
        let token: String = self
            .lock()
            .query_one(r#"SELECT token FROM users WHERE "user"=$1"#, &[&user])?
            .get(0);
        Ok(Some(self.session_response(&user, token, device)?))
    }

    pub(crate) fn complete_admin_totp(&self, ticket: &str, code: &str) -> Result<Option<serde_json::Value>> {
        let Some(user) = self.verify_totp_ticket(ticket, code, "super_admins", "admin_totp")? else {
            return Ok(None);
        };
        let token = self.super_admin_issue_token(&user)?;
        self.audit("admin", "login_totp", &user, "")?;
        Ok(Some(serde_json::json!({"token": token, "user": user})))
    }

    fn verify_totp_ticket(&self, ticket: &str, code: &str, table: &str, purpose: &str) -> Result<Option<String>> {
        if table != "users" && table != "super_admins" { anyhow::bail!("bad totp table"); }
        let deleted = if table == "users" { " AND u.deleted=0" } else { "" };
        let sql = format!(r#"SELECT v.audience,v.expires_at,u.totp_secret FROM verify_codes v JOIN {table} u ON u."user"=v.audience WHERE v.id=$1 AND v.purpose=$2 AND u.disabled=0{deleted} FOR UPDATE OF v,u"#);
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        let Some(row) = tx.query_opt(&sql, &[&ticket.trim(), &purpose])? else { return Ok(None); };
        let user: String = row.get(0);
        let expiry: String = row.get(1);
        let secret: String = row.get(2);
        if is_expired(&expiry) {
            tx.execute("DELETE FROM verify_codes WHERE id=$1", &[&ticket.trim()])?;
            tx.commit()?;
            return Ok(None);
        }
        if !crate::totp::verify(&secret, code, chrono::Utc::now().timestamp()) {
            tx.execute("UPDATE verify_codes SET failed_attempts=failed_attempts+1 WHERE id=$1", &[&ticket.trim()])?;
            tx.execute("DELETE FROM verify_codes WHERE id=$1 AND failed_attempts>=5", &[&ticket.trim()])?;
            tx.commit()?;
            return Ok(None);
        }
        tx.execute("DELETE FROM verify_codes WHERE id=$1", &[&ticket.trim()])?;
        tx.commit()?;
        Ok(Some(user))
    }

    pub(crate) fn totp_begin(&self, user: &str, purpose: &str) -> Result<serde_json::Value> {
        let secret = crate::totp::new_secret();
        let id = random_hex(16);
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        self.lock().execute(
            "INSERT INTO verify_codes (id, audience, purpose, code_hash, email, expires_at) VALUES ($1,$2,$3,$4,'',$5)",
            &[&id, &user, &purpose, &secret, &exp],
        )?;
        Ok(serde_json::json!({
            "secret": secret,
            "otpauth": crate::totp::otpauth(user, &secret),
        }))
    }

    pub(crate) fn totp_confirm(&self, table: &str, user: &str, purpose: &str, code: &str) -> Result<bool> {
        if table != "users" && table != "super_admins" {
            anyhow::bail!("bad totp table");
        }
        let mut client = self.lock();
        let mut transaction = client.transaction()?;
        let row = transaction.query_opt(
            "SELECT code_hash, expires_at FROM verify_codes WHERE audience=$1 AND purpose=$2
             ORDER BY expires_at DESC LIMIT 1 FOR UPDATE",
            &[&user, &purpose],
        )?;
        let Some(row) = row else {
            return Ok(false);
        };
        let secret: String = row.get(0);
        let exp: String = row.get(1);
        if is_expired(&exp) {
            return Ok(false);
        }
        if !crate::totp::verify(&secret, code, chrono::Utc::now().timestamp()) {
            return Ok(false);
        }
        let sql = format!(r#"UPDATE {table} SET totp_secret=$2 WHERE "user"=$1"#);
        transaction.execute(&sql, &[&user, &secret])?;
        transaction.execute("DELETE FROM verify_codes WHERE audience=$1 AND purpose=$2", &[&user, &purpose])?;
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn totp_disable(&self, table: &str, user: &str, code: &str) -> Result<bool> {
        if table != "users" && table != "super_admins" {
            anyhow::bail!("bad totp table");
        }
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        let sql_sel = format!(r#"SELECT totp_secret FROM {table} WHERE "user"=$1 FOR UPDATE"#);
        let secret: String = tx.query_one(&sql_sel, &[&user])?.get(0);
        if secret.is_empty() {
            return Ok(true);
        }
        if !crate::totp::verify(&secret, code, chrono::Utc::now().timestamp()) {
            return Ok(false);
        }
        let sql = format!(r#"UPDATE {table} SET totp_secret='' WHERE "user"=$1"#);
        tx.execute(&sql, &[&user])?;
        let purpose = if table == "users" { "user_totp_setup" } else { "admin_totp_setup" };
        tx.execute("DELETE FROM verify_codes WHERE audience=$1 AND purpose=$2", &[&user, &purpose])?;
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn admin_has_totp(&self, user: &str) -> bool {
        self.lock()
            .query_opt(
                r#"SELECT totp_secret FROM super_admins WHERE "user"=$1"#,
                &[&user],
            )
            .ok()
            .flatten()
            .map(|row| {
                let s: String = row.get(0);
                !s.is_empty()
            })
            .unwrap_or(false)
    }

    pub(crate) fn admin_email(&self, user: &str) -> String {
        self.lock()
            .query_opt(r#"SELECT email FROM super_admins WHERE "user"=$1"#, &[&user])
            .ok()
            .flatten()
            .map(|row| row.get(0))
            .unwrap_or_default()
    }

    pub(crate) fn users_csv(&self, q: &str) -> Result<String> {
        let (users, _) = self.list_users(q, 1, 100)?;
        let mut out = String::from("user,email,disabled,deleted,session_count,active,created_at,token_masked\n");
        for u in users {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                u["user"].as_str().unwrap_or(""),
                u["email"].as_str().unwrap_or(""),
                u["disabled"].as_bool().unwrap_or(false),
                u["deleted"].as_bool().unwrap_or(false),
                u["session_count"].as_i64().unwrap_or(0),
                u["active"].as_i64().unwrap_or(0),
                u["created_at"].as_str().unwrap_or(""),
                u["token_masked"].as_str().unwrap_or(""),
            ));
        }
        Ok(out)
    }

    pub(crate) fn admin_create_user(&self, user: &str, pass_hash: &str, salt: &str) -> Result<Option<String>> {
        self.register(user, pass_hash, salt)
    }

    pub(crate) fn admin_update_user(
        &self,
        user: &str,
        pass_hash: Option<&str>,
        salt: Option<&str>,
        disabled: Option<bool>,
        email: Option<&str>,
    ) -> Result<bool> {
        if !self.exists_user(user) {
            return Ok(false);
        }
        if let (Some(hash), Some(s)) = (pass_hash, salt) {
            if !hash.is_empty() && !s.is_empty() {
                self.lock().execute(
                    r#"UPDATE users SET pass_hash=$2, salt=$3 WHERE "user"=$1"#,
                    &[&user, &hash, &s],
                )?;
            }
        }
        if let Some(flag) = disabled {
            self.set_disabled(user, flag)?;
        }
        if let Some(email) = email {
            let e = email.trim();
            self.lock().execute(r#"UPDATE users SET email=$2, email_verified=(email_verified AND email=$2) WHERE "user"=$1"#, &[&user, &e])?;
        }
        Ok(true)
    }

    pub(crate) fn put_vault(
        &self,
        user: &str,
        kdf_salt: &str,
        wrapped_urk: &str,
        urk_nonce: &str,
        version: i64,
    ) -> Result<()> {
        if kdf_salt.len() < 16 || wrapped_urk.is_empty() || urk_nonce.is_empty() {
            anyhow::bail!("invalid vault");
        }
        if version < 2 || version > 4 {
            anyhow::bail!("unsupported vault version");
        }
        let version = i32::try_from(version).map_err(|_| anyhow!("unsupported vault version"))?;
        let now = now_rfc();
        self.lock().execute(
            r#"INSERT INTO vault ("user", kdf_salt, wrapped_urk, urk_nonce, version, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6)
               ON CONFLICT ("user") DO UPDATE SET
                kdf_salt=excluded.kdf_salt, wrapped_urk=excluded.wrapped_urk,
                urk_nonce=excluded.urk_nonce, version=excluded.version, updated_at=excluded.updated_at"#,
            &[&user, &kdf_salt, &wrapped_urk, &urk_nonce, &version, &now],
        )?;
        Ok(())
    }

    pub(crate) fn get_vault(&self, user: &str) -> Result<Option<serde_json::Value>> {
        Ok(self
            .lock()
            .query_opt(
                r#"SELECT kdf_salt, wrapped_urk, urk_nonce, version FROM vault WHERE "user"=$1"#,
                &[&user],
            )?
            .map(|row| {
                let version: i32 = row.get(3);
                serde_json::json!({
                    "kdf_salt": row.get::<_, String>(0),
                    "wrapped_urk": row.get::<_, String>(1),
                    "urk_nonce": row.get::<_, String>(2),
                    "version": version as i64,
                })
            }))
    }

    pub(crate) fn user_set_password(&self, user: &str, pass_hash: &str, salt: &str) -> Result<bool> {
        Ok(self.lock().execute(
            r#"UPDATE users SET pass_hash=$2, salt=$3 WHERE "user"=$1 AND disabled=0 AND deleted=0"#,
            &[&user, &pass_hash, &salt],
        )? > 0)
    }

    pub(crate) fn user_keys(&self, user: &str, token: &str) -> Result<serde_json::Value> {
        let row = self.lock().query_one(
            r#"SELECT salt, email, totp_secret, email_verified FROM users WHERE "user"=$1"#,
            &[&user],
        )?;
        let salt: String = row.get(0);
        let email: String = row.get(1);
        let totp: String = row.get(2);
        let sessions = self.list_sessions(user, token)?;
        Ok(serde_json::json!({
            "user": user,
            "auth_salt": salt,
            "token_masked": mask_token(token),
            "sessions": sessions,
            "email": email,
            "email_verified": row.get::<_, bool>(3),
            "totp": !totp.is_empty(),
            "note": "The server stores login hashes, email, and API tokens only. Super password / Secret Key / URK stay on the client; the cloud cannot recover them. If lost, re-wrap keys on the client."
        }))
    }

    pub(crate) fn rotate_token(&self, user: &str) -> Result<Option<String>> {
        if !self.exists_user(user) {
            return Ok(None);
        }
        let token = random_hex(32);
        let mut c = self.lock();
        let mut tx = c.transaction()?;
        tx.execute(r#"UPDATE users SET token=$2 WHERE "user"=$1"#, &[&user, &token])?;
        tx.execute(r#"DELETE FROM sessions WHERE "user"=$1"#, &[&user])?;
        tx.commit()?;
        Ok(Some(token))
    }

    /// Hard delete: sessions, ciphertext, vault, codes, and the account row; username is freed immediately.
    pub(crate) fn revoke_user(&self, user: &str) -> Result<(bool, u64)> {
        let mut c = self.lock();
        let mut tx = c.transaction()?;
        tx.execute(r#"DELETE FROM sessions WHERE "user"=$1"#, &[&user])?;
        let blobs = tx.execute(r#"DELETE FROM blobs WHERE "user"=$1"#, &[&user])?;
        tx.execute(r#"DELETE FROM vault WHERE "user"=$1"#, &[&user])?;
        tx.execute(r#"DELETE FROM verify_codes WHERE audience=$1"#, &[&user])?;
        let account = tx.execute(r#"DELETE FROM users WHERE "user"=$1"#, &[&user])? > 0;
        tx.commit()?;
        Ok((account, blobs))
    }

    /// Batch upsert: per-item LWW in one transaction (newer stored updated_at drops the inbound).
    /// The batch commits atomically — one fsync per batch instead of N autocommit transactions.
    /// Returns a replaced flag per item (false = stored row was newer, inbound dropped).
    pub(crate) fn put_batch(&self, user: &str, items: &[BlobWrite<'_>]) -> Result<Vec<bool>> {
        self.sync_legacy(user, items)
    }

    pub(crate) fn put(&self, user: &str, b: &BlobWrite<'_>) -> Result<bool> {
        // Single-item batch of length 1 — LWW / rev / upsert SQL lives here; put and /push/batch share it
        Ok(self.put_batch(user, std::slice::from_ref(b))?.remove(0))
    }

    pub(crate) fn pull(
        &self,
        user: &str,
        since: Option<u64>,
    ) -> Result<(Vec<StoredMemory>, u64, i64, i64)> {
        let row = self.lock().query_one(
            r#"SELECT COUNT(*), COALESCE(SUM(CASE WHEN deleted = 0 THEN 1 ELSE 0 END),0) FROM blobs WHERE "user"=$1"#,
            &[&user],
        )?;
        let total: i64 = row.get(0);
        let alive: i64 = row.get(1);
        let cursor = self.arrival_seq()?;
        let rows = match since {
            None => self.lock().query(
                r#"SELECT id, ciphertext, nonce, embedding_enc, updated_at, deleted
                   FROM blobs WHERE "user"=$1 ORDER BY updated_at ASC"#,
                &[&user],
            )?,
            Some(n) => {
                let n = n as i64;
                self.lock().query(
                    r#"SELECT id, ciphertext, nonce, embedding_enc, updated_at, deleted
                       FROM blobs WHERE "user"=$1 AND rev > $2 ORDER BY rev ASC"#,
                    &[&user, &n],
                )?
            }
        };
        let blobs = rows.iter().map(|row| row_blob(user, row)).collect();
        Ok((blobs, cursor, total, alive))
    }

    pub(crate) fn max_updated_at(&self, user: &str) -> Result<Option<String>> {
        let v: Option<String> = self
            .lock()
            .query_one(r#"SELECT MAX(updated_at) FROM blobs WHERE "user"=$1"#, &[&user])?
            .get(0);
        Ok(v.filter(|s| !s.is_empty()))
    }

    pub(crate) fn forget(&self, user: &str, id: &str) -> Result<bool> {
        let previous = self.lock()
            .query_opt(
                r#"SELECT id,ciphertext,nonce,embedding_enc,updated_at,deleted FROM blobs WHERE "user"=$1 AND id=$2 AND deleted=0"#,
                &[&user, &id],
            )?.map(|row| row_blob(user,&row));
        let Some(previous) = previous else {
            return Ok(false);
        };
        let now = respire::transport::timestamp_after(Some(&previous.updated_at))?;
        self.put(user,&BlobWrite {id,ciphertext:&previous.ciphertext,nonce:&previous.nonce,
            embedding_enc:&previous.embedding_enc,updated_at:&now,deleted:true})
    }

    pub(crate) fn count(&self, user: &str) -> Result<i64> {
        Ok(self
            .lock()
            .query_one(
                r#"SELECT COUNT(*) FROM blobs WHERE "user"=$1 AND deleted=0"#,
                &[&user],
            )?
            .get(0))
    }
}

fn row_blob(user: &str, row: &Row) -> StoredMemory {
    let deleted: i32 = row.get(5);
    StoredMemory {
        id: row.get(0),
        user: user.to_owned(),
        ciphertext: row.get(1),
        nonce: row.get(2),
        embedding_enc: row.get(3),
        updated_at: row.get(4),
        deleted: deleted != 0,
        local_kind: String::new(),
        local_tags: String::new(),
        local_title: String::new(),
        local_project: String::new(),
        local_computer: String::new(),
        local_embedding: None,
        local_parent_id: String::new(),
        local_created_at: String::new(),
        local_content_head: String::new(),
        local_recall_count: 0,
        local_importance: "normal".to_owned(),
        local_device: String::new(),
        local_modified_by: String::new(),
        local_chunks: Vec::new(),
        local_artifact: Vec::new(),
    }
}

pub(crate) fn connect_url() -> Result<String> {
    std::env::var("DATABASE_URL").map_err(|_| anyhow!("DATABASE_URL is unset (cloud requires Postgres)"))
}

/// Test helper: create a throwaway database on the DATABASE_URL instance.
#[cfg(test)]
pub(crate) fn connect_unique() -> Result<BlobRepo> {
    let base = std::env::var("DATABASE_URL").context("DATABASE_URL required for tests")?;
    let mut admin = Client::connect(&base, NoTls).context("connect postgres")?;
    let name = format!("t{}", uuid::Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .context("create test db")?;
    drop(admin);
    BlobRepo::connect(&db_name_url(&base, &name)).context("connect test db")
}

#[cfg(test)]
mod tests {
    use super::*;
    use respire::memory::crypto::{derive_auth_salt, derive_pass_hash};

    #[test]
    fn terminated_worker_connection_recovers_without_replaying_requests() -> Result<()> {
        let repo=connect_unique()?;
        let token=repo.register("reconnect-user","hash","salt")?
            .ok_or_else(||anyhow!("test account creation failed"))?;
        let pid:i32=repo.lock().query_one("SELECT pg_backend_pid()",&[])?.get(0);
        let mut admin=Client::connect(&repo.url,NoTls)?;
        let terminated:bool=admin.query_one("SELECT pg_terminate_backend($1)",&[&pid])?.get(0);
        assert!(terminated);
        let mut recovered=false;
        for _ in 0..10 {
            let (status,_)=crate::http::handle_full(&repo,"GET","/pull","",Some(&token),None);
            assert!(status==200 || status==503,"database failure must not revoke a valid token: {status}");
            if status==200 {recovered=true;break;}
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(recovered);
        assert_eq!(crate::http::handle_full(&repo,"GET","/ready","",None,None).0,200);
        Ok(())
    }

    #[test]
    fn database_auth_errors_are_unavailable_not_bad_credentials() -> Result<()> {
        let repo=connect_unique()?;
        let token=repo.register("auth-errors","hash","salt")?
            .ok_or_else(||anyhow!("test account creation failed"))?;
        // Rename only tables in this test's unique disposable database.
        repo.lock().batch_execute("ALTER TABLE users RENAME TO unavailable_users;
            ALTER TABLE super_admins RENAME TO unavailable_admins;")?;
        let (registration_status,registration_body)=crate::http::handle_full(&repo,"POST","/register",
            r#"{"user":"unavailable","pass_hash":"hash"}"#,None,None);
        assert_eq!(registration_status,503);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&registration_body)?["error"],"database unavailable");
        assert_eq!(crate::http::handle_full(&repo,"GET","/pull","",Some(&token),None).0,503);
        assert_eq!(crate::http::handle_full(&repo,"GET","/admin/users","",Some("unknown"),None).0,503);
        repo.lock().batch_execute("ALTER TABLE unavailable_users RENAME TO users;
            ALTER TABLE unavailable_admins RENAME TO super_admins;
            UPDATE schema_meta SET v='999' WHERE k='version';")?;
        assert_eq!(crate::http::handle_full(&repo,"GET","/ready","",None,None).0,503);
        assert_eq!(crate::http::handle_full(&repo,"GET","/health","",None,None).0,200);
        Ok(())
    }

    fn repo() -> Result<BlobRepo> {
        connect_unique()
    }

    fn hash(user: &str, pass: &str) -> Result<(String, String)> {
        let salt = derive_auth_salt(user)?;
        let hash = derive_pass_hash(pass, &salt)?;
        Ok((salt, hash))
    }

    fn mem<'a>(id: &'a str, ts: &'a str, ct: &'a str) -> BlobWrite<'a> {
        BlobWrite {
            id,
            ciphertext: ct,
            nonce: "n",
            embedding_enc: "",
            updated_at: ts,
            deleted: false,
        }
    }

    #[test]
    fn schema_apply_twice_is_ok() -> Result<()> {
        let repo = repo()?;
        crate::store::migrations::apply(&mut repo.lock()).context("required")?;
        let again = BlobRepo::connect(&repo.url).context("required")?;
        assert_eq!(again.owner_count().context("required")?, 1);
        Ok(())
    }

    #[test]
    fn register_login_roundtrip() -> Result<()> {
        let repo = repo()?;
        let (salt, h) = hash("alice", "pass-1234")?;
        let token = repo.register("alice", &h, &salt).context("required")?.context("expected Some")?;
        assert!(repo.register("alice", &h, &salt).context("required")?.is_none());
        assert_eq!(repo.login("alice", &h).context("required")?.as_deref(), Some(token.as_str()));
        assert!(repo.login("alice", "nope").context("required")?.is_none());
        assert!(repo.login("missing", &h).context("required")?.is_none());
        Ok(())
    }

    #[test]
    fn login_rejects_disabled_and_deleted() -> Result<()> {
        let repo = repo()?;
        let (salt, h) = hash("bob", "pass-1234")?;
        repo.register("bob", &h, &salt).context("required")?;
        repo.set_disabled("bob", true).context("required")?;
        assert_eq!(repo.login("bob", &h).unwrap_err().to_string(), "disabled");
        repo.set_disabled("bob", false).context("required")?;
        repo.set_deleted("bob", true).context("required")?;
        assert_eq!(repo.login("bob", &h).unwrap_err().to_string(), "deleted");
        assert!(repo.user_from_token("x")?.is_none());
        Ok(())
    }

    #[test]
    fn session_token_authenticates_and_revoke() -> Result<()> {
        let repo = repo()?;
        let (salt, h) = hash("carol", "pass-1234")?;
        repo.register("carol", &h, &salt).context("required")?;
        let (tok, id) = repo.create_session("carol", "laptop").context("required")?;
        assert_eq!(repo.user_from_token(&tok)?.as_deref(), Some("carol"));
        assert!(repo.revoke_session("carol", &id).context("required")?);
        assert!(repo.user_from_token(&tok)?.is_none());
        Ok(())
    }

    #[test]
    fn blob_lww_and_rev_cursor() -> Result<()> {
        let repo = repo()?;
        let (salt, h) = hash("dave", "pass-1234")?;
        repo.register("dave", &h, &salt).context("required")?;
        let a = BlobWrite {
            id: "a",
            ciphertext: "aa",
            nonce: "n1",
            embedding_enc: "",
            updated_at: "2026-09-02T00:00:01.000Z",
            deleted: false,
        };
        assert!(repo.put("dave", &a).context("required")?);
        let older = BlobWrite { updated_at: "2026-09-01T00:00:00.000Z", ..a };
        assert!(!repo.put("dave", &older).context("required")?);
        let newer = BlobWrite { ciphertext: "bb", updated_at: "2026-09-03T00:00:00.000Z", ..a };
        assert!(repo.put("dave", &newer).context("required")?);
        let (all, cur, total, alive) = repo.pull("dave", None).context("required")?;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].ciphertext, "bb");
        assert_eq!(total, 1);
        assert_eq!(alive, 1);
        assert!(cur >= 2);
        let (inc, _, _, _) = repo.pull("dave", Some(1)).context("required")?;
        assert!(!inc.is_empty());
        Ok(())
    }

    #[test]
    fn forget_tombstone_keeps_row_increments_rev() -> Result<()> {
        let repo = repo()?;
        let (salt, h) = hash("erin", "pass-1234")?;
        repo.register("erin", &h, &salt).context("required")?;
        let b = BlobWrite {
            id: "m1",
            ciphertext: "aa",
            nonce: "n",
            embedding_enc: "",
            updated_at: "2026-09-02T00:00:00.000Z",
            deleted: false,
        };
        repo.put("erin", &b).context("required")?;
        assert_eq!(repo.count("erin").context("required")?, 1);
        assert!(repo.forget("erin", "m1").context("required")?);
        assert_eq!(repo.count("erin").context("required")?, 0);
        let (all, _, total, alive) = repo.pull("erin", None).context("required")?;
        assert_eq!(total, 1);
        assert_eq!(alive, 0);
        assert!(all[0].deleted);
        Ok(())
    }

    #[test]
    fn vault_upsert_and_get() -> Result<()> {
        let repo = repo()?;
        let (salt, h) = hash("fay", "pass-1234")?;
        repo.register("fay", &h, &salt).context("required")?;
        assert!(repo.get_vault("fay").context("required")?.is_none());
        repo.put_vault("fay", "aabbccddeeff0011", "wrap", "nonce", 3).context("required")?;
        let v = repo.get_vault("fay").context("required")?.context("expected Some")?;
        assert_eq!(v["version"], 3);
        repo.put_vault("fay", "aabbccddeeff0011", "wrap2", "nonce2", 3).context("required")?;
        let v2 = repo.get_vault("fay").context("required")?.context("expected Some")?;
        assert_eq!(v2["wrapped_urk"], "wrap2");
        Ok(())
    }

    #[test]
    fn kick_invalidates_sessions_keeps_account() -> Result<()> {
        let repo = repo()?;
        let (salt, h) = hash("gina", "pass-1234")?;
        let legacy = repo.register("gina", &h, &salt).context("required")?.context("expected Some")?;
        let (sess, _) = repo.create_session("gina", "phone").context("required")?;
        assert!(repo.kick_user("gina").context("required")?);
        assert!(repo.user_from_token(&sess)?.is_none());
        let new_legacy = repo.login("gina", &h).context("required")?.context("expected Some")?;
        assert_ne!(new_legacy, legacy);
        assert_eq!(repo.user_from_token(&new_legacy)?.as_deref(), Some("gina"));
        Ok(())
    }

    #[test]
    fn list_users_pagination_and_search() -> Result<()> {
        let repo = repo()?;
        for name in ["ann", "bob", "amy"] {
            let (s, h) = hash(name, "pass-1234")?;
            repo.register(name, &h, &s).context("required")?;
        }
        let (page1, total) = repo.list_users("", 1, 2).context("required")?;
        assert_eq!(total, 3);
        assert_eq!(page1.len(), 2);
        let (found, n) = repo.list_users("a", 1, 10).context("required")?;
        assert_eq!(n, 2);
        let mut names = Vec::new();
        for u in &found {
            names.push(u["user"].as_str().ok_or_else(|| anyhow!("user field missing"))?.to_owned());
        }
        assert!(names.contains(&"ann".to_string()) && names.contains(&"amy".to_string()));
        Ok(())
    }

    #[test]
    fn default_super_admin_seeded() -> Result<()> {
        let repo = repo()?;
        let salt = derive_auth_salt("admin")?;
        let hash = derive_pass_hash("admin", &salt).context("required")?;
        let out = repo.super_admin_login("admin", &hash).context("required")?.context("expected Some")?;
        assert!(out["token"].as_str().context("required")?.len() > 10);
        assert_eq!(repo.owner_count().context("required")?, 1);
        Ok(())
    }

    #[test]
    fn email_code_roundtrip_and_wrong_code() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("hank", "pass-1234")?;
        repo.register("hank", &h, &s).context("required")?;
        let code = repo.issue_email_code("hank", "a@b.c", "reset_password").context("required")?;
        assert_eq!(code.len(), 6);
        assert!(!repo.check_email_code("hank", "reset_password", "000000").context("required")?);
        let code2 = repo.issue_email_code("hank", "a@b.c", "reset_password").context("required")?;
        assert!(repo.check_email_code("hank", "reset_password", &code2).context("required")?);
        assert!(!repo.check_email_code("hank", "reset_password", &code2).context("required")?);
        Ok(())
    }

    #[test]
    fn schema_refuses_newer_version() -> Result<()> {
        let repo = repo()?;
        repo.lock()
            .execute("UPDATE schema_meta SET v='99' WHERE k='version'", &[])
            .context("required")?;
        let err = match BlobRepo::connect(&repo.url) {
            Err(e) => e.to_string(),
            Ok(_) => return Err(anyhow!("expected newer schema to be rejected")),
        };
        assert!(err.contains("newer than"), "{err}");
        Ok(())
    }

    #[test]
    fn apply_twice_does_not_reset_admin_password() -> Result<()> {
        let repo = repo()?;
        let salt = derive_auth_salt("admin")?;
        let old = derive_pass_hash("admin", &salt).context("required")?;
        let new = derive_pass_hash("changed-admin", &salt).context("required")?;
        assert!(repo.super_admin_set_password("admin", &new, &salt).context("required")?);
        crate::store::migrations::apply(&mut repo.lock()).context("required")?;
        assert!(repo.super_admin_login("admin", &old).context("required")?.is_none());
        assert!(repo.super_admin_login("admin", &new).context("required")?.is_some());
        assert_eq!(repo.owner_count().context("required")?, 1);
        Ok(())
    }

    #[test]
    fn reserved_word_username_user() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("user", "pass-1234")?;
        let tok = repo.register("user", &h, &s).context("required")?.context("expected Some")?;
        assert_eq!(repo.login("user", &h).context("required")?.as_deref(), Some(tok.as_str()));
        assert!(repo.put("user", &mem("id-1", "2026-09-02T00:00:00.000Z", "aa")).context("required")?);
        assert_eq!(repo.count("user").context("required")?, 1);
        let (blobs, _, total, alive) = repo.pull("user", None).context("required")?;
        assert_eq!(blobs.len(), 1);
        assert_eq!(total, 1);
        assert_eq!(alive, 1);
        Ok(())
    }

    #[test]
    fn blob_isolation_and_global_rev() -> Result<()> {
        let repo = repo()?;
        let (sa, ha) = hash("alice", "pass-1234")?;
        let (sb, hb) = hash("bob", "pass-1234")?;
        repo.register("alice", &ha, &sa).context("required")?;
        repo.register("bob", &hb, &sb).context("required")?;
        assert!(repo.put("alice", &mem("same", "2026-09-02T00:00:00.000Z", "aa")).context("required")?);
        assert!(repo.put("bob", &mem("same", "2026-09-02T00:00:00.000Z", "bb")).context("required")?);
        assert_eq!(repo.count("alice").context("required")?, 1);
        assert_eq!(repo.count("bob").context("required")?, 1);
        let (a_blobs, a_cur, _, _) = repo.pull("alice", None).context("required")?;
        let (b_blobs, b_cur, _, _) = repo.pull("bob", None).context("required")?;
        assert_eq!(a_blobs[0].ciphertext, "aa");
        assert_eq!(b_blobs[0].ciphertext, "bb");
        assert_eq!(a_cur, b_cur);
        assert_eq!(a_cur, 2);
        let (inc, _, _, _) = repo.pull("alice", Some(1)).context("required")?;
        assert!(inc.is_empty());
        let (inc, _, _, _) = repo.pull("bob", Some(1)).context("required")?;
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].ciphertext, "bb");
        Ok(())
    }

    #[test]
    fn lww_reject_does_not_bump_rev() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("dave", "pass-1234")?;
        repo.register("dave", &h, &s).context("required")?;
        let a = mem("a", "2026-09-02T00:00:01.000Z", "aa");
        assert!(repo.put("dave", &a).context("required")?);
        let (_, c0, _, _) = repo.pull("dave", None).context("required")?;
        let older = BlobWrite {
            updated_at: "2026-09-01T00:00:00.000Z",
            ..a
        };
        assert!(!repo.put("dave", &older).context("required")?);
        let (all, c1, _, _) = repo.pull("dave", None).context("required")?;
        assert_eq!(c0, c1);
        assert_eq!(all[0].ciphertext, "aa");
        let (inc, _, _, _) = repo.pull("dave", Some(c0)).context("required")?;
        assert!(inc.is_empty());
        Ok(())
    }

    #[test]
    fn equal_timestamp_overwrites() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("eve", "pass-1234")?;
        repo.register("eve", &h, &s).context("required")?;
        let a = mem("a", "2026-09-02T00:00:01.000Z", "aa");
        assert!(repo.put("eve", &a).context("required")?);
        let same = BlobWrite {
            ciphertext: "zz",
            ..a
        };
        assert!(repo.put("eve", &same).context("required")?);
        let (all, _, _, _) = repo.pull("eve", None).context("required")?;
        assert_eq!(all[0].ciphertext, "zz");
        Ok(())
    }

    #[test]
    fn forget_missing_and_twice() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("erin", "pass-1234")?;
        repo.register("erin", &h, &s).context("required")?;
        assert!(!repo.forget("erin", "missing").context("required")?);
        repo.put("erin", &mem("m1", "2026-09-02T00:00:00.000Z", "aa")).context("required")?;
        let (_, c0, _, _) = repo.pull("erin", None).context("required")?;
        assert!(repo.forget("erin", "m1").context("required")?);
        let (all, c1, total, alive) = repo.pull("erin", None).context("required")?;
        assert!(c1 > c0);
        assert_eq!(total, 1);
        assert_eq!(alive, 0);
        assert!(all[0].deleted);
        assert!(!repo.forget("erin", "m1").context("required")?);
        let (_, c2, _, _) = repo.pull("erin", None).context("required")?;
        assert_eq!(c1, c2);
        let (inc, _, _, _) = repo.pull("erin", Some(c0)).context("required")?;
        assert_eq!(inc.len(), 1);
        assert!(inc[0].deleted);
        Ok(())
    }

    #[test]
    fn put_deleted_counts_as_tombstone() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("tom", "pass-1234")?;
        repo.register("tom", &h, &s).context("required")?;
        let mut b = mem("m1", "2026-09-02T00:00:00.000Z", "aa");
        b.deleted = true;
        assert!(repo.put("tom", &b).context("required")?);
        assert_eq!(repo.count("tom").context("required")?, 0);
        let (all, _, total, alive) = repo.pull("tom", None).context("required")?;
        assert_eq!(total, 1);
        assert_eq!(alive, 0);
        assert!(all[0].deleted);
        Ok(())
    }

    #[test]
    fn vault_rejects_bad_input_and_isolates() -> Result<()> {
        let repo = repo()?;
        let (sa, ha) = hash("fay", "pass-1234")?;
        let (sb, hb) = hash("gus", "pass-1234")?;
        repo.register("fay", &ha, &sa).context("required")?;
        repo.register("gus", &hb, &sb).context("required")?;
        assert!(repo.put_vault("fay", "short", "wrap", "nonce", 3).is_err());
        assert!(repo.put_vault("fay", "aabbccddeeff0011", "", "nonce", 3).is_err());
        assert!(repo.put_vault("fay", "aabbccddeeff0011", "wrap", "", 3).is_err());
        assert!(repo.put_vault("fay", "aabbccddeeff0011", "wrap", "nonce", 1).is_err());
        assert!(repo.put_vault("fay", "aabbccddeeff0011", "wrap", "nonce", 5).is_err());
        assert!(repo.put_vault("fay", "aabbccddeeff0011", "wrap", "nonce", 4).is_ok());
        repo.put_vault("fay", "aabbccddeeff0011", "wrap-a", "nonce-a", 2).context("required")?;
        repo.put_vault("gus", "aabbccddeeff0011", "wrap-b", "nonce-b", 3).context("required")?;
        let a = repo.get_vault("fay").context("required")?.context("expected Some")?;
        let b = repo.get_vault("gus").context("required")?.context("expected Some")?;
        assert_eq!(a["wrapped_urk"], "wrap-a");
        assert_eq!(a["version"], 2);
        assert_eq!(b["wrapped_urk"], "wrap-b");
        assert_eq!(b["version"], 3);
        assert!(repo.get_vault("missing").context("required")?.is_none());
        Ok(())
    }

    #[test]
    fn last_owner_cannot_be_deleted() -> Result<()> {
        let repo = repo()?;
        assert!(!repo.delete_admin("admin").context("required")?);
        assert_eq!(repo.owner_count().context("required")?, 1);
        assert!(repo
            .create_admin("ops", "h", "s", "owner", "ops@x")
            .context("required")?
            .is_some());
        assert_eq!(repo.owner_count().context("required")?, 2);
        assert!(repo.delete_admin("admin").context("required")?);
        assert_eq!(repo.owner_count().context("required")?, 1);
        assert!(!repo.delete_admin("ops").context("required")?);
        assert!(repo.create_admin("ops", "h", "s", "owner", "").context("required")?.is_none());
        assert!(repo.create_admin("view", "h", "s", "viewer", "").context("required")?.is_some());
        assert!(repo.delete_admin("view").context("required")?);
        assert!(repo.delete_admin("ghost").context("required")? == false);
        Ok(())
    }

    #[test]
    fn tickets_one_shot_wrong_purpose_expired() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("alice", "pass-1234")?;
        repo.register("alice", &h, &s).context("required")?;
        let t = repo.issue_ticket("alice", "user_totp").context("required")?;
        assert!(repo.take_ticket(&t, "admin_totp").context("required")?.is_none());
        assert_eq!(repo.take_ticket(&t, "user_totp").context("required")?.as_deref(), Some("alice"));
        assert!(repo.take_ticket(&t, "user_totp").context("required")?.is_none());

        let past = (chrono::Utc::now() - chrono::Duration::minutes(20))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        repo.lock()
            .execute(
                "INSERT INTO verify_codes (id, audience, purpose, code_hash, email, expires_at) VALUES ($1,$2,$3,'','',$4)",
                &[&"expired-1", &"alice", &"user_totp", &past],
            )
            .context("required")?;
        assert!(repo.take_ticket("expired-1", "user_totp").context("required")?.is_none());
        assert!(repo.take_ticket("expired-1", "user_totp").context("required")?.is_none());
        Ok(())
    }

    #[test]
    fn confirm_email_and_reset_password() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("hank", "pass-1234")?;
        repo.register("hank", &h, &s).context("required")?;
        let initial = repo.issue_email_code("hank", "a@b.c", "verify_email").context("required")?;
        assert_eq!(repo.user_keys("hank", "token")?["email_verified"], false);
        assert!(!repo.queue_email_code("hank", "a@b.c", "verify_email")?);
        let wrong = if initial == "000000" { "111111" } else { "000000" };
        for _ in 0..5 {
            assert!(!repo.confirm_email("hank", wrong).context("required")?);
        }
        assert!(!repo.confirm_email("hank", &initial).context("required")?);
        let code = repo.issue_email_code("hank", "a@b.c", "verify_email").context("required")?;
        assert!(repo.confirm_email("hank", &code).context("required")?);
        assert_eq!(repo.user_email("hank").context("required")?.as_deref(), Some("a@b.c"));
        assert_eq!(repo.user_keys("hank", "token")?["email_verified"], true);
        repo.admin_update_user("hank", None, None, None, Some("a@b.c"))?;
        assert_eq!(repo.user_keys("hank", "token")?["email_verified"], true);
        repo.admin_update_user("hank", None, None, None, Some("new@b.c"))?;
        assert_eq!(repo.user_keys("hank", "token")?["email_verified"], false);
        assert!(!repo.confirm_email("hank", &code).context("required")?);

        assert!(repo.recovery_email("hank")?.is_none());
        assert!(!repo.queue_email_code("hank", "new@b.c", "reset_password")?);
        let blocked = repo.issue_email_code("hank", "new@b.c", "reset_password")?;
        assert!(!repo.reset_password("hank", &blocked, &h, &s)?);
        let verified = repo.issue_email_code("hank", "new@b.c", "verify_email")?;
        assert!(repo.confirm_email("hank", &verified)?);
        assert_eq!(repo.recovery_email("hank")?.as_deref(), Some("new@b.c"));
        assert!(repo.recovery_email("missing")?.is_none());
        repo.set_disabled("hank", true)?;
        assert!(repo.recovery_email("hank")?.is_none());
        repo.set_disabled("hank", false)?;
        let expired = repo.issue_email_code("hank", "new@b.c", "reset_password")?;
        repo.lock().execute("UPDATE verify_codes SET expires_at='2000-01-01T00:00:00Z' WHERE audience='hank' AND purpose='reset_password'", &[])?;
        assert!(!repo.reset_password("hank", &expired, &h, &s)?);
        let exhausted = repo.issue_email_code("hank", "new@b.c", "reset_password")?;
        let wrong = if exhausted == "000000" { "111111" } else { "000000" };
        for _ in 0..5 { assert!(!repo.reset_password("hank", wrong, &h, &s)?); }
        assert!(!repo.reset_password("hank", &exhausted, &h, &s)?);
        let legacy = repo.login("hank", &h)?.context("legacy token")?;
        let session = repo.login_session("hank", &h, Some("test-device"))?.context("session")?;
        let session_token = session["token"].as_str().context("session token")?;
        let ticket = repo.issue_ticket("hank", "user_totp")?;
        repo.put_vault("hank", "aabbccddeeff0011", "aa", "bb", 4)?;
        let vault = repo.get_vault("hank")?;
        let reset = repo.issue_email_code("hank", "new@b.c", "reset_password").context("required")?;
        assert!(!repo.reset_password("hank", &reset, "", &s)?);
        let (s2, h2) = hash("hank", "new-pass")?;
        assert!(repo.reset_password("hank", &reset, &h2, &s2).context("required")?);
        assert!(repo.try_user_from_token(&legacy)?.is_none());
        assert!(repo.try_user_from_token(session_token)?.is_none());
        assert!(repo.take_ticket(&ticket, "user_totp")?.is_none());
        assert_eq!(repo.get_vault("hank")?, vault);
        assert!(repo.login("hank", &h).context("required")?.is_none());
        assert!(repo.login("hank", &h2).context("required")?.is_some());
        assert!(!repo.reset_password("hank", &reset, &h, &s).context("required")?);
        Ok(())
    }

    #[test]
    fn totp_enroll_confirm_disable() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("ivy", "pass-1234")?;
        repo.register("ivy", &h, &s).context("required")?;
        repo.totp_begin("ivy", "user_totp_enroll").context("required")?;
        assert!(!repo.totp_confirm("users", "ivy", "user_totp_enroll", "000000").context("required")?);
        let begin = repo.totp_begin("ivy", "user_totp_enroll").context("required")?;
        let secret = begin["secret"].as_str().context("required")?.to_owned();
        let code = crate::totp::generate(&secret, chrono::Utc::now().timestamp()).context("required")?;
        assert!(repo.totp_confirm("users", "ivy", "user_totp_enroll", &code).context("required")?);
        let out = repo.login_session("ivy", &h, None).context("required")?.context("expected Some")?;
        assert_eq!(out["totp_required"], true);
        let ticket = out["ticket"].as_str().context("required")?;
        assert!(repo.complete_user_totp(ticket, "000000", None).context("required")?.is_none());
        let out = repo.login_session("ivy", &h, None).context("required")?.context("expected Some")?;
        let ticket = out["ticket"].as_str().context("required")?.to_owned();
        let session = repo.complete_user_totp(&ticket, &code, Some("phone")).context("required")?.context("expected Some")?;
        assert_eq!(session["user"], "ivy");
        assert!(session["token"].as_str().context("required")?.len() > 10);
        assert!(session.get("session_id").is_some());
        assert!(repo.totp_disable("users", "ivy", "000000").context("required")? == false);
        assert!(repo.totp_disable("users", "ivy", &code).context("required")?);
        let out = repo.login_session("ivy", &h, None).context("required")?.context("expected Some")?;
        assert!(out.get("totp_required").is_none());
        assert!(out["token"].as_str().is_some());
        Ok(())
    }

    #[test]
    fn audit_and_outbox_pagination() -> Result<()> {
        let repo = repo()?;
        repo.audit("admin", "kick", "alice", "d1").context("required")?;
        repo.audit("ops", "ban", "bob", "d2").context("required")?;
        repo.audit("admin", "restore", "carol", "d3").context("required")?;
        let (page1, total) = repo.list_audit("", 1, 2).context("required")?;
        assert_eq!(total, 3);
        assert_eq!(page1.len(), 2);
        let (found, n) = repo.list_audit("kick", 1, 10).context("required")?;
        assert_eq!(n, 1);
        assert_eq!(found[0]["action"], "kick");
        repo.mail_outbox("a@b.c", "subj1", "body1").context("required")?;
        repo.mail_outbox("c@d.e", "subj2", "body2").context("required")?;
        let (items, total) = repo.list_outbox(1, 1).context("required")?;
        assert_eq!(total, 2);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["subject"], "subj2");
        Ok(())
    }

    #[test]
    fn rotate_and_revoke_user() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("alice", "pass-1234")?;
        let legacy = repo.register("alice", &h, &s).context("required")?.context("expected Some")?;
        let (sess, _) = repo.create_session("alice", "laptop").context("required")?;
        repo.put("alice", &mem("m1", "2026-09-02T00:00:00.000Z", "aa")).context("required")?;
        let rotated = repo.rotate_token("alice").context("required")?.context("expected Some")?;
        assert_ne!(rotated, legacy);
        assert!(repo.user_from_token(&legacy)?.is_none());
        assert!(repo.user_from_token(&sess)?.is_none());
        assert_eq!(repo.user_from_token(&rotated)?.as_deref(), Some("alice"));
        assert_eq!(repo.count("alice").context("required")?, 1);
        let (gone, blobs) = repo.revoke_user("alice").context("required")?;
        assert!(gone);
        assert_eq!(blobs, 1);
        assert!(repo.user_from_token(&rotated)?.is_none());
        assert_eq!(repo.count("alice").context("required")?, 0);
        assert!(!repo.revoke_user("alice").context("required")?.0);
        Ok(())
    }

    #[test]
    fn disabled_blocks_session_token() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("bob", "pass-1234")?;
        repo.register("bob", &h, &s).context("required")?;
        let (sess, _) = repo.create_session("bob", "phone").context("required")?;
        assert_eq!(repo.user_from_token(&sess)?.as_deref(), Some("bob"));
        repo.set_disabled("bob", true).context("required")?;
        assert!(repo.user_from_token(&sess)?.is_none());
        repo.set_disabled("bob", false).context("required")?;
        assert_eq!(repo.user_from_token(&sess)?.as_deref(), Some("bob"));
        Ok(())
    }

    #[test]
    fn deleted_rotates_and_blocks_auth() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("cara", "pass-1234")?;
        let legacy = repo.register("cara", &h, &s).context("required")?.context("expected Some")?;
        let (sess, _) = repo.create_session("cara", "pad").context("required")?;
        repo.put("cara", &mem("m1", "2026-09-02T00:00:00.000Z", "aa")).context("required")?;
        assert!(repo.set_deleted("cara", true).context("required")?);
        assert!(repo.user_from_token(&legacy)?.is_none());
        assert!(repo.user_from_token(&sess)?.is_none());
        assert_eq!(repo.login("cara", &h).unwrap_err().to_string(), "deleted");
        assert_eq!(repo.count("cara").context("required")?, 1);
        assert!(repo.set_deleted("cara", false).context("required")?);
        let again = repo.login("cara", &h).context("required")?.context("expected Some")?;
        assert_ne!(again, legacy);
        assert_eq!(repo.count("cara").context("required")?, 1);
        Ok(())
    }

    #[test]
    fn user_set_password_skips_disabled() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("dan", "pass-1234")?;
        repo.register("dan", &h, &s).context("required")?;
        repo.set_disabled("dan", true).context("required")?;
        let (s2, h2) = hash("dan", "other")?;
        assert!(!repo.user_set_password("dan", &h2, &s2).context("required")?);
        repo.set_disabled("dan", false).context("required")?;
        assert!(repo.user_set_password("dan", &h2, &s2).context("required")?);
        assert!(repo.login("dan", &h).context("required")?.is_none());
        assert!(repo.login("dan", &h2).context("required")?.is_some());
        Ok(())
    }

    #[test]
    fn list_users_search_email_and_page_clamp() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("ann", "pass-1234")?;
        repo.register("ann", &h, &s).context("required")?;
        repo.admin_update_user("ann", None, None, None, Some("Ann@Ex.com")).context("required")?;
        let (found, n) = repo.list_users("ann@ex.com", 0, 1000).context("required")?;
        assert_eq!(n, 1);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["email"], "Ann@Ex.com");
        let csv = repo.users_csv("ann").context("required")?;
        assert!(csv.starts_with("user,email,disabled,deleted,session_count,active,created_at,token_masked\n"));
        assert!(csv.contains("ann"));
        assert!(csv.contains("Ann@Ex.com"));
        Ok(())
    }

    #[test]
    fn max_updated_at_empty_then_value() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("max", "pass-1234")?;
        repo.register("max", &h, &s).context("required")?;
        assert!(repo.max_updated_at("max").context("required")?.is_none());
        repo.put("max", &mem("m1", "2026-09-02T00:00:00.000Z", "aa")).context("required")?;
        repo.put("max", &mem("m2", "2026-09-03T00:00:00.000Z", "bb")).context("required")?;
        assert_eq!(
            repo.max_updated_at("max").context("required")?.as_deref(),
            Some("2026-09-03T00:00:00.000Z")
        );
        Ok(())
    }

    #[test]
    fn super_admin_login_disabled() -> Result<()> {
        let repo = repo()?;
        let salt = derive_auth_salt("admin")?;
        let hash = derive_pass_hash("admin", &salt).context("required")?;
        assert!(repo
            .admin_update_admin("admin", None, None, Some(true), None)
            .context("required")?);
        assert_eq!(
            repo.super_admin_login("admin", &hash).unwrap_err().to_string(),
            "disabled"
        );
        assert!(repo
            .admin_update_admin("admin", None, None, Some(false), Some("admin@x"))
            .context("required")?);
        assert_eq!(repo.admin_email("admin"), "admin@x");
        assert!(!repo.admin_has_totp("admin"));
        let out = repo.super_admin_login("admin", &hash).context("required")?.context("expected Some")?;
        assert!(out["token"].as_str().context("required")?.len() > 10);
        Ok(())
    }

    #[test]
    fn register_session_device_name() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("dev", "pass-1234")?;
        let out = repo.register_session("dev", &h, &s, Some("laptop")).context("required")?.context("expected Some")?;
        assert_eq!(out["user"], "dev");
        assert!(out["session_id"].as_str().context("required")?.len() > 8);
        let tok = out["token"].as_str().context("required")?;
        assert_eq!(repo.user_from_token(tok)?.as_deref(), Some("dev"));
        let sessions = repo.list_user_sessions("dev").context("required")?.context("expected Some")?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["device_name"], "laptop");
        assert!(repo.list_user_sessions("ghost").context("required")?.is_none());
        Ok(())
    }

    #[test]
    fn daily_stats_buckets_by_shanghai_day_and_zero_fills() -> Result<()> {
        let repo = repo()?;
        // UTC 15:59 = Shanghai 23:59 same day; UTC 16:30 = Shanghai 00:30 next day.
        repo.lock().batch_execute(
            "INSERT INTO users (\"user\", pass_hash, salt, token, created_at) VALUES
                ('u-early','h','s','t1','2026-09-01T15:59:00.000Z'),
                ('u-late','h','s','t2','2026-09-01T16:30:00.000Z');
             INSERT INTO sessions (id, \"user\", token_hash, device_name, created_at)
                VALUES ('s1','u-early','th1','d','2026-09-01T15:59:00.000Z');",
        )?;
        let today = chrono::NaiveDate::from_ymd_opt(2026, 9, 2).context("required")?;
        let stats = repo.daily_stats_until(7, today)?;
        let series = stats["series"].as_array().context("series array")?;
        assert_eq!(series.len(), 7);
        assert_eq!(series[0]["date"], "2026-08-27");
        assert_eq!(series[5]["date"], "2026-09-01");
        assert_eq!(series[6]["date"], "2026-09-02");
        assert_eq!(series[5]["registrations"], 1);
        assert_eq!(series[6]["registrations"], 1);
        assert!(series[6]["memories"].is_null());
        assert!(series[5]["memories"].is_null());
        assert_eq!(series[5]["sessions"], 1);
        assert_eq!(series[6]["sessions"], 0);
        for p in &series[..5] {
            assert_eq!(p["registrations"], 0);
            assert!(p["memories"].is_null());
            assert_eq!(p["sessions"], 0);
        }
        Ok(())
    }

    #[test]
    fn daily_stats_counts_first_server_receipt_and_survives_edits_and_deletion() -> Result<()> {
        let repo = repo()?;
        let (s, h) = hash("gone", "pass-1234")?;
        repo.register("gone", &h, &s).context("required")?;
        repo.put("gone", &mem("m1", "2026-09-02T00:00:00.000Z", "aa")).context("required")?;
        repo.put("gone", &mem("m1", "2026-09-02T00:00:00.000Z", "aa"))?;
        repo.put("gone", &mem("m1", "2026-09-02T00:30:00.000Z", "edited"))?;
        // A client timestamp is not a server receipt date and cannot break statistics.
        repo.lock().batch_execute("UPDATE blobs SET updated_at='not-a-timestamp' WHERE id='m1'")?;
        let mut tombstone = mem("m1", "2026-09-02T01:00:00.000Z", "aa");
        tombstone.deleted = true;
        repo.put("gone", &tombstone).context("required")?;
        repo.set_deleted("gone", true)?;
        let stats = repo.daily_stats(7)?;
        let series = stats["series"].as_array().context("series array")?;
        let current = series.last().context("current day")?;
        assert_eq!(current["registrations"], 1);
        assert_eq!(current["memories"], 1);
        assert_eq!(current["sessions"], 0);
        repo.lock().batch_execute("DELETE FROM blobs; DELETE FROM sessions; DELETE FROM users")?;
        assert_eq!(repo.daily_stats(7)?, stats, "anonymous totals survive hard deletion");
        Ok(())
    }

    #[test]
    fn daily_stats_rollback_and_first_tombstone_do_not_increment() -> Result<()> {
        let repo = repo()?;
        let before = repo.daily_stats(7)?;
        {
            let mut client = repo.lock();
            let mut tx = client.transaction()?;
            tx.batch_execute("INSERT INTO blobs (\"user\",id,updated_at) VALUES ('fixture','rollback','invalid')")?;
            tx.rollback()?;
            client.batch_execute("INSERT INTO blobs (\"user\",id,deleted,updated_at) VALUES ('fixture','tombstone',1,'invalid')")?;
        }
        assert_eq!(repo.daily_stats(7)?, before);
        Ok(())
    }
}
