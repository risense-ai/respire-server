//! Provider identities and one-use browser grants. Vault material is untouched.
use anyhow::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::BlobRepo;

fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn browser_grants_are_short_lived_owner_bound_and_one_use() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        let (state, verifier) = repo.start_github_authorization(Some("alice"))?;
        assert_eq!(state.len(), 64);
        assert_eq!(verifier.len(), 64);
        assert!(repo.take_github_authorization(&state, None)?.is_none());
        assert!(repo
            .take_github_authorization(&state, Some("bob"))?
            .is_none());
        assert_eq!(
            repo.take_github_authorization(&state, Some("alice"))?,
            Some(verifier)
        );
        assert!(repo
            .take_github_authorization(&state, Some("alice"))?
            .is_none());
        let (expired, _) = repo.start_github_authorization(None)?;
        repo.lock().execute(
            "UPDATE github_authorizations SET expires_at=0 WHERE state_hash=$1",
            &[&hash(&expired)],
        )?;
        assert!(repo.take_github_authorization(&expired, None)?.is_none());
        let (fresh, _) = repo.start_github_authorization(None)?;
        assert!(repo.take_github_authorization(&fresh, None)?.is_some());
        assert_eq!(
            repo.lock()
                .query_one("SELECT COUNT(*) FROM github_authorizations", &[])?
                .get::<_, i64>(0),
            0
        );
        Ok(())
    }

    #[test]
    fn github_unlink_preserves_sessions_and_vault_and_rejects_sole_login() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        let reply = repo.login_github(123, "before-rename", "dashboard")?;
        let user = reply["user"].as_str().context("user")?;
        let token = reply["token"].as_str().context("token")?;
        assert!(reply["created"].as_bool().context("created")?);
        assert!(repo.login_session(user, "", None)?.is_none());
        assert!(repo
            .login_session(user, "nonempty-hash", Some("attacker"))?
            .is_none());
        assert_eq!(
            crate::http::handle_full(
                &repo,
                "POST",
                "/login",
                &json!({"user":user,"pass_hash":""}).to_string(),
                None,
                None
            )
            .0,
            401
        );
        assert_eq!(
            crate::http::handle_full(
                &repo,
                "POST",
                "/register",
                r#"{"user":"github-456","pass_hash":"attacker-hash"}"#,
                None,
                None
            )
            .0,
            400
        );
        assert!(!repo.exists_user("github-456"));
        assert!(!repo.unbind_github(user)?);
        let salt = "ab".repeat(16);
        let wrapped = "cd".repeat(48);
        let nonce = "ef".repeat(12);
        assert!(repo.initialize_github_vault(user, &salt, &wrapped, &nonce, 4)?);
        let vault = repo.get_vault(user)?;
        assert!(!repo.initialize_github_vault(user, &salt, &"ff".repeat(48), &nonce, 4)?);
        assert_eq!(repo.get_vault(user)?, vault);
        let renamed = repo.login_github(123, "after-rename", "CLI")?;
        assert_eq!(renamed["user"], user);
        assert_eq!(renamed["created"], false);
        assert_eq!(repo.github_binding(user)?["login"], "after-rename");
        repo.user_set_password(user, "password-hash", "salt")?;
        assert!(repo.unbind_github(user)?);
        assert_eq!(repo.github_binding(user)?["bound"], false);
        assert_eq!(repo.try_user_from_token(token)?, Some(user.to_owned()));
        assert_eq!(repo.get_vault(user)?, vault);
        assert!(repo.login_github(123, "after-rename", "dashboard").is_err());
        Ok(())
    }

    #[test]
    fn bindings_never_merge_accounts_and_github_obeys_totp_and_disabled_flags() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        repo.register("alice", "h1", "s1")?.context("alice")?;
        repo.register("bob", "h2", "s2")?.context("bob")?;
        assert!(repo.bind_github("alice", 100, "same-name")?);
        assert!(!repo.bind_github("bob", 100, "same-name")?);
        assert!(!repo.bind_github("alice", 101, "different-id")?);
        assert!(repo.bind_github("bob", 101, "same-name")?);
        assert_eq!(
            repo.login_github(100, "renamed", "dashboard")?["user"],
            "alice"
        );
        repo.put_vault(
            "alice",
            "0123456789abcdef",
            "original-ciphertext",
            "nonce",
            4,
        )?;
        let vault = repo.get_vault("alice")?;
        let sessions = repo
            .lock()
            .query_one("SELECT COUNT(*) FROM sessions WHERE \"user\"='alice'", &[])?
            .get::<_, i64>(0);
        repo.lock().execute(
            "UPDATE users SET totp_secret='JBSWY3DPEHPK3PXP' WHERE \"user\"='alice'",
            &[],
        )?;
        let challenged = repo.login_github(100, "renamed", "dashboard")?;
        assert_eq!(challenged["totp_required"], true);
        assert!(challenged.get("token").is_none());
        assert!(repo
            .complete_user_totp(
                challenged["ticket"].as_str().context("ticket")?,
                "invalid",
                Some("dashboard")
            )?
            .is_none());
        assert_eq!(
            repo.lock()
                .query_one("SELECT COUNT(*) FROM sessions WHERE \"user\"='alice'", &[])?
                .get::<_, i64>(0),
            sessions
        );
        assert_eq!(repo.get_vault("alice")?, vault);
        let code = crate::totp::generate("JBSWY3DPEHPK3PXP", chrono::Utc::now().timestamp())
            .context("TOTP code")?;
        let ticket = challenged["ticket"].as_str().context("ticket")?;
        let completed = repo
            .complete_user_totp(ticket, &code, Some("dashboard"))?
            .context("completed TOTP")?;
        assert!(completed["token"].is_string());
        assert!(repo
            .complete_user_totp(ticket, &code, Some("dashboard"))?
            .is_none());
        repo.lock()
            .execute("UPDATE users SET disabled=1 WHERE \"user\"='alice'", &[])?;
        assert!(repo.login_github(100, "renamed", "dashboard").is_err());
        repo.lock().execute(
            "UPDATE users SET disabled=0,deleted=1 WHERE \"user\"='alice'",
            &[],
        )?;
        assert!(repo.login_github(100, "renamed", "dashboard").is_err());
        assert!(!repo.bind_github("missing", 999, "missing")?);
        Ok(())
    }
}

impl BlobRepo {
    pub(crate) fn start_github_authorization(
        &self,
        owner: Option<&str>,
    ) -> Result<(String, String)> {
        let state = respire::memory::crypto::random_hex(32);
        let verifier = respire::memory::crypto::random_hex(32);
        let purpose = if owner.is_some() { "bind" } else { "login" };
        let owner = owner.unwrap_or("");
        let now = chrono::Utc::now().timestamp();
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        tx.execute(
            "DELETE FROM github_authorizations WHERE expires_at <= $1",
            &[&now],
        )?;
        tx.execute("INSERT INTO github_authorizations (state_hash,purpose,owner_user,verifier,expires_at) VALUES ($1,$2,$3,$4,$5)",
            &[&hash(&state), &purpose, &owner, &verifier, &(now + 600)])?;
        tx.commit()?;
        Ok((state, verifier))
    }

    pub(crate) fn take_github_authorization(
        &self,
        state: &str,
        owner: Option<&str>,
    ) -> Result<Option<String>> {
        let purpose = if owner.is_some() { "bind" } else { "login" };
        let owner = owner.unwrap_or("");
        let row = self.lock().query_opt(
            "DELETE FROM github_authorizations WHERE state_hash=$1 AND purpose=$2 AND owner_user=$3 AND expires_at>$4 RETURNING verifier",
            &[&hash(state), &purpose, &owner, &chrono::Utc::now().timestamp()],
        )?;
        Ok(row.map(|row| row.get(0)))
    }

    pub(crate) fn github_binding(&self, user: &str) -> Result<Value> {
        let row = self.lock().query_opt(
            "SELECT github_id,github_login FROM github_identities WHERE \"user\"=$1",
            &[&user],
        )?;
        Ok(match row {
            Some(row) => {
                json!({"bound":true,"id":row.get::<_,i64>(0),"login":row.get::<_,String>(1)})
            }
            None => json!({"bound":false}),
        })
    }

    /// Conflict is explicit: never replace either account's existing binding.
    pub(crate) fn bind_github(&self, user: &str, github_id: i64, login: &str) -> Result<bool> {
        if github_id <= 0 || login.is_empty() {
            anyhow::bail!("invalid GitHub identity");
        }
        let count = self.lock().execute(
            "INSERT INTO github_identities (github_id,\"user\",github_login,linked_at) SELECT $1,\"user\",$3,$4 FROM users WHERE \"user\"=$2 AND disabled=0 AND deleted=0 ON CONFLICT DO NOTHING",
            &[&github_id, &user, &login, &chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(count == 1)
    }

    /// The last login method cannot be removed. Existing sessions and vaults stay intact.
    pub(crate) fn unbind_github(&self, user: &str) -> Result<bool> {
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        let row = tx.query_opt(
            "SELECT pass_hash FROM users WHERE \"user\"=$1 AND disabled=0 AND deleted=0 FOR UPDATE",
            &[&user],
        )?;
        let Some(row) = row else {
            return Ok(false);
        };
        if row.get::<_, String>(0).is_empty() {
            return Ok(false);
        }
        tx.execute("DELETE FROM github_identities WHERE \"user\"=$1", &[&user])?;
        tx.commit()?;
        Ok(true)
    }

    pub(crate) fn initialize_github_vault(
        &self,
        user: &str,
        salt: &str,
        wrapped: &str,
        nonce: &str,
        version: i64,
    ) -> Result<bool> {
        anyhow::ensure!(
            version == 4
                && salt.len() == 32
                && nonce.len() == 24
                && wrapped.strip_prefix("rsrs:v1:").unwrap_or(wrapped).len() == 96
                && [salt, wrapped.strip_prefix("rsrs:v1:").unwrap_or(wrapped), nonce]
                    .iter()
                    .all(|s| s.bytes().all(|b| b.is_ascii_hexdigit())),
            "invalid initial vault"
        );
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        let active = tx.query_opt(
            "SELECT 1 FROM users WHERE \"user\"=$1 AND disabled=0 AND deleted=0 FOR UPDATE",
            &[&user],
        )?;
        if active.is_none() {
            return Ok(false);
        }
        let count = tx.execute("INSERT INTO vault (\"user\",kdf_salt,wrapped_urk,urk_nonce,version,updated_at) SELECT $1,$2,$3,$4,4,$5 WHERE EXISTS (SELECT 1 FROM github_identities WHERE \"user\"=$1) AND NOT EXISTS (SELECT 1 FROM blobs WHERE \"user\"=$1) ON CONFLICT DO NOTHING",
            &[&user,&salt,&wrapped,&nonce,&chrono::Utc::now().to_rfc3339()])?;
        tx.commit()?;
        Ok(count == 1)
    }

    /// Identity, account activation and session/TOTP issuance share one transaction.
    pub(crate) fn login_github(&self, github_id: i64, login: &str, device: &str) -> Result<Value> {
        if github_id <= 0 || login.is_empty() {
            anyhow::bail!("invalid GitHub identity");
        }
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        // Serialize first sign-in of the same provider identity, including absent rows.
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&github_id])?;
        let row = tx.query_opt(
            "SELECT g.\"user\",u.totp_secret,u.disabled,u.deleted FROM github_identities g JOIN users u ON u.\"user\"=g.\"user\" WHERE github_id=$1 FOR UPDATE OF g,u", &[&github_id],
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        let (user, totp, created) = if let Some(row) = row {
            if row.get::<_, i32>(2) != 0 || row.get::<_, i32>(3) != 0 {
                anyhow::bail!("account unavailable");
            }
            tx.execute(
                "UPDATE github_identities SET github_login=$2 WHERE github_id=$1",
                &[&github_id, &login],
            )?;
            (row.get::<_, String>(0), row.get::<_, String>(1), false)
        } else {
            let user = format!("github-{github_id}");
            let token = respire::memory::crypto::random_hex(32);
            let inserted = tx.execute("INSERT INTO users (\"user\",pass_hash,salt,token,created_at) VALUES ($1,'','',$2,$3) ON CONFLICT DO NOTHING", &[&user,&token,&now])?;
            if inserted != 1 {
                anyhow::bail!("account name conflict");
            }
            tx.execute("INSERT INTO github_identities (github_id,\"user\",github_login,linked_at) VALUES ($1,$2,$3,$4)", &[&github_id,&user,&login,&now])?;
            (user, String::new(), true)
        };
        let reply = if !totp.is_empty() {
            let ticket = respire::memory::crypto::random_hex(16);
            let expiry = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
            tx.execute("INSERT INTO verify_codes (id,audience,purpose,code_hash,email,expires_at) VALUES ($1,$2,'user_totp','','',$3)", &[&ticket,&user,&expiry])?;
            json!({"user":user,"totp_required":true,"ticket":ticket})
        } else {
            let token = respire::memory::crypto::random_hex(32);
            let id = uuid::Uuid::new_v4().to_string();
            tx.execute("INSERT INTO sessions (id,\"user\",token_hash,device_name,created_at,readonly) VALUES ($1,$2,$3,$4,$5,0)", &[&id,&user,&hash(&token),&device,&now])?;
            json!({"user":user,"token":token,"session_id":id,"created":created})
        };
        tx.commit()?;
        Ok(reply)
    }
}
