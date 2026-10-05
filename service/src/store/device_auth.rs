//! Short-lived browser-approved CLI grants. Only hashes of the CLI secrets persist.
use anyhow::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use super::BlobRepo;

fn hash(value: &str) -> String { format!("{:x}", Sha256::digest(value.as_bytes())) }

impl BlobRepo {
    pub(crate) fn start_cli_authorization(&self, device: &str, expected_user: &str) -> Result<Value> {
        let device_code = respire::memory::crypto::random_hex(32);
        let user_code = respire::memory::crypto::random_hex(6).to_uppercase();
        let expires = chrono::Utc::now().timestamp() + 600;
        let mut client = self.lock();
        client.execute("DELETE FROM cli_authorizations WHERE expires_at <= $1", &[&chrono::Utc::now().timestamp()])?;
        client.execute("INSERT INTO cli_authorizations (device_hash,user_code,device_name,expected_user,expires_at) VALUES ($1,$2,$3,$4,$5)",
            &[&hash(&device_code), &user_code, &device, &expected_user, &expires])?;
        Ok(json!({"device_code":device_code,"user_code":user_code,"expires_in":600,"interval":5}))
    }

    pub(crate) fn cli_authorization_info(&self, code: &str) -> Result<Option<Value>> {
        let row = self.lock().query_opt("SELECT device_name,expected_user,expires_at,state FROM cli_authorizations WHERE user_code=$1 AND expires_at>$2",
            &[&code, &chrono::Utc::now().timestamp()])?;
        Ok(row.map(|row| json!({"device_name":row.get::<_,String>(0),"expected_user":row.get::<_,String>(1),
            "expires_in":row.get::<_,i64>(2)-chrono::Utc::now().timestamp(),"state":row.get::<_,String>(3)})))
    }

    pub(crate) fn decide_cli_authorization(&self, code: &str, user: &str, approve: bool) -> Result<bool> {
        let state = if approve { "approved" } else { "denied" };
        let changed = self.lock().execute("UPDATE cli_authorizations SET state=$1,approved_user=$2 WHERE user_code=$3 AND state='pending' AND expires_at>$4 AND (expected_user='' OR expected_user=$2)",
            &[&state, &user, &code, &chrono::Utc::now().timestamp()])?;
        Ok(changed == 1)
    }

    pub(crate) fn poll_cli_authorization(&self, device_code: &str) -> Result<Value> {
        let mut client = self.lock();
        let mut tx = client.transaction()?;
        let device_hash = hash(device_code);
        let Some(row) = tx.query_opt("SELECT state,approved_user,device_name,expires_at,next_poll FROM cli_authorizations WHERE device_hash=$1 FOR UPDATE", &[&device_hash])? else {
            return Ok(json!({"state":"invalid"}));
        };
        if row.get::<_,i64>(3) <= chrono::Utc::now().timestamp() { return Ok(json!({"state":"expired"})); }
        let now_seconds = chrono::Utc::now().timestamp();
        if row.get::<_,i64>(4) > now_seconds { return Ok(json!({"state":"slow_down"})); }
        let state: String = row.get(0);
        if state != "approved" {
            tx.execute("UPDATE cli_authorizations SET next_poll=$2 WHERE device_hash=$1", &[&device_hash, &(now_seconds+5)])?;
            tx.commit()?;
            return Ok(json!({"state":state}));
        }
        let user: String = row.get(1);
        let device: String = row.get(2);
        let active = tx.query_opt(r#"SELECT 1 FROM users WHERE "user"=$1 AND disabled=0 AND deleted=0"#, &[&user])?;
        if active.is_none() {
            tx.execute("DELETE FROM cli_authorizations WHERE device_hash=$1", &[&device_hash])?;
            tx.commit()?;
            return Ok(json!({"state":"invalid"}));
        }
        let token = respire::memory::crypto::random_hex(32);
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(r#"INSERT INTO sessions (id,"user",token_hash,device_name,created_at,readonly) VALUES ($1,$2,$3,$4,$5,0)"#,
            &[&id, &user, &hash(&token), &device, &now])?;
        tx.execute("DELETE FROM cli_authorizations WHERE device_hash=$1", &[&device_hash])?;
        tx.commit()?;
        Ok(json!({"state":"authorized","user":user,"token":token,"session_id":id}))
    }
}
