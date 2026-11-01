//! A separate, user-verified ceremony authorizes one concrete review intent.
use super::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBinding {
    owner: String,
    local_library_id: String,
    id: String,
    record_revision: String,
    expected_memory_revision: String,
    claim_digest: String,
    intent_digest: String,
}

impl ReviewBinding {
    fn validate(&self, user: &str) -> Result<()> {
        fn digest(value: &str) -> bool {
            value.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
        }
        if self.owner != user
            || self.local_library_id.is_empty()
            || self.local_library_id.len() > 256
            || Uuid::parse_str(&self.id)?.to_string() != self.id
            || !digest(&self.record_revision)
            || !digest(&self.claim_digest)
            || !digest(&self.intent_digest)
            || self.expected_memory_revision.len() != 32
            || !self
                .expected_memory_revision
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            bail!("invalid review binding");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    credential_id: String,
    binding: ReviewBinding,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    binding: ReviewBinding,
    authentication: PasskeyAuthentication,
    passkey: Passkey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    ceremony_id: String,
    credential: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consume {
    event_id: String,
    binding: ReviewBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    event_id: String,
    reason: String,
}

fn start(repo: &BlobRepo, config: &Config, user: &str, token: &str, body: &str) -> Result<Value> {
    let input: Start = serde_json::from_str(body)?;
    input.binding.validate(user)?;
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    let meta = vault(&mut tx, user)?;
    let row = current_credential(&mut tx, config, user, &meta, &input.credential_id)?;
    let passkey: Passkey = serde_json::from_str(&row.get::<_, String>(0))?;
    let (options, authentication) = config
        .webauthn
        .start_passkey_authentication(std::slice::from_ref(&passkey))?;
    let pending = Pending {
        binding: input.binding,
        authentication,
        passkey,
    };
    let id = save_ceremony(
        &mut tx,
        config,
        user,
        token,
        &meta,
        "review-confirm",
        &pending,
    )?;
    tx.commit()?;
    let mut response = envelope(
        config,
        &meta,
        &id,
        serde_json::to_value(options)?["publicKey"].clone(),
    );
    response["purpose"] = json!("review-confirm");
    response["binding"] = serde_json::to_value(pending.binding)?;
    response["credential_id"] = json!(input.credential_id);
    Ok(response)
}

fn finish(repo: &BlobRepo, config: &Config, user: &str, token: &str, body: &str) -> Result<Value> {
    let input: Complete = serde_json::from_str(body)?;
    let (meta, pending) = take_ceremony::<Pending>(
        repo,
        config,
        user,
        token,
        &input.ceremony_id,
        "review-confirm",
    )?;
    pending.binding.validate(user)?;
    validate_credential(&input.credential, Some(&meta.account_id))?;
    let credential: PublicKeyCredential = serde_json::from_value(input.credential)?;
    let result = config
        .webauthn
        .finish_passkey_authentication(&credential, &pending.authentication)?;
    let id = credential_id(&pending.passkey);
    if !result.user_verified()
        || result.cred_id() != pending.passkey.cred_id()
        || credential.id != id
    {
        bail!("verified credential mismatch");
    }
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    check_meta(&mut tx, user, &meta)?;
    let row = current_credential(&mut tx, config, user, &meta, &id)?;
    let old_count: i64 = row.get(4);
    let new_count = i64::from(result.counter());
    if (old_count != 0 || new_count != 0) && new_count <= old_count {
        bail!("authenticator counter did not advance");
    }
    let mut current: Passkey = serde_json::from_str(&row.get::<_, String>(0))?;
    current
        .update_credential(&result)
        .ok_or_else(|| anyhow!("credential update mismatch"))?;
    tx.execute(
        "UPDATE vault_passkeys SET passkey=$2,last_used_at=$3,sign_count=$4 WHERE credential_id=$1",
        &[
            &id,
            &serde_json::to_string(&current)?,
            &timestamp(),
            &new_count,
        ],
    )?;
    let event_id = Uuid::new_v4().to_string();
    let confirmed_at = timestamp();
    let expires_at = now() + TTL_SECONDS;
    tx.execute(r#"INSERT INTO review_confirmations
        (event_id,"user",account_id,key_generation,rp_id,origin,credential_id,binding,confirmed_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
        &[&event_id, &user, &meta.account_id, &meta.key_generation, &config.rp_id, &config.origin,
          &id, &serde_json::to_string(&pending.binding)?, &confirmed_at, &expires_at])?;
    tx.commit()?;
    drop(client);
    receipt(repo, config, user, &event_id, None)
}

// Consumption and read validation share the same account-first lock order.
fn receipt(
    repo: &BlobRepo,
    config: &Config,
    user: &str,
    event_id: &str,
    consume: Option<&ReviewBinding>,
) -> Result<Value> {
    Uuid::parse_str(event_id)?;
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    let meta = vault(&mut tx, user)?;
    let row = tx.query_opt(r#"SELECT account_id,key_generation,rp_id,origin,credential_id,binding,confirmed_at,expires_at,consumed_at,revoked_at
        FROM review_confirmations WHERE event_id=$1 AND "user"=$2 FOR UPDATE"#, &[&event_id, &user])?
        .ok_or_else(|| anyhow!("confirmation unavailable"))?;
    let binding: ReviewBinding = serde_json::from_str(&row.get::<_, String>(5))?;
    binding.validate(user)?;
    let mut consumed_at: Option<String> = row.get(8);
    let revoked_at: Option<String> = row.get(9);
    let expires_at: i64 = row.get(7);
    let current_account = row.get::<_, String>(0) == meta.account_id
        && row.get::<_, i64>(1) == meta.key_generation
        && row.get::<_, String>(2) == config.rp_id
        && row.get::<_, String>(3) == config.origin;
    let credential_active = tx.query_opt(r#"SELECT 1 FROM vault_passkeys WHERE credential_id=$1 AND "user"=$2 AND account_id=$3 AND key_generation=$4 AND rp_id=$5 AND origin=$6"#,
        &[&row.get::<_, String>(4), &user, &meta.account_id, &meta.key_generation, &config.rp_id, &config.origin])?.is_some();
    let valid = current_account && credential_active && revoked_at.is_none();
    if let Some(expected) = consume {
        expected.validate(user)?;
        if !valid || expires_at <= now() || consumed_at.is_some() || expected != &binding {
            bail!("approval expired, consumed, revoked, or binding mismatch");
        }
        let consumed = timestamp();
        tx.execute(
            "UPDATE review_confirmations SET consumed_at=$2 WHERE event_id=$1",
            &[&event_id, &consumed],
        )?;
        consumed_at = Some(consumed);
    }
    let response = json!({"event_id":event_id,"purpose":"review-confirm","account_id":meta.account_id,
        "binding":binding,"confirmed_by":{"kind":"human","id":user,"event_id":event_id},
        "confirmed_at":row.get::<_, String>(6),"expires_at":expires_at,
        "consumed_at":consumed_at,"revoked_at":revoked_at,"valid":valid,
        "submission_available":valid && expires_at > now() && consumed_at.is_none()});
    tx.commit()?;
    Ok(response)
}

fn revoke(repo: &BlobRepo, user: &str, body: &str) -> Result<Value> {
    let input: Revoke = serde_json::from_str(body)?;
    Uuid::parse_str(&input.event_id)?;
    if input.reason.trim().is_empty() || input.reason.len() > 1024 {
        bail!("reason required");
    }
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    vault(&mut tx, user)?;
    let changed = tx.execute(
        r#"UPDATE review_confirmations SET revoked_at=COALESCE(revoked_at,$3),
        revocation_reason=COALESCE(revocation_reason,$4) WHERE event_id=$1 AND "user"=$2"#,
        &[&input.event_id, &user, &timestamp(), &input.reason],
    )?;
    if changed != 1 {
        bail!("confirmation unavailable");
    }
    tx.commit()?;
    Ok(json!({"event_id":input.event_id,"revoked":true}))
}

pub(super) fn route(
    repo: &BlobRepo,
    config: &Config,
    method: &str,
    suffix: &str,
    body: &str,
    user: &str,
    token: &str,
) -> (u16, String) {
    let result = match (method, suffix) {
        ("POST", "/review/start") => start(repo, config, user, token, body),
        ("POST", "/review/finish") => finish(repo, config, user, token, body),
        ("POST", "/review/consume") => (|| {
            let input: Consume = serde_json::from_str(body)?;
            receipt(repo, config, user, &input.event_id, Some(&input.binding))
        })(),
        ("POST", "/review/revoke") => revoke(repo, user, body),
        ("GET", path) if path.starts_with("/review/events/") => {
            receipt(repo, config, user, &path[15..], None)
        }
        _ => return super::super::json::json(404, json!({"error":"not found"})),
    };
    match result {
        Ok(value) => super::super::json::json(200, value),
        Err(error) if error.is::<postgres::Error>() => super::super::json::server_error(error),
        Err(_) => super::super::json::json(
            400,
            json!({"error":"review confirmation rejected","code":"verification_rejected"}),
        ),
    }
}
