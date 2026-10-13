//! Opt-in WebAuthn vault unlock with PRF or a trusted-browser key. We verify
//! signatures; PRF outputs, trusted-browser keys and the URK stay browser-side.
//! Persisted ceremony state must never be returned to a client.

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use postgres::{Row, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::store::BlobRepo;

const TTL_SECONDS: i64 = 300;
const MAX_CREDENTIALS: i64 = 20;
const MAX_PENDING: i64 = 8;
const WRAPPER_KDF: &str = "webauthn-prf-hkdf-sha256-v1";
const DEVICE_WRAPPER_KDF: &str = "trusted-browser-aes256gcm-v1";

struct Config {
    rp_id: String,
    origin: String,
    webauthn: Webauthn,
    trusted_browser: bool,
}

impl Config {
    fn new(rp_id: &str, origin: &str) -> Result<Self> {
        let url = Url::parse(origin)?;
        // A dedicated RP per Dashboard deployment. No sibling origins, broad
        // parent-domain RP, arbitrary ports, paths, or insecure local exceptions.
        if url.scheme() != "https"
            || url.host_str() != Some(rp_id)
            || url.origin().ascii_serialization() != origin
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("passkeys require an exact HTTPS origin and matching RP host");
        }
        let webauthn = WebauthnBuilder::new(rp_id, &url)?
            .rp_name("Respire")
            .allow_subdomains(false)
            .allow_any_port(false)
            .timeout(std::time::Duration::from_secs(TTL_SECONDS as u64))
            .build()?;
        Ok(Self {
            rp_id: rp_id.into(),
            origin: origin.into(),
            webauthn,
            trusted_browser: false,
        })
    }

    fn from_env() -> Result<Option<Self>> {
        let rp = crate::env::var("RSRS_PASSKEY_RP_ID").unwrap_or_default();
        let origin = crate::env::var("RSRS_PASSKEY_ORIGIN").unwrap_or_default();
        if rp.is_empty() && origin.is_empty() {
            return Ok(None);
        }
        if rp.is_empty() || origin.is_empty() {
            bail!("set both RSRS_PASSKEY_RP_ID and RSRS_PASSKEY_ORIGIN, or neither");
        }
        let mut config = Self::new(&rp, &origin)?;
        config.trusted_browser =
            crate::env::var("RSRS_TRUSTED_BROWSER_UNLOCK").as_deref() == Ok("1");
        Ok(Some(config))
    }
}

pub(super) fn check_config() -> Result<()> {
    Config::from_env().map(|_| ())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Meta {
    account_id: String,
    key_generation: i64,
}

fn vault(tx: &mut Transaction<'_>, user: &str) -> Result<Meta> {
    // Global account lock order is users -> vault -> credentials/ceremonies.
    // Ceremony foreign keys also lock users, so vault-first could deadlock a reset.
    tx.query_opt(
        r#"SELECT 1 FROM users WHERE "user"=$1 FOR UPDATE"#,
        &[&user],
    )?
    .ok_or_else(|| anyhow!("user gone"))?;
    let row = tx
        .query_opt(
            r#"SELECT account_id,key_generation FROM vault WHERE "user"=$1 FOR UPDATE"#,
            &[&user],
        )?
        .ok_or_else(|| anyhow!("unlock and initialize the vault before adding passkeys"))?;
    Ok(Meta {
        account_id: row.get(0),
        key_generation: row.get(1),
    })
}

fn check_meta(tx: &mut Transaction<'_>, user: &str, expected: &Meta) -> Result<()> {
    if vault(tx, user)? != *expected {
        bail!("vault generation changed; restart ceremony");
    }
    Ok(())
}

fn token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn timestamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn credential_id(passkey: &Passkey) -> String {
    URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref())
}

/// A device ID is a public selector, never an authentication factor. The
/// browser-only AES key is deliberately absent from every server data type.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Prf,
    TrustedBrowser,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prf => "prf",
            Self::TrustedBrowser => "trusted_browser",
        }
    }
    fn kdf(self) -> &'static str {
        match self {
            Self::Prf => WRAPPER_KDF,
            Self::TrustedBrowser => DEVICE_WRAPPER_KDF,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
struct Binding {
    mode: Mode,
    device_id: Option<String>,
}

impl Binding {
    fn checked(config: &Config, mode: Mode, device_id: Option<String>) -> Result<Self> {
        match mode {
            Mode::Prf if device_id.is_none() => {}
            Mode::TrustedBrowser if config.trusted_browser => {
                let id = device_id
                    .as_deref()
                    .ok_or_else(|| anyhow!("device ID required"))?;
                let uuid = Uuid::parse_str(id)?;
                if uuid.get_version_num() != 4
                    || uuid.get_variant() != uuid::Variant::RFC4122
                    || uuid.to_string() != id
                {
                    bail!("canonical random device UUID required");
                }
            }
            _ => bail!("unlock mode unavailable or invalid device binding"),
        }
        Ok(Self { mode, device_id })
    }

    fn check(&self, config: &Config, mode: Mode, device_id: Option<String>) -> Result<()> {
        if *self != Self::checked(config, mode, device_id)? {
            bail!("unlock mode or device mismatch");
        }
        Ok(())
    }

    fn decorate(&self, response: &mut Value) {
        response["mode"] = json!(self.mode);
        if let Some(device_id) = &self.device_id {
            response["device_id"] = json!(device_id);
        }
    }

    fn from_row(row: &Row) -> Result<Self> {
        Ok(Self {
            mode: serde_json::from_value(json!(row.get::<_, String>(5)))?,
            device_id: row.get(6),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct PendingRegistration {
    #[serde(default)]
    binding: Binding,
    registration: PasskeyRegistration,
    label: String,
}

#[derive(Serialize, Deserialize)]
struct PendingAssertion {
    #[serde(default)]
    binding: Binding,
    authentication: PasskeyAuthentication,
    passkey: Passkey,
    label: String,
    prf_salt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartRegistration {
    label: String,
    #[serde(default)]
    mode: Mode,
    device_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectCredential {
    credential_id: String,
    #[serde(default)]
    mode: Mode,
    device_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    ceremony_id: String,
    #[serde(default)]
    mode: Mode,
    device_id: Option<String>,
    credential: Value,
    #[serde(default)]
    wrapper: Option<Wrapper>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapper {
    version: u32,
    kdf: String,
    wrapped_urk: String,
    nonce: String,
}

impl Wrapper {
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || ![WRAPPER_KDF, DEVICE_WRAPPER_KDF].contains(&self.kdf.as_str())
            || canonical_bytes(&self.wrapped_urk)?.len() != 48
            || canonical_bytes(&self.nonce)?.len() != 12
        {
            bail!("invalid passkey wrapper");
        }
        Ok(())
    }
}

fn canonical_bytes(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        bail!("noncanonical base64url");
    }
    Ok(bytes)
}

/// Reject secret-bearing extension data rather than silently retaining it in
/// server-side state or logs. Only public, unsigned capability hints are accepted:
/// PRF support, and registration-only credential properties. Neither is used as
/// proof of user verification or authenticator security.
fn validate_credential(value: &Value, account_id: Option<&str>) -> Result<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("invalid credential"))?;
    for key in obj.keys() {
        if !["id", "rawId", "type", "response", "clientExtensionResults"].contains(&key.as_str()) {
            bail!("unsupported credential field");
        }
    }
    if value["type"] != "public-key" {
        bail!("invalid credential type");
    }
    let id = value["id"]
        .as_str()
        .ok_or_else(|| anyhow!("missing credential id"))?;
    let raw = value["rawId"]
        .as_str()
        .ok_or_else(|| anyhow!("missing raw credential id"))?;
    if id != raw || !(1..=1024).contains(&canonical_bytes(id)?.len()) {
        bail!("invalid credential id");
    }
    if let Some(extensions) = value.get("clientExtensionResults") {
        let ext = extensions
            .as_object()
            .ok_or_else(|| anyhow!("invalid extensions"))?;
        // Only registration omits the account-handle check. credProps is a
        // registration extension and must not widen the assertion allowlist.
        let registration = account_id.is_none();
        if ext
            .keys()
            .any(|k| k != "prf" && !(registration && k == "credProps"))
        {
            bail!("unsupported client extensions");
        }
        if let Some(props) = ext.get("credProps") {
            let props = props
                .as_object()
                .ok_or_else(|| anyhow!("invalid credential properties"))?;
            if props.keys().any(|k| k != "rk") || props.get("rk").is_some_and(|v| !v.is_boolean()) {
                bail!("invalid credential properties");
            }
        }
        if let Some(prf) = ext.get("prf") {
            let prf = prf
                .as_object()
                .ok_or_else(|| anyhow!("invalid PRF capability"))?;
            if prf.keys().any(|k| k != "enabled")
                || prf.get("enabled").is_some_and(|v| !v.is_boolean())
            {
                bail!("PRF output must remain in the browser");
            }
        }
    }
    let response = value["response"]
        .as_object()
        .ok_or_else(|| anyhow!("invalid response"))?;
    for key in response.keys() {
        if ![
            "clientDataJSON",
            "attestationObject",
            "transports",
            "authenticatorData",
            "signature",
            "userHandle",
        ]
        .contains(&key.as_str())
        {
            bail!("unsupported response field");
        }
    }
    // webauthn-rs verifies RP, origin, challenge, type, UV and signature. The
    // application additionally binds a returned userHandle to the account UUID.
    if let (Some(account), Some(handle)) = (account_id, response.get("userHandle")) {
        if !handle.is_null() {
            let bytes = canonical_bytes(
                handle
                    .as_str()
                    .ok_or_else(|| anyhow!("invalid user handle"))?,
            )?;
            if bytes != Uuid::parse_str(account)?.as_bytes() {
                bail!("credential account mismatch");
            }
        }
    }
    // Reject cross-origin ceremonies explicitly, including non-browser clients.
    let client_data = canonical_bytes(
        response
            .get("clientDataJSON")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing client data"))?,
    )?;
    let data: Value = serde_json::from_slice(&client_data)?;
    if data
        .get("crossOrigin")
        .is_some_and(|v| v != &Value::Bool(false))
        || data.get("topOrigin").is_some()
    {
        bail!("cross-origin ceremony rejected");
    }
    Ok(())
}

fn save_ceremony<T: Serialize>(
    tx: &mut Transaction<'_>,
    config: &Config,
    user: &str,
    token: &str,
    meta: &Meta,
    kind: &str,
    state: &T,
) -> Result<String> {
    tx.execute(
        r#"DELETE FROM vault_passkey_ceremonies WHERE "user"=$1 AND expires_at <= $2"#,
        &[&user, &now()],
    )?;
    let count: i64 = tx
        .query_one(
            r#"SELECT COUNT(*) FROM vault_passkey_ceremonies WHERE "user"=$1"#,
            &[&user],
        )?
        .get(0);
    if count >= MAX_PENDING {
        bail!("too many pending passkey ceremonies; retry in five minutes");
    }
    let id = Uuid::new_v4().to_string();
    tx.execute(
        r#"INSERT INTO vault_passkey_ceremonies
        (id,"user",session_hash,account_id,key_generation,rp_id,origin,kind,state,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
        &[
            &id,
            &user,
            &token_hash(token),
            &meta.account_id,
            &meta.key_generation,
            &config.rp_id,
            &config.origin,
            &kind,
            &serde_json::to_string(state)?,
            &(now() + TTL_SECONDS),
        ],
    )?;
    Ok(id)
}

/// DELETE RETURNING is committed before parsing/verifying the submitted
/// credential, so both failed verification and successful use consume the ID.
fn take_ceremony<T: serde::de::DeserializeOwned>(
    repo: &BlobRepo,
    config: &Config,
    user: &str,
    token: &str,
    id: &str,
    kind: &str,
) -> Result<(Meta, T)> {
    Uuid::parse_str(id)?;
    let row = repo
        .lock()
        .query_opt(
            r#"DELETE FROM vault_passkey_ceremonies
        WHERE id=$1 AND "user"=$2 AND session_hash=$3 AND kind=$4
        RETURNING account_id,key_generation,rp_id,origin,state,expires_at"#,
            &[&id, &user, &token_hash(token), &kind],
        )?
        .ok_or_else(|| anyhow!("ceremony expired, consumed, or unavailable"))?;
    if row.get::<_, i64>(5) <= now()
        || row.get::<_, String>(2) != config.rp_id
        || row.get::<_, String>(3) != config.origin
    {
        bail!("ceremony expired or configuration changed");
    }
    Ok((
        Meta {
            account_id: row.get(0),
            key_generation: row.get(1),
        },
        serde_json::from_str(&row.get::<_, String>(4))?,
    ))
}

fn envelope(config: &Config, meta: &Meta, ceremony: &str, public_key: Value) -> Value {
    json!({"ceremony_id":ceremony,"public_key":public_key,"rp_id":config.rp_id,"trusted_browser_enabled":config.trusted_browser,
        "account_id":meta.account_id,"key_generation":meta.key_generation})
}

fn assertion_envelope(
    config: &Config,
    meta: &Meta,
    ceremony: &str,
    public_key: Value,
    state: &PendingAssertion,
) -> Value {
    let mut response = envelope(config, meta, ceremony, public_key);
    response["credential_id"] = json!(credential_id(&state.passkey));
    state.binding.decorate(&mut response);
    if state.binding.mode == Mode::Prf {
        response["prf_salt"] = json!(state.prf_salt);
    }
    response
}

fn current_credential(
    tx: &mut Transaction<'_>,
    config: &Config,
    user: &str,
    meta: &Meta,
    id: &str,
) -> Result<Row> {
    tx.query_opt(
        r#"SELECT passkey,label,prf_salt,wrapper,sign_count,mode,device_id FROM vault_passkeys
        WHERE credential_id=$1 AND "user"=$2 AND account_id=$3 AND key_generation=$4
        AND rp_id=$5 AND origin=$6 FOR UPDATE"#,
        &[
            &id,
            &user,
            &meta.account_id,
            &meta.key_generation,
            &config.rp_id,
            &config.origin,
        ],
    )?
    .ok_or_else(|| anyhow!("passkey unavailable for this account and vault generation"))
}

fn list(repo: &BlobRepo, config: &Config, user: &str) -> Result<Value> {
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    let exists = tx
        .query_opt(r#"SELECT 1 FROM vault WHERE "user"=$1"#, &[&user])?
        .is_some();
    if !exists {
        return Ok(
            json!({"enabled":true,"trusted_browser_enabled":config.trusted_browser,"rp_id":config.rp_id,"origin":config.origin,"credentials":[]}),
        );
    }
    let meta = vault(&mut tx, user)?;
    let rows = tx.query(
        r#"SELECT credential_id,label,created_at,last_used_at,prf_salt,mode,device_id
        FROM vault_passkeys WHERE "user"=$1 AND account_id=$2 AND key_generation=$3
        AND rp_id=$4 AND origin=$5 ORDER BY created_at,credential_id"#,
        &[
            &user,
            &meta.account_id,
            &meta.key_generation,
            &config.rp_id,
            &config.origin,
        ],
    )?;
    let credentials: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let mode: String = r.get(5);
            let mut entry = json!({
                "credential_id":r.get::<_, String>(0),"label":r.get::<_, String>(1),
                "created_at":r.get::<_, String>(2),"last_used_at":r.get::<_, Option<String>>(3),
                "mode":mode,"key_generation":meta.key_generation,
            });
            if mode == "prf" {
                entry["prf_salt"] = json!(r.get::<_, String>(4));
            } else {
                entry["device_id"] = json!(r.get::<_, Option<String>>(6));
            }
            entry
        })
        .collect();
    tx.commit()?;
    Ok(
        json!({"enabled":true,"trusted_browser_enabled":config.trusted_browser,"rp_id":config.rp_id,"origin":config.origin,
        "account_id":meta.account_id,"key_generation":meta.key_generation,"credentials":credentials}),
    )
}

fn register_start(
    repo: &BlobRepo,
    config: &Config,
    user: &str,
    token: &str,
    body: &str,
) -> Result<Value> {
    let input: StartRegistration = serde_json::from_str(body)?;
    let binding = Binding::checked(config, input.mode, input.device_id)?;
    let label = input.label.trim();
    if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
        bail!("label must be 1 to 80 characters");
    }
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    let meta = vault(&mut tx, user)?;
    let rows = tx.query(
        r#"SELECT passkey FROM vault_passkeys WHERE "user"=$1"#,
        &[&user],
    )?;
    if rows.len() as i64 >= MAX_CREDENTIALS {
        bail!("passkey limit reached");
    }
    let exclude: Vec<CredentialID> = rows
        .into_iter()
        .map(|row| {
            serde_json::from_str::<Passkey>(&row.get::<_, String>(0)).map(|p| p.cred_id().clone())
        })
        .collect::<std::result::Result<_, _>>()?;
    let (options, registration) = config.webauthn.start_passkey_registration(
        Uuid::parse_str(&meta.account_id)?,
        user,
        user,
        Some(exclude),
    )?;
    let id = save_ceremony(
        &mut tx,
        config,
        user,
        token,
        &meta,
        "register",
        &PendingRegistration {
            binding: binding.clone(),
            registration,
            label: label.into(),
        },
    )?;
    tx.commit()?;
    let mut public_key = serde_json::to_value(options)?["publicKey"].clone();
    // Advertise only client extension outputs that this API accepts. The
    // library defaults also request UVM/credProtect; those are unnecessary for
    // PRF unlock and may expose additional device information. Its server-side
    // state permits ignored extensions; UV remains required independently.
    public_key["extensions"] = match binding.mode {
        Mode::Prf => json!({"prf":{},"credProps":true}),
        Mode::TrustedBrowser => json!({"credProps":true}),
    };
    let mut response = envelope(config, &meta, &id, public_key);
    binding.decorate(&mut response);
    Ok(response)
}

fn register_finish(
    repo: &BlobRepo,
    config: &Config,
    user: &str,
    token: &str,
    body: &str,
) -> Result<Value> {
    let input: Finish = serde_json::from_str(body)?;
    let (meta, pending) = take_ceremony::<PendingRegistration>(
        repo,
        config,
        user,
        token,
        &input.ceremony_id,
        "register",
    )?;
    pending.binding.check(config, input.mode, input.device_id)?;
    if input.wrapper.is_some() {
        bail!("wrapper is only accepted after verified assertion");
    }
    validate_credential(&input.credential, None)?;
    let registration: RegisterPublicKeyCredential = serde_json::from_value(input.credential)?;
    let passkey = config
        .webauthn
        .finish_passkey_registration(&registration, &pending.registration)?;
    let id = credential_id(&passkey);
    if registration.id != id {
        bail!("attested credential id mismatch");
    }
    let (options, authentication) = config
        .webauthn
        .start_passkey_authentication(std::slice::from_ref(&passkey))?;
    // 256-bit server-generated public PRF input; the output is never transmitted.
    let prf_salt = URL_SAFE_NO_PAD.encode(Sha256::digest(
        respire::memory::crypto::random_hex(32).as_bytes(),
    ));
    let state = PendingAssertion {
        binding: pending.binding,
        authentication,
        passkey,
        label: pending.label,
        prf_salt: if input.mode == Mode::Prf {
            prf_salt
        } else {
            String::new()
        },
    };
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    check_meta(&mut tx, user, &meta)?;
    if tx
        .query_opt(
            "SELECT 1 FROM vault_passkeys WHERE credential_id=$1",
            &[&id],
        )?
        .is_some()
    {
        bail!("credential already registered");
    }
    let ceremony = save_ceremony(&mut tx, config, user, token, &meta, "test", &state)?;
    tx.commit()?;
    Ok(assertion_envelope(
        config,
        &meta,
        &ceremony,
        serde_json::to_value(options)?["publicKey"].clone(),
        &state,
    ))
}

fn register_test(
    repo: &BlobRepo,
    config: &Config,
    user: &str,
    token: &str,
    body: &str,
) -> Result<Value> {
    let input: Finish = serde_json::from_str(body)?;
    let (meta, mut state) =
        take_ceremony::<PendingAssertion>(repo, config, user, token, &input.ceremony_id, "test")?;
    state.binding.check(config, input.mode, input.device_id)?;
    if input.wrapper.is_some() {
        bail!("wrapper must be tested locally before committing");
    }
    validate_credential(&input.credential, Some(&meta.account_id))?;
    let credential: PublicKeyCredential = serde_json::from_value(input.credential)?;
    let result = config
        .webauthn
        .finish_passkey_authentication(&credential, &state.authentication)?;
    if !result.user_verified()
        || result.cred_id() != state.passkey.cred_id()
        || credential.id != credential_id(&state.passkey)
    {
        bail!("verified credential mismatch");
    }
    state
        .passkey
        .update_credential(&result)
        .ok_or_else(|| anyhow!("credential update mismatch"))?;
    let (options, authentication) = config
        .webauthn
        .start_passkey_authentication(std::slice::from_ref(&state.passkey))?;
    state.authentication = authentication;
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    check_meta(&mut tx, user, &meta)?;
    let id = save_ceremony(&mut tx, config, user, token, &meta, "activate", &state)?;
    tx.commit()?;
    Ok(assertion_envelope(
        config,
        &meta,
        &id,
        serde_json::to_value(options)?["publicKey"].clone(),
        &state,
    ))
}

fn unlock_start(
    repo: &BlobRepo,
    config: &Config,
    user: &str,
    token: &str,
    body: &str,
) -> Result<Value> {
    let input: SelectCredential = serde_json::from_str(body)?;
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    let meta = vault(&mut tx, user)?;
    let row = current_credential(&mut tx, config, user, &meta, &input.credential_id)?;
    let binding = Binding::from_row(&row)?;
    binding.check(config, input.mode, input.device_id)?;
    let passkey: Passkey = serde_json::from_str(&row.get::<_, String>(0))?;
    let (options, authentication) = config
        .webauthn
        .start_passkey_authentication(std::slice::from_ref(&passkey))?;
    let state = PendingAssertion {
        binding,
        authentication,
        passkey,
        label: row.get(1),
        prf_salt: row.get(2),
    };
    let id = save_ceremony(&mut tx, config, user, token, &meta, "unlock", &state)?;
    tx.commit()?;
    Ok(assertion_envelope(
        config,
        &meta,
        &id,
        serde_json::to_value(options)?["publicKey"].clone(),
        &state,
    ))
}

fn assertion_finish(
    repo: &BlobRepo,
    config: &Config,
    user: &str,
    token: &str,
    body: &str,
    activate: bool,
) -> Result<Value> {
    let input: Finish = serde_json::from_str(body)?;
    let (meta, mut pending) = take_ceremony::<PendingAssertion>(
        repo,
        config,
        user,
        token,
        &input.ceremony_id,
        if activate { "activate" } else { "unlock" },
    )?;
    pending.binding.check(config, input.mode, input.device_id)?;
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
    pending
        .passkey
        .update_credential(&result)
        .ok_or_else(|| anyhow!("credential update mismatch"))?;
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    check_meta(&mut tx, user, &meta)?;
    let wrapper = if activate {
        let wrapper = input.wrapper.ok_or_else(|| anyhow!("wrapper required"))?;
        wrapper.validate()?;
        if wrapper.kdf != pending.binding.mode.kdf() {
            bail!("wrapper does not match unlock mode");
        }
        let count: i64 = tx
            .query_one(
                r#"SELECT COUNT(*) FROM vault_passkeys WHERE "user"=$1"#,
                &[&user],
            )?
            .get(0);
        if count >= MAX_CREDENTIALS {
            bail!("passkey limit reached");
        }
        let inserted = tx.execute(r#"INSERT INTO vault_passkeys
            (credential_id,"user",account_id,rp_id,origin,key_generation,label,passkey,prf_salt,wrapper,created_at,last_used_at,sign_count,mode,device_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12,$13,$14) ON CONFLICT (credential_id) DO NOTHING"#,
            &[&id,&user,&meta.account_id,&config.rp_id,&config.origin,&meta.key_generation,
              &pending.label,&serde_json::to_string(&pending.passkey)?,&pending.prf_salt,
              &serde_json::to_string(&wrapper)?,&timestamp(),&i64::from(result.counter()),
              &pending.binding.mode.as_str(),&pending.binding.device_id])?;
        if inserted != 1 {
            bail!("credential already registered");
        }
        wrapper
    } else {
        if input.wrapper.is_some() {
            bail!("unlock cannot replace a wrapper");
        }
        let row = current_credential(&mut tx, config, user, &meta, &id)?;
        if Binding::from_row(&row)? != pending.binding {
            bail!("credential mode or device changed");
        }
        let old_count: i64 = row.get(4);
        let new_count = i64::from(result.counter());
        if (old_count != 0 || new_count != 0) && new_count <= old_count {
            bail!("authenticator counter did not advance");
        }
        let mut current: Passkey = serde_json::from_str(&row.get::<_, String>(0))?;
        current
            .update_credential(&result)
            .ok_or_else(|| anyhow!("credential update mismatch"))?;
        tx.execute("UPDATE vault_passkeys SET passkey=$2,last_used_at=$3,sign_count=$4 WHERE credential_id=$1",
            &[&id,&serde_json::to_string(&current)?,&timestamp(),&new_count])?;
        serde_json::from_str::<Wrapper>(&row.get::<_, String>(3))?
    };
    tx.commit()?;
    if activate {
        return Ok(json!({"ok":true}));
    }
    let mut response = json!({"wrapper":wrapper,"credential_id":id,
        "rp_id":config.rp_id,"account_id":meta.account_id,"key_generation":meta.key_generation});
    pending.binding.decorate(&mut response);
    if pending.binding.mode == Mode::Prf {
        response["prf_salt"] = json!(pending.prf_salt);
    }
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveCredential {
    credential_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelCeremony {
    ceremony_id: String,
}

fn cancel(repo: &BlobRepo, user: &str, token: &str, body: &str) -> Result<Value> {
    let input: CancelCeremony = serde_json::from_str(body)?;
    Uuid::parse_str(&input.ceremony_id)?;
    // Cancellation only removes pending state. An in-flight commit can already
    // have consumed it; this response must not imply activation was prevented.
    repo.lock().execute(
        r#"DELETE FROM vault_passkey_ceremonies WHERE id=$1 AND "user"=$2 AND session_hash=$3"#,
        &[&input.ceremony_id, &user, &token_hash(token)],
    )?;
    Ok(json!({"ok":true}))
}

fn remove(repo: &BlobRepo, user: &str, body: &str) -> Result<Value> {
    let input: RemoveCredential = serde_json::from_str(body)?;
    let mut client = repo.lock();
    let mut tx = client.transaction()?;
    vault(&mut tx, user)?;
    let removed = tx.execute(
        r#"DELETE FROM vault_passkeys WHERE credential_id=$1 AND "user"=$2"#,
        &[&input.credential_id, &user],
    )?;
    if removed != 1 {
        bail!("passkey unavailable");
    }
    // Also revoke in-flight assertions; a removed key can never release a wrapper.
    tx.execute(
        r#"DELETE FROM vault_passkey_ceremonies WHERE "user"=$1"#,
        &[&user],
    )?;
    tx.commit()?;
    Ok(json!({"ok":true}))
}

pub(super) fn route(
    repo: &BlobRepo,
    method: &str,
    path: &str,
    body: &str,
    user: &str,
    token: &str,
) -> Option<(u16, String)> {
    let suffix = path.strip_prefix("/api/self/passkeys")?;
    if !suffix.is_empty() && !suffix.starts_with('/') {
        return None;
    }
    let config = match Config::from_env() {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Some(super::json::json(
                if method == "GET" && suffix.is_empty() {
                    200
                } else {
                    404
                },
                json!({"enabled":false,"trusted_browser_enabled":false,"credentials":[],"error":"passkey unlock is disabled"}),
            ))
        }
        Err(_) => {
            return Some(super::json::json(
                503,
                json!({"error":"passkey configuration unavailable"}),
            ))
        }
    };
    Some(route_config(
        repo, &config, method, suffix, body, user, token,
    ))
}

fn route_config(
    repo: &BlobRepo,
    config: &Config,
    method: &str,
    suffix: &str,
    body: &str,
    user: &str,
    token: &str,
) -> (u16, String) {
    if body.len() > 128 * 1024 {
        return super::json::json(413, json!({"error":"passkey request too large"}));
    }
    let result = match (method, suffix) {
        ("GET", "") => list(repo, config, user),
        ("POST", "/register/start") => register_start(repo, config, user, token, body),
        ("POST", "/register/finish") => register_finish(repo, config, user, token, body),
        ("POST", "/register/test") => register_test(repo, config, user, token, body),
        ("POST", "/register/commit") => assertion_finish(repo, config, user, token, body, true),
        ("POST", "/unlock/start") => unlock_start(repo, config, user, token, body),
        ("POST", "/unlock/finish") => assertion_finish(repo, config, user, token, body, false),
        ("POST", "/remove") => remove(repo, user, body),
        ("POST", "/cancel") => cancel(repo, user, token, body),
        _ => return super::json::json(404, json!({"error":"not found"})),
    };
    match result {
        Ok(value) => super::json::json(200, value),
        Err(error) if error.is::<postgres::Error>() => super::json::server_error(error),
        // Do not echo submitted credentials, extension outputs, or library error details.
        Err(_) => super::json::json(
            400,
            json!({"error":"passkey operation rejected; restart and try again"}),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use webauthn_authenticator_rs::{softpasskey::SoftPasskey, WebauthnAuthenticator};

    type Authenticator = WebauthnAuthenticator<SoftPasskey>;
    const USER: &str = "passkey-user";
    const TOKEN: &str = "synthetic-session";

    fn fixture() -> Result<(BlobRepo, Config, Authenticator)> {
        let repo = crate::store::connect_unique()?;
        repo.register(USER, "hash", "salt")?
            .context("register fixture")?;
        repo.put_vault(USER, "0011223344556677", "opaque-original-urk", "nonce", 4)?;
        Ok((
            repo,
            Config::new("dash.example.com", "https://dash.example.com")?,
            WebauthnAuthenticator::new(SoftPasskey::new(true)),
        ))
    }

    fn clean_credential<T: Serialize>(value: T) -> Result<Value> {
        let mut value = serde_json::to_value(value)?;
        value
            .as_object_mut()
            .context("credential object")?
            .remove("extensions");
        value["clientExtensionResults"] = json!({"prf":{"enabled":true}});
        Ok(value)
    }

    fn make_registration(
        auth: &mut Authenticator,
        config: &Config,
        options: &Value,
    ) -> Result<Value> {
        let options: CreationChallengeResponse =
            serde_json::from_value(json!({"publicKey":options["public_key"]}))?;
        clean_credential(
            auth.do_registration(Url::parse(&config.origin)?, options)
                .map_err(|e| anyhow!("synthetic registration failed: {e:?}"))?,
        )
    }

    fn make_assertion(auth: &mut Authenticator, config: &Config, options: &Value) -> Result<Value> {
        let options: RequestChallengeResponse =
            serde_json::from_value(json!({"publicKey":options["public_key"]}))?;
        clean_credential(
            auth.do_authentication(Url::parse(&config.origin)?, options)
                .map_err(|e| anyhow!("synthetic authentication failed: {e:?}"))?,
        )
    }

    fn finish_body(envelope: &Value, credential: Value) -> Value {
        json!({"ceremony_id":envelope["ceremony_id"],"credential":credential})
    }

    fn wrapper() -> Wrapper {
        Wrapper {
            version: 1,
            kdf: WRAPPER_KDF.into(),
            wrapped_urk: URL_SAFE_NO_PAD.encode([7u8; 48]),
            nonce: URL_SAFE_NO_PAD.encode([8u8; 12]),
        }
    }

    fn pending_test(repo: &BlobRepo, config: &Config, auth: &mut Authenticator) -> Result<Value> {
        let options = register_start(repo, config, USER, TOKEN, r#"{"label":"Test key"}"#)?;
        let credential = make_registration(auth, config, &options)?;
        register_finish(
            repo,
            config,
            USER,
            TOKEN,
            &finish_body(&options, credential).to_string(),
        )
    }

    fn enroll(repo: &BlobRepo, config: &Config, auth: &mut Authenticator) -> Result<Value> {
        let test = pending_test(repo, config, auth)?;
        let credential = make_assertion(auth, config, &test)?;
        let activate = register_test(
            repo,
            config,
            USER,
            TOKEN,
            &finish_body(&test, credential).to_string(),
        )?;
        let credential = make_assertion(auth, config, &activate)?;
        let mut input = finish_body(&activate, credential);
        input["wrapper"] = serde_json::to_value(wrapper())?;
        assert_eq!(
            assertion_finish(repo, config, USER, TOKEN, &input.to_string(), true)?,
            json!({"ok":true})
        );
        Ok(activate)
    }

    fn select(envelope: &Value) -> String {
        json!({"credential_id":envelope["credential_id"]}).to_string()
    }

    fn change_client_data(credential: &mut Value, field: &str, value: Value) -> Result<()> {
        let mut data: Value = serde_json::from_slice(&canonical_bytes(
            credential["response"]["clientDataJSON"]
                .as_str()
                .context("client data")?,
        )?)?;
        data[field] = value;
        credential["response"]["clientDataJSON"] =
            json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&data)?));
        Ok(())
    }

    const DEVICE: &str = "11111111-2222-4333-8444-555555555555";

    fn trusted_body(envelope: &Value, mut credential: Value) -> Value {
        credential["clientExtensionResults"] = json!({});
        let mut body = finish_body(envelope, credential);
        body["mode"] = json!("trusted_browser");
        body["device_id"] = envelope["device_id"].clone();
        body
    }
    fn trusted_select(envelope: &Value) -> String {
        json!({"credential_id":envelope["credential_id"],"mode":"trusted_browser",
            "device_id":envelope["device_id"]})
        .to_string()
    }
    fn trusted_wrapper() -> Wrapper {
        Wrapper {
            kdf: DEVICE_WRAPPER_KDF.into(),
            ..wrapper()
        }
    }
    fn trusted_pending(
        repo: &BlobRepo,
        config: &Config,
        auth: &mut Authenticator,
    ) -> Result<Value> {
        let start = register_start(
            repo,
            config,
            USER,
            TOKEN,
            &json!({"label":"This browser","mode":"trusted_browser","device_id":DEVICE})
                .to_string(),
        )?;
        assert_eq!(start["public_key"]["extensions"], json!({"credProps":true}));
        assert_eq!(start["mode"], "trusted_browser");
        assert_eq!(start["device_id"], DEVICE);
        let credential = make_registration(auth, config, &start)?;
        register_finish(
            repo,
            config,
            USER,
            TOKEN,
            &trusted_body(&start, credential).to_string(),
        )
    }
    fn trusted_activate(
        repo: &BlobRepo,
        config: &Config,
        auth: &mut Authenticator,
    ) -> Result<Value> {
        let test = trusted_pending(repo, config, auth)?;
        assert!(test.get("prf_salt").is_none());
        let credential = make_assertion(auth, config, &test)?;
        let activate = register_test(
            repo,
            config,
            USER,
            TOKEN,
            &trusted_body(&test, credential).to_string(),
        )?;
        assert_ne!(
            activate["public_key"]["challenge"],
            test["public_key"]["challenge"]
        );
        Ok(activate)
    }
    fn trusted_enroll(repo: &BlobRepo, config: &Config, auth: &mut Authenticator) -> Result<Value> {
        let activate = trusted_activate(repo, config, auth)?;
        let credential = make_assertion(auth, config, &activate)?;
        let mut body = trusted_body(&activate, credential);
        body["wrapper"] = serde_json::to_value(trusted_wrapper())?;
        assertion_finish(repo, config, USER, TOKEN, &body.to_string(), true)?;
        assert!(assertion_finish(repo, config, USER, TOKEN, &body.to_string(), true).is_err());
        Ok(activate)
    }

    #[test]
    fn trusted_browser_explicit_opt_in_and_canonical_device_binding() -> Result<()> {
        let (repo, mut config, _) = fixture()?;
        let valid = json!({"label":"Browser","mode":"trusted_browser","device_id":DEVICE});
        assert!(!list(&repo, &config, USER)?["trusted_browser_enabled"]
            .as_bool()
            .context("flag")?);
        assert!(register_start(&repo, &config, USER, TOKEN, &valid.to_string()).is_err());
        config.trusted_browser = true;
        for (mode, device) in [
            ("unknown", json!(DEVICE)),
            ("prf", json!(DEVICE)),
            ("trusted_browser", Value::Null),
            ("trusted_browser", json!("bad")),
            (
                "trusted_browser",
                json!("11111111-2222-1333-8444-555555555555"),
            ),
            (
                "trusted_browser",
                json!("11111111-2222-4333-7444-555555555555"),
            ),
            (
                "trusted_browser",
                json!("AAAAAAAA-2222-4333-8444-555555555555"),
            ),
        ] {
            assert!(register_start(
                &repo,
                &config,
                USER,
                TOKEN,
                &json!({"label":"Browser","mode":mode,"device_id":device}).to_string()
            )
            .is_err());
        }
        register_start(&repo, &config, USER, TOKEN, &valid.to_string())?;
        Ok(())
    }

    #[test]
    fn trusted_browser_without_prf_keeps_recovery_and_requires_two_fresh_assertions() -> Result<()>
    {
        let (repo, mut config, mut auth) = fixture()?;
        config.trusted_browser = true;
        let recovery = repo.get_vault(USER)?;
        let test = trusted_pending(&repo, &config, &mut auth)?;
        let mut skip = trusted_body(&test, make_assertion(&mut auth, &config, &test)?);
        skip["wrapper"] = serde_json::to_value(trusted_wrapper())?;
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &skip.to_string(), true).is_err());
        skip.as_object_mut().context("body")?.remove("wrapper");
        let activate = register_test(&repo, &config, USER, TOKEN, &skip.to_string())?;
        assert!(register_test(&repo, &config, USER, TOKEN, &skip.to_string()).is_err());
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        let mut commit = trusted_body(&activate, make_assertion(&mut auth, &config, &activate)?);
        commit["wrapper"] = serde_json::to_value(trusted_wrapper())?;
        assertion_finish(&repo, &config, USER, TOKEN, &commit.to_string(), true)?;
        let listed = list(&repo, &config, USER)?;
        assert_eq!(listed["credentials"][0]["mode"], "trusted_browser");
        assert_eq!(listed["credentials"][0]["device_id"], DEVICE);
        assert!(listed["credentials"][0].get("prf_salt").is_none());
        assert!(!listed.to_string().contains("wrapped_urk"));
        let options = unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&activate))?;
        let body = trusted_body(&options, make_assertion(&mut auth, &config, &options)?);
        let released = assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), false)?;
        assert_eq!(
            released["wrapper"],
            serde_json::to_value(trusted_wrapper())?
        );
        for key in [
            "account_id",
            "rp_id",
            "credential_id",
            "key_generation",
            "mode",
            "device_id",
        ] {
            assert_eq!(released[key], activate[key], "{key}");
        }
        assert!(released.get("prf_salt").is_none());
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), false).is_err());
        assert_eq!(repo.get_vault(USER)?, recovery);
        config.trusted_browser = false;
        assert!(unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&activate)).is_err());
        // Disabling enrollment/unlock never blocks account-owner revocation.
        remove(&repo, USER, &select(&activate))?;
        Ok(())
    }

    #[test]
    fn trusted_mode_cannot_be_switched_or_commit_prf_wrappers() -> Result<()> {
        let (repo, mut config, mut auth) = fixture()?;
        config.trusted_browser = true;
        for stage in 0..4 {
            let envelope = if stage == 0 {
                register_start(
                    &repo,
                    &config,
                    USER,
                    TOKEN,
                    &json!({"label":"Browser","mode":"trusted_browser","device_id":DEVICE})
                        .to_string(),
                )?
            } else if stage == 1 {
                trusted_pending(&repo, &config, &mut auth)?
            } else {
                trusted_activate(&repo, &config, &mut auth)?
            };
            let credential = if stage == 0 {
                make_registration(&mut auth, &config, &envelope)?
            } else {
                make_assertion(&mut auth, &config, &envelope)?
            };
            let mut body = trusted_body(&envelope, credential);
            if stage == 3 {
                body["wrapper"] = serde_json::to_value(wrapper())?;
            } else {
                body["device_id"] = json!(Uuid::new_v4().to_string());
            }
            let result = match stage {
                0 => register_finish(&repo, &config, USER, TOKEN, &body.to_string()),
                1 => register_test(&repo, &config, USER, TOKEN, &body.to_string()),
                _ => assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), true),
            };
            assert!(result.is_err());
        }
        let prf = pending_test(&repo, &config, &mut auth)?;
        // Schema-8 pending state has no binding field; its default stays PRF.
        repo.lock().execute("UPDATE vault_passkey_ceremonies SET state=(state::jsonb - 'binding')::text WHERE id=$1",
            &[&prf["ceremony_id"].as_str().context("ceremony")?])?;
        let activate = register_test(
            &repo,
            &config,
            USER,
            TOKEN,
            &finish_body(&prf, make_assertion(&mut auth, &config, &prf)?).to_string(),
        )?;
        let mut body = finish_body(&activate, make_assertion(&mut auth, &config, &activate)?);
        body["wrapper"] = serde_json::to_value(trusted_wrapper())?;
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), true).is_err());
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        Ok(())
    }

    #[test]
    fn trusted_unlock_enforces_device_account_session_uv_expiry_generation_and_counters(
    ) -> Result<()> {
        let (repo, mut config, mut auth) = fixture()?;
        config.trusted_browser = true;
        let active = trusted_enroll(&repo, &config, &mut auth)?;
        repo.register("other-user", "hash", "salt")?
            .context("other")?;
        repo.put_vault("other-user", "0011223344556677", "other", "n", 4)?;
        assert!(unlock_start(
            &repo,
            &config,
            "other-user",
            TOKEN,
            &trusted_select(&active)
        )
        .is_err());
        assert!(unlock_start(&repo, &config, USER, TOKEN, &select(&active)).is_err());
        let mut wrong: Value = serde_json::from_str(&trusted_select(&active))?;
        wrong["device_id"] = json!(Uuid::new_v4().to_string());
        assert!(unlock_start(&repo, &config, USER, TOKEN, &wrong.to_string()).is_err());
        for kind in 0..7 {
            let mut options = unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&active))?;
            if kind == 0 {
                options["public_key"]["userVerification"] = json!("discouraged");
            }
            let mut body = trusted_body(&options, make_assertion(&mut auth, &config, &options)?);
            if kind == 1 {
                // A correctly bound, signed request must still belong to this
                // account/session; foreign attempts must not consume it.
                assert!(assertion_finish(
                    &repo,
                    &config,
                    "other-user",
                    TOKEN,
                    &body.to_string(),
                    false
                )
                .is_err());
                assert!(assertion_finish(
                    &repo,
                    &config,
                    USER,
                    "other-session",
                    &body.to_string(),
                    false
                )
                .is_err());
            }
            match kind {
                1 => body["device_id"] = json!(Uuid::new_v4().to_string()),
                2 => {
                    body["mode"] = json!("prf");
                    body.as_object_mut().context("body")?.remove("device_id");
                }
                3 => {
                    repo.lock().execute(
                        "UPDATE vault_passkey_ceremonies SET expires_at=$1",
                        &[&now()],
                    )?;
                }
                4 => {
                    repo.lock()
                        .execute("UPDATE vault_passkey_ceremonies SET key_generation=0", &[])?;
                }
                5 => {
                    body["credential"]["id"] = json!(URL_SAFE_NO_PAD.encode([1; 32]));
                    body["credential"]["rawId"] = body["credential"]["id"].clone();
                }
                6 => {
                    config.trusted_browser = false;
                }
                _ => {}
            }
            assert!(
                assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), false).is_err(),
                "{kind}"
            );
            config.trusted_browser = true;
            body["mode"] = json!("trusted_browser");
            body["device_id"] = json!(DEVICE);
            assert!(
                assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), false).is_err()
            );
        }
        let a = unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&active))?;
        let b = unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&active))?;
        let first = trusted_body(&a, make_assertion(&mut auth, &config, &a)?);
        let second = trusted_body(&b, make_assertion(&mut auth, &config, &b)?);
        assertion_finish(&repo, &config, USER, TOKEN, &second.to_string(), false)?;
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &first.to_string(), false).is_err());
        Ok(())
    }

    #[test]
    fn trusted_cancel_is_session_scoped_and_never_claims_commit_rollback() -> Result<()> {
        let (repo, mut config, mut auth) = fixture()?;
        config.trusted_browser = true;
        for phase in 0..3 {
            let options = if phase == 0 {
                trusted_pending(&repo, &config, &mut auth)?
            } else {
                trusted_activate(&repo, &config, &mut auth)?
            };
            let cancel_body = json!({"ceremony_id":options["ceremony_id"]}).to_string();
            cancel(&repo, "other-user", TOKEN, &cancel_body)?;
            cancel(&repo, USER, "other-session", &cancel_body)?;
            let mut body = trusted_body(&options, make_assertion(&mut auth, &config, &options)?);
            if phase == 2 {
                body["wrapper"] = serde_json::to_value(trusted_wrapper())?;
                assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), true)?;
            }
            cancel(&repo, USER, TOKEN, &cancel_body)?;
            cancel(&repo, USER, TOKEN, &cancel_body)?;
            assert!(register_test(&repo, &config, USER, TOKEN, &body.to_string()).is_err());
            assert!(
                assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), true).is_err()
            );
        }
        assert_eq!(
            list(&repo, &config, USER)?["credentials"]
                .as_array()
                .context("list")?
                .len(),
            1,
            "cancel after committed activation must not silently revoke a key"
        );
        Ok(())
    }

    #[test]
    fn trusted_rewrap_preserves_and_reset_or_removal_revokes_pending_unlocks() -> Result<()> {
        let (repo, mut config, mut auth) = fixture()?;
        config.trusted_browser = true;
        for operation in 0..3 {
            let active = trusted_enroll(&repo, &config, &mut auth)?;
            let generation = active["key_generation"].as_i64().context("generation")?;
            repo.write_vault_operation(
                USER,
                "0011223344556677",
                "same-urk-rewrapped",
                "n",
                4,
                false,
                true,
                Some(generation),
                false,
            )?;
            let options = unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&active))?;
            let body = trusted_body(&options, make_assertion(&mut auth, &config, &options)?);
            assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), false)?;
            let options = unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&active))?;
            let body = trusted_body(&options, make_assertion(&mut auth, &config, &options)?);
            match operation {
                0 => {
                    remove(&repo, USER, &select(&active))?;
                }
                1 => {
                    repo.write_vault_operation(
                        USER,
                        "0011223344556677",
                        "new-urk",
                        "n",
                        4,
                        false,
                        false,
                        Some(generation),
                        true,
                    )?;
                }
                _ => {
                    repo.put_vault(USER, "0011223344556677", "legacy-new-urk", "n", 4)?;
                }
            }
            assert!(
                assertion_finish(&repo, &config, USER, TOKEN, &body.to_string(), false).is_err()
            );
            assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        }
        Ok(())
    }

    #[test]
    fn trusted_pending_and_active_resource_caps_are_shared_with_prf() -> Result<()> {
        let (repo, mut config, mut auth) = fixture()?;
        config.trusted_browser = true;
        let active = trusted_enroll(&repo, &config, &mut auth)?;
        for _ in 0..MAX_PENDING {
            unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&active))?;
        }
        assert!(unlock_start(&repo, &config, USER, TOKEN, &trusted_select(&active)).is_err());
        assert!(register_start(&repo, &config, USER, TOKEN, r#"{"label":"PRF"}"#).is_err());
        repo.lock()
            .execute("DELETE FROM vault_passkey_ceremonies", &[])?;
        // Synthetic rows exercise the shared account limit without 20 ceremonies.
        repo.lock().execute(r#"INSERT INTO vault_passkeys
            (credential_id,"user",account_id,rp_id,origin,key_generation,label,passkey,prf_salt,wrapper,created_at,mode,device_id)
            SELECT credential_id || n::text,"user",account_id,rp_id,origin,key_generation,label,passkey,prf_salt,wrapper,created_at,mode,device_id
            FROM vault_passkeys CROSS JOIN generate_series(1,19) AS n"#, &[])?;
        assert!(register_start(
            &repo,
            &config,
            USER,
            TOKEN,
            &json!({"label":"Overflow","mode":"trusted_browser","device_id":DEVICE}).to_string()
        )
        .is_err());
        assert!(register_start(&repo, &config, USER, TOKEN, r#"{"label":"PRF"}"#).is_err());
        Ok(())
    }

    #[test]
    fn config_requires_explicit_exact_https_origin() -> Result<()> {
        Config::new("dash.example.com", "https://dash.example.com")?;
        for (rp, origin) in [
            ("example.com", "https://dash.example.com"),
            ("dash.example.com", "http://dash.example.com"),
            ("dash.example.com", "https://evil.example.com"),
            ("dash.example.com", "https://dash.example.com/"),
            ("dash.example.com", "https://dash.example.com/path"),
            ("dash.example.com", "https://dash.example.com?x=y"),
            ("dash.example.com", "https://user@dash.example.com"),
            ("", ""),
        ] {
            assert!(Config::new(rp, origin).is_err(), "{rp} {origin}");
        }
        Ok(())
    }

    #[test]
    fn wrappers_validate_version_kdf_and_canonical_lengths() -> Result<()> {
        wrapper().validate()?;
        for kind in 0..6 {
            let mut bad = wrapper();
            match kind {
                0 => bad.version = 2,
                1 => bad.kdf = "different".into(),
                2 => bad.wrapped_urk = URL_SAFE_NO_PAD.encode([7u8; 32]),
                3 => bad.nonce = URL_SAFE_NO_PAD.encode([8u8; 16]),
                4 => bad.nonce.push('='),
                _ => bad.wrapped_urk = "not base64!".into(),
            }
            assert!(bad.validate().is_err());
        }
        let extra = format!(
            r#"{{"version":1,"kdf":"{WRAPPER_KDF}","wrapped_urk":"x","nonce":"y","prf_output":"secret"}}"#
        );
        assert!(serde_json::from_str::<Wrapper>(&extra).is_err());
        Ok(())
    }

    #[test]
    fn registration_requires_two_distinct_assertions_and_roundtrip_commit() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        let original = repo.get_vault(USER)?;
        let test = pending_test(&repo, &config, &mut auth)?;
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        let credential = make_assertion(&mut auth, &config, &test)?;
        let input = finish_body(&test, credential);
        // Neither registration nor the first assertion state can directly commit.
        let mut skipped = input.clone();
        skipped["wrapper"] = serde_json::to_value(wrapper())?;
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &skipped.to_string(), true).is_err());
        let activate = register_test(&repo, &config, USER, TOKEN, &input.to_string())?;
        assert_ne!(
            test["public_key"]["challenge"],
            activate["public_key"]["challenge"]
        );
        assert_eq!(test["prf_salt"], activate["prf_salt"]);
        assert!(register_test(&repo, &config, USER, TOKEN, &input.to_string()).is_err());
        let mut commit = finish_body(&activate, make_assertion(&mut auth, &config, &activate)?);
        commit["wrapper"] = serde_json::to_value(wrapper())?;
        assertion_finish(&repo, &config, USER, TOKEN, &commit.to_string(), true)?;
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &commit.to_string(), true).is_err());
        assert_eq!(
            repo.get_vault(USER)?,
            original,
            "passkeys must never replace recovery wrapper"
        );
        let listed = list(&repo, &config, USER)?;
        assert_eq!(
            listed["credentials"]
                .as_array()
                .context("credentials")?
                .len(),
            1
        );
        assert!(!listed.to_string().contains("wrapped_urk"));
        let options = unlock_start(&repo, &config, USER, TOKEN, &select(&activate))?;
        let input = finish_body(&options, make_assertion(&mut auth, &config, &options)?);
        let unlocked = assertion_finish(&repo, &config, USER, TOKEN, &input.to_string(), false)?;
        assert_eq!(unlocked["wrapper"], serde_json::to_value(wrapper())?);
        assert_eq!(unlocked["account_id"], activate["account_id"]);
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &input.to_string(), false).is_err());
        Ok(())
    }

    #[test]
    fn signed_assertions_reject_origin_challenge_rp_uv_signature_and_account_handle() -> Result<()>
    {
        let (repo, config, mut auth) = fixture()?;
        let active = enroll(&repo, &config, &mut auth)?;
        for kind in 0..9 {
            let mut options = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
            // This is a correctly signed assertion without the required UV bit.
            if kind == 0 {
                options["public_key"]["userVerification"] = json!("discouraged");
            }
            let mut credential = make_assertion(&mut auth, &config, &options)?;
            match kind {
                0 => {}
                1 => change_client_data(
                    &mut credential,
                    "origin",
                    json!("https://evil.example.com"),
                )?,
                2 => change_client_data(
                    &mut credential,
                    "challenge",
                    json!(URL_SAFE_NO_PAD.encode([0u8; 32])),
                )?,
                3 => {
                    let mut bytes = canonical_bytes(
                        credential["response"]["authenticatorData"]
                            .as_str()
                            .context("auth data")?,
                    )?;
                    bytes[0] ^= 1;
                    credential["response"]["authenticatorData"] =
                        json!(URL_SAFE_NO_PAD.encode(bytes));
                }
                4 => credential["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64])),
                5 => {
                    credential["response"]["userHandle"] =
                        json!(URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()))
                }
                6 => change_client_data(&mut credential, "crossOrigin", json!(true))?,
                7 => {
                    credential["clientExtensionResults"]["prf"]["results"] =
                        json!({"first":"must-stay-client-side"})
                }
                _ => {
                    credential["id"] = json!(URL_SAFE_NO_PAD.encode([1u8; 32]));
                    credential["rawId"] = credential["id"].clone();
                }
            }
            let input = finish_body(&options, credential);
            assert!(
                assertion_finish(&repo, &config, USER, TOKEN, &input.to_string(), false).is_err(),
                "negative {kind}"
            );
            let remaining: i64 = repo
                .lock()
                .query_one(
                    "SELECT COUNT(*) FROM vault_passkey_ceremonies WHERE id=$1",
                    &[&options["ceremony_id"].as_str().context("id")?],
                )?
                .get(0);
            assert_eq!(remaining, 0, "failed verification consumes ceremony {kind}");
        }
        Ok(())
    }

    #[test]
    fn correctly_signed_assertions_still_require_exact_origin_rp_and_challenge() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        let active = enroll(&repo, &config, &mut auth)?;
        for kind in 0..3 {
            let mut options = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
            let origin = match kind {
                0 => {
                    options["public_key"]["challenge"] = json!(URL_SAFE_NO_PAD.encode([9u8; 32]));
                    config.origin.clone()
                }
                1 => "https://sibling.dash.example.com".into(),
                _ => {
                    options["public_key"]["rpId"] = json!("other.example.com");
                    "https://other.example.com".into()
                }
            };
            let assertion_options: RequestChallengeResponse =
                serde_json::from_value(json!({"publicKey":options["public_key"]}))?;
            let credential = clean_credential(
                auth.do_authentication(Url::parse(&origin)?, assertion_options)
                    .map_err(|e| anyhow!("signed negative fixture: {e:?}"))?,
            )?;
            // These payloads carry valid signatures over the wrong values, not
            // post-signature byte tampering that signature verification alone rejects.
            assert!(
                assertion_finish(
                    &repo,
                    &config,
                    USER,
                    TOKEN,
                    &finish_body(&options, credential).to_string(),
                    false
                )
                .is_err(),
                "signed negative {kind}"
            );
        }
        Ok(())
    }

    #[test]
    fn registration_accepts_only_advertised_safe_credential_properties() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        for props in [json!({}), json!({"rk":true}), json!({"rk":false})] {
            let options = register_start(&repo, &config, USER, TOKEN, r#"{"label":"Properties"}"#)?;
            assert_eq!(
                options["public_key"]["extensions"],
                json!({"prf":{},"credProps":true})
            );
            let mut credential = make_registration(&mut auth, &config, &options)?;
            credential["clientExtensionResults"]["credProps"] = props;
            let next = register_finish(
                &repo,
                &config,
                USER,
                TOKEN,
                &finish_body(&options, credential).to_string(),
            )?;
            assert!(next["credential_id"].is_string());
            assert_ne!(next["ceremony_id"], options["ceremony_id"]);
            assert!(
                next["public_key"].get("extensions").is_none(),
                "assertion options must not advertise unhandled client extensions"
            );
        }
        // Accepted browser hints do not replace the two signed assertions.
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        Ok(())
    }

    #[test]
    fn registration_rejects_malformed_properties_unknown_extensions_and_prf_secrets() -> Result<()>
    {
        let (repo, config, mut auth) = fixture()?;
        let invalid = [
            json!({"credProps":null}),
            json!({"credProps":true}),
            json!({"credProps":[]}),
            json!({"credProps":{"rk":null}}),
            json!({"credProps":{"rk":"true"}}),
            json!({"credProps":{"rk":1}}),
            json!({"credProps":{"rk":true,"unknown":false}}),
            json!({"unknown":{}}),
            json!({"uvm":[[1,2,3]]}),
            json!({"credProps":{"rk":true},"prf":{"enabled":true,"results":{"first":"secret"}}}),
        ];
        for extensions in invalid {
            let options = register_start(
                &repo,
                &config,
                USER,
                TOKEN,
                r#"{"label":"Invalid properties"}"#,
            )?;
            let mut credential = make_registration(&mut auth, &config, &options)?;
            credential["clientExtensionResults"] = extensions;
            let input = finish_body(&options, credential).to_string();
            assert!(register_finish(&repo, &config, USER, TOKEN, &input).is_err());
            let remaining: i64 = repo
                .lock()
                .query_one(
                    "SELECT COUNT(*) FROM vault_passkey_ceremonies WHERE id=$1",
                    &[&options["ceremony_id"].as_str().context("ceremony ID")?],
                )?
                .get(0);
            assert_eq!(remaining, 0, "rejected registration consumes its ceremony");
        }
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        Ok(())
    }

    #[test]
    fn assertions_do_not_accept_registration_credential_properties() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        let active = enroll(&repo, &config, &mut auth)?;
        let options = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
        let mut credential = make_assertion(&mut auth, &config, &options)?;
        credential["clientExtensionResults"]["credProps"] = json!({"rk":true});
        assert!(assertion_finish(
            &repo,
            &config,
            USER,
            TOKEN,
            &finish_body(&options, credential).to_string(),
            false
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn registration_rejects_origin_and_uv_and_does_not_activate() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        for kind in 0..3 {
            let mut options =
                register_start(&repo, &config, USER, TOKEN, r#"{"label":"Bad key"}"#)?;
            if kind == 0 {
                options["public_key"]["authenticatorSelection"]["userVerification"] =
                    json!("discouraged");
            }
            let mut credential = make_registration(&mut auth, &config, &options)?;
            if kind == 1 {
                change_client_data(
                    &mut credential,
                    "origin",
                    json!("https://wrong.example.com"),
                )?;
            }
            if kind == 2 {
                credential["clientExtensionResults"]["prf"]["results"] = json!({"first":"secret"});
            }
            assert!(register_finish(
                &repo,
                &config,
                USER,
                TOKEN,
                &finish_body(&options, credential).to_string()
            )
            .is_err());
        }
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        Ok(())
    }

    #[test]
    fn ceremony_is_owned_by_account_session_configuration_and_ttl() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        let active = enroll(&repo, &config, &mut auth)?;
        repo.register("other-user", "hash", "salt")?
            .context("other user")?;
        repo.put_vault("other-user", "0011223344556677", "other-wrap", "n", 4)?;
        assert!(unlock_start(&repo, &config, "other-user", TOKEN, &select(&active)).is_err());
        let options = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
        let input = finish_body(&options, make_assertion(&mut auth, &config, &options)?);
        assert!(assertion_finish(
            &repo,
            &config,
            "other-user",
            TOKEN,
            &input.to_string(),
            false
        )
        .is_err());
        assert!(assertion_finish(
            &repo,
            &config,
            USER,
            "other-session",
            &input.to_string(),
            false
        )
        .is_err());
        assertion_finish(&repo, &config, USER, TOKEN, &input.to_string(), false)?;
        for expired in [false, true] {
            let options = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
            let input = finish_body(&options, make_assertion(&mut auth, &config, &options)?);
            if expired {
                repo.lock().execute(
                    "UPDATE vault_passkey_ceremonies SET expires_at=$1",
                    &[&now()],
                )?;
            }
            let other = Config::new("other.example.com", "https://other.example.com")?;
            assert!(assertion_finish(
                &repo,
                if expired { &config } else { &other },
                USER,
                TOKEN,
                &input.to_string(),
                false
            )
            .is_err());
            assert!(
                assertion_finish(&repo, &config, USER, TOKEN, &input.to_string(), false).is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn concurrent_assertions_cannot_rewind_counter() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        let active = enroll(&repo, &config, &mut auth)?;
        let first = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
        let second = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
        let a = finish_body(&first, make_assertion(&mut auth, &config, &first)?);
        let b = finish_body(&second, make_assertion(&mut auth, &config, &second)?);
        assertion_finish(&repo, &config, USER, TOKEN, &b.to_string(), false)?;
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &a.to_string(), false).is_err());
        Ok(())
    }

    #[test]
    fn multiple_keys_remove_only_owned_key_and_cancel_inflight_work() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        let a = enroll(&repo, &config, &mut auth)?;
        let b = enroll(&repo, &config, &mut auth)?;
        assert_eq!(
            list(&repo, &config, USER)?["credentials"]
                .as_array()
                .context("credentials")?
                .len(),
            2
        );
        repo.register("other-user", "hash", "salt")?
            .context("other user")?;
        repo.put_vault("other-user", "0011223344556677", "other-wrap", "n", 4)?;
        assert!(remove(&repo, "other-user", &select(&a)).is_err());
        let options = unlock_start(&repo, &config, USER, TOKEN, &select(&a))?;
        let input = finish_body(&options, make_assertion(&mut auth, &config, &options)?);
        remove(&repo, USER, &select(&a))?;
        assert!(assertion_finish(&repo, &config, USER, TOKEN, &input.to_string(), false).is_err());
        assert!(unlock_start(&repo, &config, USER, TOKEN, &select(&a)).is_err());
        unlock_start(&repo, &config, USER, TOKEN, &select(&b))?;
        assert_eq!(
            list(&repo, &config, USER)?["credentials"]
                .as_array()
                .context("credentials")?
                .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn same_urk_rewrap_preserves_but_reset_and_legacy_replacement_invalidate() -> Result<()> {
        let (repo, config, mut auth) = fixture()?;
        let active = enroll(&repo, &config, &mut auth)?;
        let generation = active["key_generation"].as_i64().context("generation")?;
        assert!(repo
            .write_vault_operation(
                USER,
                "0011223344556677",
                "rewrapped",
                "n",
                4,
                false,
                true,
                Some(generation - 1),
                false
            )
            .is_err());
        repo.write_vault_operation(
            USER,
            "0011223344556677",
            "rewrapped",
            "n",
            4,
            false,
            true,
            Some(generation),
            false,
        )?;
        assert_eq!(
            list(&repo, &config, USER)?["credentials"]
                .as_array()
                .context("credentials")?
                .len(),
            1
        );
        let options = unlock_start(&repo, &config, USER, TOKEN, &select(&active))?;
        let input = finish_body(&options, make_assertion(&mut auth, &config, &options)?);
        assertion_finish(&repo, &config, USER, TOKEN, &input.to_string(), false)?;
        let test = pending_test(&repo, &config, &mut auth)?;
        repo.write_vault_operation(
            USER,
            "0011223344556677",
            "new-urk",
            "n",
            4,
            false,
            false,
            Some(generation),
            true,
        )?;
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        assert!(unlock_start(&repo, &config, USER, TOKEN, &select(&active)).is_err());
        let input = finish_body(&test, make_assertion(&mut auth, &config, &test)?);
        assert!(register_test(&repo, &config, USER, TOKEN, &input.to_string()).is_err());
        let fresh = enroll(&repo, &config, &mut auth)?;
        assert_eq!(fresh["key_generation"], generation + 1);
        repo.put_vault(USER, "0011223344556677", "new-urk", "n", 4)?;
        assert_eq!(
            list(&repo, &config, USER)?["credentials"]
                .as_array()
                .context("credentials")?
                .len(),
            1,
            "identical legacy no-op"
        );
        repo.put_vault(USER, "0011223344556677", "legacy-changed-key", "n", 4)?;
        assert_eq!(list(&repo, &config, USER)?["credentials"], json!([]));
        assert_eq!(
            repo.get_vault(USER)?.context("vault")?["key_generation"],
            generation + 2
        );
        Ok(())
    }

    #[test]
    fn pending_registration_is_bounded_and_missing_vault_list_is_graceful() -> Result<()> {
        let (repo, config, _) = fixture()?;
        for _ in 0..MAX_PENDING {
            register_start(&repo, &config, USER, TOKEN, r#"{"label":"Key"}"#)?;
        }
        assert!(register_start(&repo, &config, USER, TOKEN, r#"{"label":"Overflow"}"#).is_err());
        repo.lock().execute(
            "UPDATE vault_passkey_ceremonies SET expires_at=$1",
            &[&now()],
        )?;
        register_start(&repo, &config, USER, TOKEN, r#"{"label":"After expiry"}"#)?;
        repo.register("no-vault", "hash", "salt")?
            .context("other user")?;
        assert_eq!(list(&repo, &config, "no-vault")?["credentials"], json!([]));
        assert!(register_start(&repo, &config, "no-vault", TOKEN, r#"{"label":"Key"}"#).is_err());
        Ok(())
    }

    #[test]
    fn account_first_lock_order_prevents_reset_registration_deadlock() -> Result<()> {
        let (repo, _, _) = fixture()?;
        let url = repo.url.clone();
        let mut client = repo.lock();
        let mut tx = client.transaction()?;
        tx.batch_execute("SET LOCAL lock_timeout='2s'")?;
        let owner_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[])?.get(0);
        tx.query_one(
            r#"SELECT 1 FROM users WHERE "user"=$1 FOR UPDATE"#,
            &[&USER],
        )?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || -> Result<Value> {
            let repo = BlobRepo::connect(&url)?;
            let pid: i32 = repo
                .lock()
                .query_one("SELECT pg_backend_pid()", &[])?
                .get(0);
            sender.send(pid)?;
            register_start(
                &repo,
                &Config::new("dash.example.com", "https://dash.example.com")?,
                USER,
                TOKEN,
                r#"{"label":"Concurrent registration"}"#,
            )
        });
        let pid = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let blocked: bool = tx
                .query_one("SELECT $1=ANY(pg_blocking_pids($2))", &[&owner_pid, &pid])?
                .get(0);
            if blocked {
                break;
            }
            if std::time::Instant::now() >= deadline {
                bail!("worker never reached lock barrier");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Before the lock-order fix registration held vault while waiting for
        // its FK users lock, so this statement timed out (or deadlocked).
        tx.query_one(
            r#"SELECT 1 FROM vault WHERE "user"=$1 FOR UPDATE"#,
            &[&USER],
        )?;
        tx.execute(
            r#"UPDATE vault SET key_generation=key_generation+1 WHERE "user"=$1"#,
            &[&USER],
        )?;
        tx.commit()?;
        drop(client);
        let options = worker
            .join()
            .map_err(|_| anyhow!("registration thread panicked"))??;
        assert_eq!(options["key_generation"], 2);
        Ok(())
    }

    #[test]
    fn route_dispatch_bounds_and_rejects_invalid_input() -> Result<()> {
        let (repo, config, _) = fixture()?;
        assert_eq!(
            route_config(&repo, &config, "GET", "", "", USER, TOKEN).0,
            200
        );
        assert_eq!(
            route_config(&repo, &config, "GET", "/unknown", "", USER, TOKEN).0,
            404
        );
        assert_eq!(
            route_config(
                &repo,
                &config,
                "POST",
                "/register/start",
                &" ".repeat(128 * 1024 + 1),
                USER,
                TOKEN
            )
            .0,
            413
        );
        for suffix in [
            "/cancel",
            "/register/start",
            "/register/finish",
            "/register/test",
            "/register/commit",
            "/unlock/start",
            "/unlock/finish",
            "/remove",
        ] {
            assert_eq!(
                route_config(&repo, &config, "POST", suffix, "{}", USER, TOKEN).0,
                400
            );
        }
        assert_eq!(
            route_config(
                &repo,
                &config,
                "POST",
                "/register/start",
                r#"{"label":"Valid"}"#,
                USER,
                TOKEN
            )
            .0,
            200
        );
        for label in [
            "".to_owned(),
            " ".to_owned(),
            "a".repeat(81),
            "control\u{0007}".into(),
        ] {
            assert_eq!(
                route_config(
                    &repo,
                    &config,
                    "POST",
                    "/register/start",
                    &json!({"label":label}).to_string(),
                    USER,
                    TOKEN
                )
                .0,
                400
            );
        }
        Ok(())
    }

    #[test]
    fn routing_requires_auth_and_blocks_readonly_mutations() -> Result<()> {
        let (repo, _, _) = fixture()?;
        for path in [
            "/api/self/passkeys/register/start",
            "/api/self/passkeys/cancel",
            "/api/self/passkeys/remove",
            "/api/self/vault/reset",
        ] {
            assert_eq!(
                crate::http::handle_full(&repo, "POST", path, "{}", None, None).0,
                401
            );
        }
        let (token, _) = repo.create_session(USER, "readonly")?;
        repo.lock().execute(
            r#"UPDATE sessions SET readonly=1 WHERE "user"=$1"#,
            &[&USER],
        )?;
        for path in [
            "/api/self/passkeys/register/start",
            "/api/self/passkeys/cancel",
            "/api/self/passkeys/remove",
            "/api/self/passkeys/unlock/start",
            "/api/self/vault/reset",
        ] {
            assert_eq!(
                crate::http::handle_full(&repo, "POST", path, "{}", Some(&token), None).0,
                403
            );
        }
        Ok(())
    }
}
