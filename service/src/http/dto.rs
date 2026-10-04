//! Request bodies for the cloud HTTP API.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct RegisterIn {
    pub user: String,
    pub pass_hash: String,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub salt: String,
    #[serde(default)]
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginIn {
    pub user: String,
    pub pass_hash: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PushIn {
    pub id: String,
    #[serde(default)]
    pub ciphertext: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub embedding_enc: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct BatchPushIn {
    pub items: Vec<PushIn>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ForgetIn {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct PasswordIn {
    pub pass_hash: String,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SessionCreateIn {
    #[serde(default)]
    pub device_name: Option<String>,
    /// Read-only session (recall-only teammate): can read, cannot write; enforced server-side.
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminUpdateIn {
    #[serde(default)]
    pub pass_hash: Option<String>,
    #[serde(default)]
    pub salt: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TotpIn {
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct EmailIn {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ForgotIn {
    pub user: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ResetIn {
    pub user: String,
    pub code: String,
    pub pass_hash: String,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct VaultIn {
    pub kdf_salt: String,
    pub wrapped_urk: String,
    pub urk_nonce: String,
    #[serde(default = "default_vault_version")]
    pub version: i64,
}

fn default_vault_version() -> i64 {
    2
}

#[derive(Debug, Deserialize)]
pub(super) struct AdminCreateIn {
    pub user: String,
    pub pass_hash: String,
    #[serde(default)]
    pub salt: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub email: String,
}

/// Max items per batch: clients chunk at 100; this cap leaves headroom against abuse.
pub(super) const MAX_PUSH_BATCH: usize = 512;

pub(super) fn push_item_error(parsed: &PushIn) -> Option<String> {
    if parsed.id.trim().is_empty() || parsed.updated_at.trim().is_empty() {
        return Some("id/updated_at required".to_owned());
    }
    if chrono::DateTime::parse_from_rfc3339(&parsed.updated_at).is_err() {
        return Some("updated_at must be RFC3339".to_owned());
    }
    if !parsed.deleted && (parsed.ciphertext.trim().is_empty() || parsed.nonce.trim().is_empty()) {
        return Some("active memory requires ciphertext/nonce".to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_item_rejects_empty_id() {
        let p = PushIn {
            id: String::new(),
            ciphertext: "aa".into(),
            nonce: "bb".into(),
            embedding_enc: String::new(),
            updated_at: "2026-09-22T00:00:00.000Z".into(),
            deleted: false,
        };
        assert!(push_item_error(&p).unwrap().contains("id"));
    }

    #[test]
    fn push_item_rejects_bad_time() {
        let p = PushIn {
            id: "id1".into(),
            ciphertext: "aa".into(),
            nonce: "bb".into(),
            embedding_enc: String::new(),
            updated_at: "not-rfc3339".into(),
            deleted: false,
        };
        assert!(push_item_error(&p).unwrap().contains("RFC3339"));
    }

    #[test]
    fn push_item_active_needs_ciphertext() {
        let p = PushIn {
            id: "id1".into(),
            ciphertext: String::new(),
            nonce: String::new(),
            embedding_enc: String::new(),
            updated_at: "2026-09-22T00:00:00.000Z".into(),
            deleted: false,
        };
        assert!(push_item_error(&p).is_some());
        let tomb = PushIn { deleted: true, ..p };
        assert!(push_item_error(&tomb).is_none());
    }

    #[test]
    fn push_item_ok() {
        let p = PushIn {
            id: "id1".into(),
            ciphertext: "aa".into(),
            nonce: "bb".into(),
            embedding_enc: String::new(),
            updated_at: "2026-09-22T00:00:00.000Z".into(),
            deleted: false,
        };
        assert_eq!(push_item_error(&p), None);
    }
}
