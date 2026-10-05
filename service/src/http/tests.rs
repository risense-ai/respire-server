//! HTTP route tests (moved with the router split; behavior unchanged).
use super::*;
use anyhow::{anyhow, Context, Result};
use respire::memory::crypto::{derive_auth_salt, derive_pass_hash};

#[test]
fn browser_pages_preserve_snapshot_and_incremental_account_boundaries() -> Result<()> {
    let repo = repo()?;
    let (token, _, _) = register_user(&repo, "browser-pages")?;
    let epoch = repo.sync_capabilities("browser-pages")?.epoch;
    let query = |after: i64, until: Option<i64>, snapshot: bool| {
        let bound = until.map_or(String::new(), |n| format!("&until={n}"));
        format!("/api/self/memories?epoch={epoch}&after={after}&snapshot={}{}", i32::from(snapshot), bound)
    };
    let read = |path: &str| -> Result<serde_json::Value> {
        let (status, body) = handle(&repo, "GET", path, "", Some(&token));
        assert_eq!(status, 200, "{body}");
        Ok(serde_json::from_str(&body)?)
    };
    assert_eq!(handle(&repo, "GET", &query(0, None, true), "", None).0, 401);
    let empty = read(&query(0, None, true))?;
    assert_eq!(empty["blobs"], serde_json::json!([]));
    assert_eq!(empty["cursor"], 0);
    let items: Vec<_> = (0..102).map(|n| serde_json::json!({
        "id": format!("page-{n}"), "ciphertext": format!("cipher-{n}"), "nonce": "nonce",
        "embedding_enc": "vector-must-not-be-sent", "updated_at": "2026-10-05T00:00:00Z",
        "deleted": false
    })).collect();
    let batch = serde_json::json!({"items": items}).to_string();
    assert_eq!(handle(&repo, "POST", "/push/batch", &batch, Some(&token)).0, 200);
    let first = read(&query(0, None, true))?;
    let blobs = first["blobs"].as_array().context("page blobs")?;
    assert_eq!(blobs.len(), 100);
    assert_eq!(first["has_more"], true);
    assert_eq!(first["cursor"], 100);
    assert_eq!(first["until"], 102);
    assert!(blobs.iter().all(|b| b.as_object().is_some_and(|o|
        o.len() == 5 && !o.contains_key("embedding_enc") && !o.contains_key("user"))));

    // Mutations between pages must not alter the immutable snapshot upper bound.
    let edit = serde_json::json!({"id":"page-101", "ciphertext":"edited", "nonce":"nonce",
        "updated_at":"2026-10-06T00:00:00Z", "deleted":false}).to_string();
    assert_eq!(handle(&repo, "POST", "/push", &edit, Some(&token)).0, 200);
    assert_eq!(handle(&repo, "POST", "/forget", r#"{"id":"page-0"}"#, Some(&token)).0, 200);
    let stale = serde_json::json!({"id":"page-101", "ciphertext":"stale", "nonce":"nonce",
        "updated_at":"2026-10-04T00:00:00Z", "deleted":false}).to_string();
    assert_eq!(handle(&repo, "POST", "/push", &stale, Some(&token)).0, 200);
    let last = read(&query(100, Some(102), true))?;
    assert_eq!(last["blobs"].as_array().context("last blobs")?.len(), 2);
    assert_eq!(last["blobs"][1]["ciphertext"], "cipher-101");
    assert_eq!(last["cursor"], 102);
    assert_eq!(last["has_more"], false);
    let delta = read(&query(102, None, false))?;
    let changes = delta["blobs"].as_array().context("delta blobs")?;
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0]["ciphertext"], "edited");
    assert_eq!(changes[1]["id"], "page-0");
    assert_eq!(changes[1]["deleted"], true);
    assert_eq!(delta["cursor"], 105); // rejected revision omitted but consumed
    assert_eq!(read(&query(105, None, false))?["blobs"], serde_json::json!([]));
    let (other_token, _, _) = register_user(&repo, "browser-other")?;
    let other_epoch = repo.sync_capabilities("browser-other")?.epoch;
    let (status, other) = handle(&repo, "GET",
        &format!("/api/self/memories?epoch={other_epoch}&after=0&snapshot=1"), "", Some(&other_token));
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_str::<serde_json::Value>(&other)?["blobs"], serde_json::json!([]));
    for suffix in ["", "?epoch=&after=0", "?epoch=any", "?epoch=any&after=-1",
        "?epoch=any&after=x", "?epoch=any&after=2&until=1",
        "?epoch=any&after=0&until=x", "?epoch=any&after=0&snapshot=2"] {
        assert_eq!(handle(&repo, "GET", &format!("/api/self/memories{suffix}"), "", Some(&token)).0, 400);
    }
    for path in ["/api/self/memories?epoch=old&after=0".to_owned(), query(106, None, false),
        query(0, Some(106), true)] {
        let (status, body) = handle(&repo, "GET", &path, "", Some(&token));
        assert_eq!(status, 409);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body)?["code"], "snapshot_required");
    }
    Ok(())
}

    fn repo() -> Result<BlobRepo> {
        crate::store::connect_unique()
    }

    fn register_user(repo: &BlobRepo, user: &str) -> Result<(String, String, String)> {
        let salt = derive_auth_salt(user)?;
        let hash = derive_pass_hash("pass-1234", &salt)?;
        let body = format!(r#"{{"user":"{user}","pass_hash":"{hash}","salt":"{salt}"}}"#);
        let (status, reply) = handle(repo, "POST", "/register", &body, None);
        assert_eq!(status, 200);
        let token = serde_json::from_str::<serde_json::Value>(&reply)?["token"]
            .as_str()
            .ok_or_else(|| anyhow!("token missing"))?
            .to_owned();
        Ok((token, salt, hash))
    }

    #[test]
    fn register_login_flow() -> Result<()> {
        let repo = repo()?;
        let (token, _salt, hash) = register_user(&repo, "alice")?;
        assert_eq!(token.len(), 64);
        // duplicate register 409 (same user + salt → same hash)
        let salt2 = derive_auth_salt("alice")?;
        let hash2 = derive_pass_hash("pass-1234", &salt2).context("required")?;
        let body2 = format!(r#"{{"user":"alice","pass_hash":"{hash2}","salt":"{salt2}"}}"#);
        let (status, _) = handle(&repo, "POST", "/register", &body2, None);
        assert_eq!(status, 409);
        // login: any device derives the same salt+hash for the user → 200 and matching token
        let body = format!(r#"{{"user":"alice","pass_hash":"{hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/login", &body, None);
        assert_eq!(status, 200);
        let login_token = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        assert_eq!(login_token, token);
        // wrong pass_hash → 401
        let bad = format!(r#"{{"user":"alice","pass_hash":"deadbeef"}}"#);
        let (status, _) = handle(&repo, "POST", "/login", &bad, None);
        assert_eq!(status, 401);
        Ok(())
    }

    #[test]
    fn push_pull_require_valid_token() -> Result<()> {
        let repo = repo()?;
        // no token → 401
        let (status, _) = handle(&repo, "GET", "/count", "", None);
        assert_eq!(status, 401);
        // register to obtain a token
        let (token, _, _) = register_user(&repo, "bob")?;
        // valid token → 200
        let (status, reply) = handle(&repo, "GET", "/count", "", Some(&token));
        assert_eq!(status, 200);
        assert!(reply.contains("\"count\":0"));
        // push + pull + forget
        let body = r#"{"id":"id-1","ciphertext":"aabb","nonce":"1122","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}"#;
        let (status, _) = handle(&repo, "POST", "/push", body, Some(&token));
        assert_eq!(status, 200);
        let (_, reply) = handle(&repo, "GET", "/pull", "", Some(&token));
        let blobs = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["blobs"]
            .as_array()
            .context("required")?
            .len();
        assert_eq!(blobs, 1);
        let (_, reply) = handle(&repo, "POST", "/forget", r#"{"id":"id-1"}"#, Some(&token));
        assert!(reply.contains("\"deleted\":true"));
        let (_, reply) = handle(&repo, "GET", "/count", "", Some(&token));
        assert!(reply.contains("\"count\":0"));
        // wrong token → 401
        let (status, _) = handle(&repo, "GET", "/count", "", Some("wrong-token"));
        assert_eq!(status, 401);
        Ok(())
    }

    #[test]
    fn push_batch_requires_valid_token() -> Result<()> {
        let repo = repo()?;
        let body = r#"{"items":[{"id":"id-1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}]}"#;
        let (status, _) = handle(&repo, "POST", "/push/batch", body, None);
        assert_eq!(status, 401);
        let (status, _) = handle(&repo, "POST", "/push/batch", body, Some("wrong-token"));
        assert_eq!(status, 401);
        Ok(())
    }

    #[test]
    fn push_batch_lww_mixed_results() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "batcher")?;
        let item = |id: &str, ct: &str, ts: &str| {
            format!(r#"{{"id":"{id}","ciphertext":"{ct}","nonce":"11","updated_at":"{ts}","deleted":false}}"#)
        };
        // batch 1: two new writes → all replaced
        let body = format!(
            r#"{{"items":[{},{}]}}"#,
            item("b-1", "aa", "2026-09-02T00:00:00.000Z"),
            item("b-2", "bb", "2026-09-02T00:00:01.000Z"),
        );
        let (status, reply) = handle(&repo, "POST", "/push/batch", &body, Some(&token));
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reply).context("required")?["replaced"],
            serde_json::json!([true, true])
        );
        // batch 2: b-1 newer overwrite + same-batch stale reject + b-3 insert → [true, false, true]
        let body = format!(
            r#"{{"items":[{},{},{}]}}"#,
            item("b-1", "cc", "2026-09-03T00:00:00.000Z"),
            item("b-1", "stale", "2026-09-01T00:00:00.000Z"),
            item("b-3", "dd", "2026-09-02T00:00:02.000Z"),
        );
        let (status, reply) = handle(&repo, "POST", "/push/batch", &body, Some(&token));
        assert_eq!(status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reply).context("required")?["replaced"],
            serde_json::json!([true, false, true])
        );
        // stored: 3 live rows; b-1 ciphertext is the first item of the batch
        let (_, reply) = handle(&repo, "GET", "/count", "", Some(&token));
        assert!(reply.contains("\"count\":3"));
        let (_, reply) = handle(&repo, "GET", "/pull", "", Some(&token));
        let blobs = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["blobs"].clone();
        let b1 = blobs
            .as_array()
            .context("required")?
            .iter()
            .find(|b| b["id"] == "b-1")
            .context("required")?;
        assert_eq!(b1["ciphertext"], "cc");
        Ok(())
    }

    #[test]
    fn push_batch_invalid_item_rejects_whole_batch() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "batch-vld")?;
        // item 1 missing updated_at → 400 at item 1; whole batch dropped (validate before write; count stays 0)
        let body = r#"{"items":[{"id":"ok-1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false},{"id":"bad-1","ciphertext":"aa","nonce":"11","updated_at":"","deleted":false}]}"#;
        let (status, reply) = handle(&repo, "POST", "/push/batch", body, Some(&token));
        assert_eq!(status, 400);
        assert!(reply.contains("item 1"));
        let (_, reply) = handle(&repo, "GET", "/count", "", Some(&token));
        assert!(reply.contains("\"count\":0"));
        // live item missing ciphertext → 400
        let body = r#"{"items":[{"id":"ok-1","ciphertext":"","nonce":"","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}]}"#;
        let (status, reply) = handle(&repo, "POST", "/push/batch", body, Some(&token));
        assert_eq!(status, 400);
        assert!(reply.contains("active memory requires ciphertext/nonce"));
        Ok(())
    }

    #[test]
    fn push_batch_size_cap() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "batch-cap")?;
        let items: Vec<String> = (0..513)
            .map(|i| {
                format!(r#"{{"id":"x-{i}","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}}"#)
            })
            .collect();
        let body = format!(r#"{{"items":[{}]}}"#, items.join(","));
        let (status, _) = handle(&repo, "POST", "/push/batch", &body, Some(&token));
        assert_eq!(status, 413);
        Ok(())
    }

    #[test]
    fn per_user_isolation() -> Result<()> {
        let repo = repo()?;
        let (token_a, _, _) = register_user(&repo, "user-a")?;
        let (token_b, _, _) = register_user(&repo, "user-b")?;
        let body = r#"{"id":"id-1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}"#;
        handle(&repo, "POST", "/push", body, Some(&token_a));
        let (_, reply) = handle(&repo, "GET", "/count", "", Some(&token_b));
        assert!(reply.contains("\"count\":0"));
        let (_, reply) = handle(&repo, "GET", "/count", "", Some(&token_a));
        assert!(reply.contains("\"count\":1"));
        Ok(())
    }

    #[test]
    fn health_no_auth() -> Result<()> {
        let repo = repo()?;
        let (status, body) = handle(&repo, "GET", "/health", "", None);
        assert_eq!(status, 200);
        assert!(body.contains("\"ok\":true") || body.contains("\"ok\": true"));
        Ok(())
    }

    #[test]
    fn api_does_not_serve_site_or_spa() -> Result<()> {
        assert!(public_route("GET", "/").is_none());
        assert!(public_route("GET", "/zh/").is_none());
        assert!(public_route("GET", "/admin").is_none());
        assert!(public_route("GET", "/dashboard").is_none());
        let (_, health) = public_route("GET", "/health").context("/health")?;
        assert!(health.contains("\"ok\""));
        Ok(())
    }

    /// HTML pages are a separate nginx deploy. The API returns 401 without a token.
    #[test]
    fn html_paths_are_not_served_by_api() -> Result<()> {
        let repo = repo()?;
        for path in ["/", "/admin", "/admin/", "/dashboard", "/dashboard/", "/dashboard/memories"] {
            let (status, body) = handle(&repo, "GET", path, "", None);
            assert_eq!(status, 401, "{path}");
            assert!(!body.to_ascii_lowercase().contains("<!doctype html>"), "{path}");
        }
        assert_eq!(handle(&repo, "GET", "/admin/users", "", None).0, 401);
        Ok(())
    }

    /// Fresh DB arrival seq starts at 0; first push becomes 1; no since is full, since=1 is empty.
    #[test]
    fn first_put_starts_rev_cursor() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "legacy")?;
        let body = r#"{"id":"new-1","ciphertext":"bb","nonce":"22","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}"#;
        let (status, _) = handle(&repo, "POST", "/push", body, Some(&token));
        assert_eq!(status, 200);
        let (blobs, cursor, _, _) = repo.pull("legacy", None).context("required")?;
        assert_eq!(blobs.len(), 1);
        assert_eq!(cursor, 1);
        let (blobs, _, _, _) = repo.pull("legacy", Some(1)).context("required")?;
        assert_eq!(blobs.len(), 0);
        Ok(())
    }

    /// Incremental pull: /pull?since=<arrival seq> returns new/changed only; LWW rejects do not stamp arrival.
    #[test]
    fn pull_incremental_by_rev() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "carol")?;
        let push = |id: &str, ts: &str| {
            let body = format!(
                r#"{{"id":"{id}","ciphertext":"aa","nonce":"11","updated_at":"{ts}","deleted":false}}"#
            );
            handle(&repo, "POST", "/push", &body, Some(&token))
        };
        push("a", "2026-09-02T00:00:00.000Z");
        push("b", "2026-09-02T00:00:01.000Z");

        // first pull (no since) → both rows, plus cursor and totals
        let (status, reply) = handle(&repo, "GET", "/pull", "", Some(&token));
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&reply).context("required")?;
        assert_eq!(v["blobs"].as_array().context("required")?.len(), 2);
        assert_eq!(v["total"].as_u64().context("required")?, 2);
        assert_eq!(v["alive"].as_u64().context("required")?, 2);
        let cursor = v["cursor"].as_u64().context("required")?;
        assert_eq!(cursor, 2);

        // pull from cursor → nothing new
        let (_, reply) = handle(&repo, "GET", "/pull?since=2", "", Some(&token));
        let v: serde_json::Value = serde_json::from_str(&reply).context("required")?;
        assert_eq!(v["blobs"].as_array().context("required")?.len(), 0);

        // third item → incremental returns only that
        push("c", "2026-09-02T00:00:02.000Z");
        let (_, reply) = handle(&repo, "GET", "/pull?since=2", "", Some(&token));
        let v: serde_json::Value = serde_json::from_str(&reply).context("required")?;
        assert_eq!(v["blobs"].as_array().context("required")?.len(), 1);
        assert_eq!(v["blobs"][0]["id"].as_str().context("required")?, "c");
        assert_eq!(v["cursor"].as_u64().context("required")?, 3);

        // stale write rejected (LWW) → no arrival stamp → since=3 still empty
        push("a", "2026-09-01T00:00:00.000Z"); // older than stored
        let (_, reply) = handle(&repo, "GET", "/pull?since=3", "", Some(&token));
        let v: serde_json::Value = serde_json::from_str(&reply).context("required")?;
        assert_eq!(v["blobs"].as_array().context("required")?.len(), 0);
        assert_eq!(v["cursor"].as_u64().context("required")?, 3);
        Ok(())
    }

    /// /admin/*: no token 401; user token 403; admin token may list (token masked, never full).
    #[test]
    fn admin_list_requires_admin_token() -> Result<()> {
        let repo = repo()?;
        let (alice_token, _, _) = register_user(&repo, "alice")?;
        let (status, _) = handle(&repo, "GET", "/admin/users", "", None);
        assert_eq!(status, 401);
        let (status, _) = handle(&repo, "GET", "/admin/users", "", Some(&alice_token));
        assert_eq!(status, 403);
        let (status, _) = handle_full(&repo, "GET", "/admin/users", "", Some(&alice_token), None);
        assert_eq!(status, 403);
        let (status, reply) =
            handle_full(&repo, "GET", "/admin/users", "", Some("adm-1"), Some("adm-1"));
        assert_eq!(status, 200);
        assert!(reply.contains("alice"));
        assert!(reply.contains("token_masked"));
        // full token must not be echoed
        assert!(!reply.contains(&alice_token));
        // mask looks like abcdef…wxyz
        assert!(reply.contains("…"));
        Ok(())
    }

    /// Admin rotate and revoke: rotate kills the old token; revoke deletes the account and its ciphertext.
    #[test]
    fn admin_rotate_and_revoke() -> Result<()> {
        let repo = repo()?;
        let (alice_token, _, _) = register_user(&repo, "alice")?;
        let body = r#"{"id":"id-1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}"#;
        handle(&repo, "POST", "/push", body, Some(&alice_token));
        // rotate
        let (status, reply) =
            handle_full(&repo, "POST", "/admin/users/alice/rotate", "", Some("adm-1"), Some("adm-1"));
        assert_eq!(status, 200);
        let new_token = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        assert_ne!(new_token, alice_token);
        assert_eq!(repo.user_from_token(&new_token)?.as_deref(), Some("alice"));
        assert_eq!(repo.user_from_token(&alice_token)?, None);
        // new token can still push; old token 401
        let (status, _) = handle(&repo, "POST", "/push", body, Some(&new_token));
        assert_eq!(status, 200);
        let (status, _) = handle(&repo, "POST", "/push", body, Some(&alice_token));
        assert_eq!(status, 401);
        // revoke: delete the account and its ciphertext
        let (status, reply) =
            handle_full(&repo, "POST", "/admin/users/alice/revoke", "", Some("adm-1"), Some("adm-1"));
        assert_eq!(status, 200);
        let blobs = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["blobs_deleted"]
            .as_u64()
            .context("required")?;
        assert_eq!(blobs, 1);
        // account gone: old and new tokens 401; list is empty
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&new_token));
        assert_eq!(status, 401);
        let (_, reply) = handle_full(&repo, "GET", "/admin/users", "", Some("adm-1"), Some("adm-1"));
        assert!(!reply.contains("alice"));
        // revoke a missing user → 404
        let (status, _) =
            handle_full(&repo, "POST", "/admin/users/ghost/revoke", "", Some("adm-1"), Some("adm-1"));
        assert_eq!(status, 404);
        Ok(())
    }

    #[test]
    fn purge_wipes_data_and_releases_username() -> Result<()> {
        let repo = repo()?;
        let (token, salt, hash) = register_user(&repo, "alice")?;
        let body = r#"{"id":"id-1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}"#;
        handle(&repo, "POST", "/push", body, Some(&token));
        let (status, _) = handle(
            &repo,
            "POST",
            "/api/self/vault",
            r#"{"kdf_salt":"aabbccddeeff0011","wrapped_urk":"aa","urk_nonce":"bb","version":4}"#,
            Some(&token),
        );
        assert_eq!(status, 200);
        let (status, _) = handle_full(
            &repo,
            "POST",
            "/admin/users/alice/delete",
            "",
            Some("adm-1"),
            Some("adm-1"),
        );
        assert_eq!(status, 200);
        let register = format!(r#"{{"user":"alice","pass_hash":"{hash}","salt":"{salt}"}}"#);
        let (status, _) = handle(&repo, "POST", "/register", &register, None);
        assert_eq!(status, 409);

        let (status, reply) = handle_full(
            &repo,
            "POST",
            "/admin/users/alice/purge",
            "",
            Some("adm-1"),
            Some("adm-1"),
        );
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("\"purged\":true") || reply.contains("\"purged\": true"));
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&token));
        assert_eq!(status, 401);
        let (status, _) = handle(&repo, "POST", "/register", &register, None);
        assert_eq!(status, 200);
        let (new_token, _, _) = {
            let (status, reply) = handle(&repo, "POST", "/login", &format!(r#"{{"user":"alice","pass_hash":"{hash}"}}"#), None);
            assert_eq!(status, 200);
            let token = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
                .as_str()
                .context("required")?
                .to_owned();
            (token, (), ())
        };
        let (status, _) = handle(&repo, "GET", "/api/self/vault", "", Some(&new_token));
        assert_eq!(status, 404);
        let (status, reply) = handle(&repo, "GET", "/count", "", Some(&new_token));
        assert_eq!(status, 200);
        assert!(reply.contains("\"count\":0"));
        Ok(())
    }

    #[test]
    fn self_purge_deletes_account() -> Result<()> {
        let repo = repo()?;
        let (token, salt, hash) = register_user(&repo, "carol")?;
        // 2026-09-21 server confirm gate: missing/wrong confirm → 400 (frontend dialog can be skipped)
        let (status, _) = handle(&repo, "POST", "/api/self/purge", "", Some(&token));
        assert_eq!(status, 400);
        let (status, _) = handle(&repo, "POST", "/api/self/purge", r#"{"confirm":"wrong"}"#, Some(&token));
        assert_eq!(status, 400);
        let (status, reply) = handle(&repo, "POST", "/api/self/purge", r#"{"confirm":"carol"}"#, Some(&token));
        assert_eq!(status, 200, "{reply}");
        let (status, _) = handle(&repo, "GET", "/api/self", "", Some(&token));
        assert_eq!(status, 401);
        let register = format!(r#"{{"user":"carol","pass_hash":"{hash}","salt":"{salt}"}}"#);
        let (status, _) = handle(&repo, "POST", "/register", &register, None);
        assert_eq!(status, 200);
        Ok(())
    }

    #[test]
    fn admin_disable_and_sessions() -> Result<()> {
        let repo = repo()?;
        let (alice_token, _, hash) = register_user(&repo, "alice")?;
        let (status, reply) = handle_full(
            &repo,
            "POST",
            "/admin/users/alice/disable",
            "",
            Some("adm-1"),
            Some("adm-1"),
        );
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("\"disabled\":true"));
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&alice_token));
        assert_eq!(status, 401);
        let login = format!(r#"{{"user":"alice","pass_hash":"{hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/login", &login, None);
        assert_eq!(status, 403, "{reply}");
        let (status, _) = handle_full(
            &repo,
            "POST",
            "/admin/users/alice/enable",
            "",
            Some("adm-1"),
            Some("adm-1"),
        );
        assert_eq!(status, 200);
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&alice_token));
        assert_eq!(status, 200);
        let (status, reply) = handle_full(
            &repo,
            "GET",
            "/admin/users",
            "",
            Some("adm-1"),
            Some("adm-1"),
        );
        assert_eq!(status, 200);
        assert!(reply.contains("session_count"));
        assert!(reply.contains("\"disabled\":false"));
        let (status, reply) = handle_full(
            &repo,
            "GET",
            "/admin/users/alice/sessions",
            "",
            Some("adm-1"),
            Some("adm-1"),
        );
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("sessions"));
        Ok(())
    }

    /// /api/self and self-rotate: owner can see the mask and rotate their own token.
    #[test]
    fn self_info_and_rotate() -> Result<()> {
        let repo = repo()?;
        let (bob_token, _, _) = register_user(&repo, "bob")?;
        let (status, reply) = handle(&repo, "GET", "/api/self", "", Some(&bob_token));
        assert_eq!(status, 200);
        assert!(reply.contains("bob"));
        assert!(reply.contains("token_masked"));
        assert!(!reply.contains(&bob_token));
        // rotate self
        let (status, reply) = handle(&repo, "POST", "/api/self/rotate", "", Some(&bob_token));
        assert_eq!(status, 200);
        let new_token = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        assert_ne!(new_token, bob_token);
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&bob_token));
        assert_eq!(status, 401);
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&new_token));
        assert_eq!(status, 200);
        // no token → 401
        let (status, _) = handle(&repo, "GET", "/api/self", "", None);
        assert_eq!(status, 401);
        Ok(())
    }

    /// Default super-admin admin/admin: login, create user, change password, mint token, delete.
    #[test]
    fn super_admin_default_and_user_crud() -> Result<()> {
        let repo = repo()?;
        let salt = derive_auth_salt("admin")?;
        let hash = derive_pass_hash("admin", &salt).context("required")?;
        let login = format!(r#"{{"user":"admin","pass_hash":"{hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/admin/login", &login, None);
        assert_eq!(status, 200, "{reply}");
        let admin_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();

        let (status, reply) = handle(&repo, "GET", "/admin/me", "", Some(&admin_tok));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("super_admin"));

        let salt_u = derive_auth_salt("carol")?;
        let hash_u = derive_pass_hash("carol-pass", &salt_u).context("required")?;
        let create = format!(r#"{{"user":"carol","pass_hash":"{hash_u}","salt":"{salt_u}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/admin/users", &create, Some(&admin_tok));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("token"));

        let (status, reply) = handle(&repo, "GET", "/admin/users", "", Some(&admin_tok));
        assert_eq!(status, 200);
        assert!(reply.contains("carol"));

        let new_hash = derive_pass_hash("carol-pass-2", &salt_u).context("required")?;
        let update = format!(r#"{{"pass_hash":"{new_hash}","salt":"{salt_u}","disabled":false}}"#);
        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/users/carol/update",
            &update,
            Some(&admin_tok),
        );
        assert_eq!(status, 200, "{reply}");

        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/users/carol/sessions",
            r#"{"device_name":"admin-ui"}"#,
            Some(&admin_tok),
        );
        assert_eq!(status, 200, "{reply}");
        let sess_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&sess_tok));
        assert_eq!(status, 200);

        let login_new = format!(r#"{{"user":"carol","pass_hash":"{new_hash}"}}"#);
        let (status, _) = handle(&repo, "POST", "/login", &login_new, None);
        assert_eq!(status, 200);

        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/users/carol/revoke",
            "",
            Some(&admin_tok),
        );
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("deleted"));
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&sess_tok));
        assert_eq!(status, 401);
        Ok(())
    }

    /// Self-service: mint / list / revoke tokens, read key summary, change password.
    #[test]
    fn self_tokens_keys_password() -> Result<()> {
        let repo = repo()?;
        let (bob_token, salt, _) = register_user(&repo, "bob")?;
        let (status, reply) = handle(
            &repo,
            "POST",
            "/api/self/sessions",
            r#"{"device_name":"laptop"}"#,
            Some(&bob_token),
        );
        assert_eq!(status, 200, "{reply}");
        let new_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        let session_id = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["session_id"]
            .as_str()
            .context("required")?
            .to_owned();
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&new_tok));
        assert_eq!(status, 200);

        let (status, reply) = handle(&repo, "GET", "/api/self/sessions", "", Some(&bob_token));
        assert_eq!(status, 200);
        assert!(reply.contains("laptop"));

        let (status, reply) = handle(&repo, "GET", "/api/self/keys", "", Some(&bob_token));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("auth_salt"));
        assert!(reply.contains("Secret Key"));

        let (status, reply) = handle(
            &repo,
            "POST",
            &format!("/api/self/sessions/{session_id}/revoke"),
            "",
            Some(&bob_token),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, _) = handle(&repo, "GET", "/count", "", Some(&new_tok));
        assert_eq!(status, 401);

        let new_hash = derive_pass_hash("pass-9999", &salt).context("required")?;
        let (status, reply) = handle(
            &repo,
            "POST",
            "/api/self/password",
            &format!(r#"{{"pass_hash":"{new_hash}","salt":"{salt}"}}"#),
            Some(&bob_token),
        );
        assert_eq!(status, 200, "{reply}");
        let login = format!(r#"{{"user":"bob","pass_hash":"{new_hash}"}}"#);
        let (status, _) = handle(&repo, "POST", "/login", &login, None);
        assert_eq!(status, 200);
        Ok(())
    }

    /// Super-admin password change invalidates the old hash; seed only on empty table, so a change is not reset.
    #[test]
    fn super_admin_password_change_persists() -> Result<()> {
        let repo = repo()?;
        let salt = derive_auth_salt("admin")?;
        let old_hash = derive_pass_hash("admin", &salt).context("required")?;
        let login = format!(r#"{{"user":"admin","pass_hash":"{old_hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/admin/login", &login, None);
        assert_eq!(status, 200, "{reply}");
        let admin_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();

        let new_hash = derive_pass_hash("changed-admin", &salt).context("required")?;
        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/password",
            &format!(r#"{{"pass_hash":"{new_hash}","salt":"{salt}"}}"#),
            Some(&admin_tok),
        );
        assert_eq!(status, 200, "{reply}");

        let (status, _) = handle(&repo, "POST", "/admin/login", &login, None);
        assert_eq!(status, 401);
        let login_new = format!(r#"{{"user":"admin","pass_hash":"{new_hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/admin/login", &login_new, None);
        assert_eq!(status, 200, "{reply}");
        Ok(())
    }

    #[test]
    fn admin_roles_audit_mail_totp_export() -> Result<()> {
        let repo = repo()?;
        let salt = derive_auth_salt("admin")?;
        let hash = derive_pass_hash("admin", &salt).context("required")?;
        let login = format!(r#"{{"user":"admin","pass_hash":"{hash}"}}"#);
        let (_, reply) = handle(&repo, "POST", "/admin/login", &login, None);
        let owner_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();

        let salt_u = derive_auth_salt("carol")?;
        let hash_u = derive_pass_hash("carol-pass", &salt_u).context("required")?;
        let create = format!(r#"{{"user":"carol","pass_hash":"{hash_u}","salt":"{salt_u}","email":"carol@example.com"}}"#);
        let (status, _) = handle(&repo, "POST", "/admin/users", &create, Some(&owner_tok));
        assert_eq!(status, 200);
        let (status, reply) = handle(&repo, "GET", "/admin/users?q=carol&page=1&limit=10", "", Some(&owner_tok));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("\"total\":"));
        let (status, reply) = handle(&repo, "GET", "/admin/users?export=1", "", Some(&owner_tok));
        assert_eq!(status, 200);
        assert!(reply.contains("csv"));
        assert!(reply.contains("carol"));

        let salt_a = derive_auth_salt("ops")?;
        let hash_a = derive_pass_hash("ops-pass", &salt_a).context("required")?;
        let create_admin = format!(
            r#"{{"user":"ops","pass_hash":"{hash_a}","salt":"{salt_a}","role":"viewer"}}"#
        );
        let (status, reply) = handle(&repo, "POST", "/admin/admins", &create_admin, Some(&owner_tok));
        assert_eq!(status, 200, "{reply}");
        let login_ops = format!(r#"{{"user":"ops","pass_hash":"{hash_a}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/admin/login", &login_ops, None);
        assert_eq!(status, 200, "{reply}");
        let ops_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        let (status, _) = handle(&repo, "POST", "/admin/users", &create, Some(&ops_tok));
        assert_eq!(status, 403);

        let (status, reply) = handle(&repo, "GET", "/admin/audit?page=1", "", Some(&owner_tok));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("user_create"));

        let (status, _) = handle(&repo, "POST", "/forgot", r#"{"user":"carol"}"#, None);
        assert_eq!(status, 200);
        let (empty, _) = repo.list_outbox(1, 10)?;
        assert!(empty.is_empty());
        let verify = repo.issue_email_code("carol", "carol@example.com", "verify_email")?;
        assert!(repo.confirm_email("carol", &verify)?);
        let (status, _) = handle(&repo, "POST", "/forgot", r#"{"user":"carol"}"#, None);
        assert_eq!(status, 200);
        let (status, reply) = handle(&repo, "GET", "/admin/outbox", "", Some(&owner_tok));
        assert_eq!(status, 200, "{reply}");
        let item = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["items"][0].clone();
        assert!(item.get("body").is_none());
        assert_eq!(item["status"], "pending");
        let body: String = repo.lock().query_one("SELECT body FROM mail_outbox WHERE id=$1", &[&item["id"].as_i64().context("required")?])?.get(0);
        let reset_code = body
            .split(|c: char| !c.is_ascii_digit())
            .find(|w| w.len() == 6)
            .context("required")?
            .to_owned();
        let new_hash = derive_pass_hash("carol-new", &salt_u).context("required")?;
        let (status, reply) = handle(
            &repo,
            "POST",
            "/reset",
            &format!(r#"{{"user":"carol","code":"{reset_code}","pass_hash":"{new_hash}","salt":"{salt_u}"}}"#),
            None,
        );
        assert_eq!(status, 200, "{reply}");
        let login_c = format!(r#"{{"user":"carol","pass_hash":"{new_hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/login", &login_c, None);
        assert_eq!(status, 200);
        let carol_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        let (status, _) = handle(
            &repo,
            "POST",
            "/api/self/vault",
            r#"{"kdf_salt":"aabbccddeeff0011","wrapped_urk":"aa","urk_nonce":"bb"}"#,
            Some(&carol_tok),
        );
        assert_eq!(status, 200);
        let (status, reply) = handle(&repo, "GET", "/api/self/vault", "", Some(&carol_tok));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("wrapped_urk"));

        let (status, reply) = handle(&repo, "POST", "/admin/totp/begin", "", Some(&owner_tok));
        assert_eq!(status, 200, "{reply}");
        let secret = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["secret"]
            .as_str()
            .context("required")?
            .to_owned();
        let code = crate::totp::generate(&secret, chrono::Utc::now().timestamp()).context("required")?;
        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/totp/confirm",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&owner_tok),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "POST", "/admin/login", &login, None);
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("totp_required"));
        let ticket = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["ticket"]
            .as_str()
            .context("required")?
            .to_owned();
        let code = crate::totp::generate(&secret, chrono::Utc::now().timestamp()).context("required")?;
        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/login/totp",
            &format!(r#"{{"ticket":"{ticket}","code":"{code}"}}"#),
            None,
        );
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("token"));
        Ok(())
    }

    #[test]
    fn admin_ban_kick_soft_delete() -> Result<()> {
        let repo = repo()?;
        let (token, _salt, hash) = register_user(&repo, "bob")?;
        let body = format!(
            r#"{{"id":"m1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}}"#
        );
        let (status, _) = handle(&repo, "POST", "/push", &body, Some(&token));
        assert_eq!(status, 200);

        let admin_salt = derive_auth_salt("admin")?;
        let admin_hash = derive_pass_hash("admin", &admin_salt).context("required")?;
        let login = format!(r#"{{"user":"admin","pass_hash":"{admin_hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/admin/login", &login, None);
        assert_eq!(status, 200, "{reply}");
        let admin = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();

        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/users/bob/disable",
            "",
            Some(&admin),
        );
        assert_eq!(status, 200, "{reply}");
        let login_bob = format!(r#"{{"user":"bob","pass_hash":"{hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/login", &login_bob, None);
        assert_eq!(status, 403, "{reply}");
        assert!(reply.contains("disabled"));

        let (status, _) = handle(&repo, "POST", "/admin/users/bob/enable", "", Some(&admin));
        assert_eq!(status, 200);
        let (status, _) = handle(&repo, "POST", "/login", &login_bob, None);
        assert_eq!(status, 200);

        let (status, reply) = handle(&repo, "POST", "/admin/users/bob/kick", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("kicked"));
        assert!(!reply.contains(&token));
        let (status, _) = handle(&repo, "GET", "/pull", "", Some(&token));
        assert_eq!(status, 401);

        let (status, reply) = handle(&repo, "POST", "/login", &login_bob, None);
        assert_eq!(status, 200, "{reply}");
        let new_tok = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        let (status, reply) = handle(&repo, "GET", "/pull", "", Some(&new_tok));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("m1"));

        let (status, reply) = handle(&repo, "POST", "/admin/users/bob/delete", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "POST", "/login", &login_bob, None);
        assert_eq!(status, 403, "{reply}");
        assert!(reply.contains("deleted"));
        let (status, _) = handle(&repo, "GET", "/pull", "", Some(&new_tok));
        assert_eq!(status, 401);

        let (status, reply) = handle(&repo, "GET", "/admin/users", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("\"deleted\":true") || reply.contains("\"deleted\": true"));

        let (status, _) = handle(&repo, "POST", "/admin/users/bob/restore", "", Some(&admin));
        assert_eq!(status, 200);
        let (status, reply) = handle(&repo, "POST", "/login", &login_bob, None);
        assert_eq!(status, 200, "{reply}");
        let restored = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        let (status, reply) = handle(&repo, "GET", "/pull", "", Some(&restored));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("m1"));
        Ok(())
    }

    #[test]
    fn vault_stores_version() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "vera")?;
        let (status, _) = handle(
            &repo,
            "POST",
            "/api/self/vault",
            r#"{"kdf_salt":"aabbccddeeff0011","wrapped_urk":"aa","urk_nonce":"bb","version":3}"#,
            Some(&token),
        );
        assert_eq!(status, 200);
        let (status, reply) = handle(&repo, "GET", "/api/self/vault", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("\"version\":3") || reply.contains("\"version\": 3"));
        Ok(())
    }

    #[test]
    fn v2_capabilities_push_pull_and_v1_max_forget() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "syncer")?;
        let (status, reply) = handle(&repo, "GET", "/sync/capabilities", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        let cap: serde_json::Value = serde_json::from_str(&reply)?;
        let epoch = cap["epoch"].as_str().context("epoch")?.to_owned();
        let blob = serde_json::json!({
            "id": "11111111-1111-4111-8111-111111111111",
            "user": "syncer",
            "ciphertext": "aa",
            "nonce": "11",
            "embedding_enc": "",
            "updated_at": "2026-09-22T00:00:00.000Z",
            "deleted": false
        });
        let body = serde_json::json!({
            "epoch": epoch,
            "items": [{
                "op_id": "op-1",
                "base_rev": null,
                "parent_op_id": null,
                "blob": blob
            }]
        });
        let (status, reply) = handle(&repo, "POST", "/v2/push/batch", &body.to_string(), Some(&token));
        assert_eq!(status, 200, "{reply}");
        let pull = format!("/v2/pull?epoch={epoch}&after=0");
        let (status, reply) = handle(&repo, "GET", &pull, "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("11111111-1111-4111-8111-111111111111"));
        let (status, reply) = handle(&repo, "GET", "/max", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            "/forget",
            r#"{"id":"11111111-1111-4111-8111-111111111111"}"#,
            Some(&token),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/ready", "", None);
        assert_eq!(status, 200, "{reply}");
        let (status, _) = handle(&repo, "POST", "/forgot", r#"{"user":"syncer"}"#, None);
        assert_eq!(status, 200);
        Ok(())
    }

    #[test]
    fn self_email_and_totp_begin() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "mailer")?;
        let (status, reply) = handle(
            &repo,
            "POST",
            "/api/self/email",
            r#"{"email":"not-an-email"}"#,
            Some(&token),
        );
        assert_eq!(status, 400, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            "/api/self/email",
            r#"{"email":"a@b.c"}"#,
            Some(&token),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "POST", "/api/self/totp/begin", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("secret") || reply.contains("otpauth"));
        Ok(())
    }

    #[test]
    fn self_sessions_rotate_and_readonly() -> Result<()> {
        let repo = repo()?;
        let (token, _, _) = register_user(&repo, "sess")?;
        let (status, reply) = handle(&repo, "GET", "/api/self", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/api/self/sessions", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            "/api/self/sessions",
            r#"{"device_name":"reader","readonly":true}"#,
            Some(&token),
        );
        assert_eq!(status, 200, "{reply}");
        let ro = serde_json::from_str::<serde_json::Value>(&reply)?;
        let ro_tok = ro["token"].as_str().context("ro token")?.to_owned();
        let sid = ro["session_id"].as_str().context("sid")?.to_owned();
        let (status, reply) = handle(
            &repo,
            "POST",
            "/push",
            r#"{"id":"m1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}"#,
            Some(&ro_tok),
        );
        assert_eq!(status, 403, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/pull", "", Some(&ro_tok));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            &format!("/api/self/sessions/{sid}/revoke"),
            "",
            Some(&token),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "POST", "/api/self/rotate", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        let (status, _) = handle(&repo, "GET", "/pull", "", Some(&token));
        assert_eq!(status, 401);
        Ok(())
    }

    #[test]
    fn admin_me_audit_export_and_env_token() -> Result<()> {
        let repo = repo()?;
        let _ = register_user(&repo, "bob")?;
        let admin_salt = derive_auth_salt("admin")?;
        let admin_hash = derive_pass_hash("admin", &admin_salt).context("required")?;
        let login = format!(r#"{{"user":"admin","pass_hash":"{admin_hash}"}}"#);
        let (status, reply) = handle(&repo, "POST", "/admin/login", &login, None);
        assert_eq!(status, 200, "{reply}");
        let admin = serde_json::from_str::<serde_json::Value>(&reply).context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();
        let (status, reply) = handle(&repo, "GET", "/admin/me", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/admin/audit", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/admin/outbox", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/admin/admins", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/admin/users?export=1", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle_full(
            &repo,
            "GET",
            "/admin/me",
            "",
            Some("env-secret"),
            Some("env-secret"),
        );
        assert_eq!(status, 200, "{reply}");
        assert!(reply.contains("env"));
        let (status, _) = handle(&repo, "GET", "/admin/me", "", None);
        assert_eq!(status, 401);
        let (status, _) = handle(&repo, "POST", "/register", "not-json", None);
        assert_eq!(status, 400);
        let (status, reply) = handle(&repo, "GET", "/admin/users/bob/sessions", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            "/admin/users/bob/sessions",
            r#"{"device_name":"ops"}"#,
            Some(&admin),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "POST", "/admin/users/bob/rotate", "", Some(&admin));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/admin/nope", "", Some(&admin));
        assert_eq!(status, 404, "{reply}");
        Ok(())
    }

    #[test]
    fn self_password_keys_and_push_batch() -> Result<()> {
        let repo = repo()?;
        let (token, salt, _) = register_user(&repo, "pat")?;
        let (status, reply) = handle(&repo, "GET", "/api/self/keys", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            "/api/self/password",
            &format!(r#"{{"pass_hash":"abcd","salt":"{salt}"}}"#),
            Some(&token),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            "/push/batch",
            r#"{"items":[{"id":"b1","ciphertext":"aa","nonce":"11","updated_at":"2026-09-02T00:00:00.000Z","deleted":false}]}"#,
            Some(&token),
        );
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(&repo, "GET", "/count", "", Some(&token));
        assert_eq!(status, 200, "{reply}");
        let (status, reply) = handle(
            &repo,
            "POST",
            "/api/self/email/confirm",
            r#"{"code":"000000"}"#,
            Some(&token),
        );
        assert_eq!(status, 401, "{reply}");
        let (status, reply) = handle(&repo, "POST", "/api/self/purge", r#"{"confirm":"nope"}"#, Some(&token));
        assert_eq!(status, 400, "{reply}");
        Ok(())
    }

    static CLI_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct DataDirGuard(Option<String>);
    impl Drop for DataDirGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("ONEMEMORY_DATA_DIR", v),
                None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
            }
        }
    }

    fn lock_cli_env() -> (std::sync::MutexGuard<'static, ()>, DataDirGuard) {
        let guard = CLI_ENV.lock().unwrap_or_else(|e| e.into_inner());
        static KEYRING: std::sync::Once = std::sync::Once::new();
        KEYRING.call_once(|| {
            // HTTP fixtures must not write the developer's OS credential store.
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
        (guard, DataDirGuard(std::env::var("ONEMEMORY_DATA_DIR").ok()))
    }

    fn spawn_live(url: String) -> Result<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok(repo) = BlobRepo::connect(&url) else { return; };
            let _ = crate::http::serve_with_ready("127.0.0.1:0", repo, None, Some(tx));
        });
        let addr = rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .context("live server ready")?;
        Ok(format!("http://{addr}"))
    }

    fn use_dir(path: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(path)?;
        std::env::set_var("ONEMEMORY_DATA_DIR", path);
        Ok(())
    }

    /// CLI over real HTTP: register/login/vault v3/new-device unlock, then push-pull ciphertext.
    #[test]
    fn cli_http_register_login_vault_push_pull() -> Result<()> {
        let _lock = lock_cli_env();
        let root = tempfile::tempdir().context("required")?;
        let live = crate::store::connect_unique()?;
        let base = spawn_live(live.url.clone())?;

        use_dir(&root.path().join("dev-a"))?;
        let secret = respire::service::register(&base, "alice", "login-pass", "")
            .context("required")?
            .context("register must issue a super password")?;
        assert!(secret.starts_with("A3-"));
        let sess = respire::auth::read_session_json().context("required")?;
        assert_eq!(sess["vault_version"].as_i64(), Some(4));

        let issued = respire::service::login(
            &base,
            "alice",
            "login-pass",
            Some(&secret),
            Some(&secret),
            false,
        )
        .context("required")?;
        assert!(issued.is_none());
        let token = respire::auth::read_session_json().context("required")?["token"]
            .as_str()
            .context("required")?
            .to_owned();

        let keys = respire::auth::load_local_session().context("required")?;
        let data_key = respire::memory::crypto::derive_subkey(&keys.urk, b"onememory:data:v1")?;
        let payload = serde_json::json!({
            "kind": "context",
            "tags": "",
            "title": "cli-http",
            "content": "regression memory",
            "user": "alice",
            "computer": "t",
            "project": "p",
            "created_at": "2026-09-11T00:00:00.000Z",
            "updated_at": "2026-09-11T00:00:00.000Z",
        })
        .to_string();
        let (nonce, ciphertext) = respire::memory::crypto::encrypt_item(&data_key, &payload).context("required")?;
        let mut blob = respire::StoredMemory::new_pending(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            "alice".into(),
        );
        blob.ciphertext = ciphertext;
        blob.nonce = nonce;
        blob.updated_at = "2026-09-11T00:00:00.000Z".into();
        let remote = respire::transport::remote::RemoteTransport::new(
            respire::transport::remote::RemoteConfig {
                address: base.clone(),
                token: token.clone(),
            },
        );
        use respire::MemoryTransport;
        remote.put(&blob).context("required")?;

        use_dir(&root.path().join("dev-b"))?;
        assert!(respire::service::login(
            &base,
            "alice",
            "login-pass",
            Some("A3-000000-000000-000000-000000-000000-000000"),
            None,
            false,
        )
        .is_err());
        assert!(respire::service::login(
            &base,
            "alice",
            "login-pass",
            Some("super-pass"),
            Some("A3-000000-000000-000000-000000-000000-000000"),
            false,
        )
        .is_err());
        let issued = respire::service::login(
            &base,
            "alice",
            "login-pass",
            Some(&secret),
            None,
            false,
        )
        .context("required")?;
        assert!(issued.is_none());
        let sess_b = respire::auth::read_session_json().context("required")?;
        assert!(!sess_b.as_object().context("required")?.contains_key("secret_key"), "v4 must not store the plaintext key in session");
        let keys_b = std::env::set_var("ONEMEMORY_SUPER", &secret);
        let keys_b = respire::auth::load_local_session().context("required")?;
        std::env::remove_var("ONEMEMORY_SUPER");
        let _ = keys_b;
        assert_eq!(keys_b.urk, keys.urk);
        let remote_b = respire::transport::remote::RemoteTransport::new(
            respire::transport::remote::RemoteConfig {
                address: base.clone(),
                token: sess_b["token"].as_str().context("required")?.to_owned(),
            },
        );
        let pulled = remote_b
            .all(false)
            .context("required")?
            .into_iter()
            .find(|m| m.id == blob.id)
            .context("required")?;
        let data_key_b =
            respire::memory::crypto::derive_subkey(&keys_b.urk, b"onememory:data:v1")?;
        let plain = respire::memory::crypto::decrypt_item(
            &data_key_b,
            &pulled.ciphertext,
            &pulled.nonce,
        )
        .context("required")?;
        assert!(plain.contains("regression memory"));
        Ok(())
    }

    /// Legacy vault v2 (super password only) upgrades to v3 on CLI login and issues a Secret Key.
    #[test]
    fn cli_http_v2_vault_upgrades_to_v3() -> Result<()> {
        let _lock = lock_cli_env();
        let root = tempfile::tempdir().context("required")?;
        let super_pass = "super-pass";
        let repo = repo()?;
        {
            let (token, _, _) = register_user(&repo, "bob")?;
            let salt = respire::memory::crypto::random_hex(16);
            let kek = respire::memory::crypto::derive_super_kek(super_pass, &salt).context("required")?;
            let urk = respire::memory::crypto::generate_key();
            let (nonce, wrapped) = respire::memory::crypto::wrap_key(&urk, &kek).context("required")?;
            let body = serde_json::json!({
                "kdf_salt": salt,
                "wrapped_urk": wrapped,
                "urk_nonce": nonce,
                "version": 2
            })
            .to_string();
            let (status, _) = handle(&repo, "POST", "/api/self/vault", &body, Some(&token));
            assert_eq!(status, 200);
        }
        let base = spawn_live(repo.url.clone())?;
        use_dir(&root.path().join("dev-v2"))?;
        let issued = respire::service::login(
            &base,
            "bob",
            "pass-1234",
            Some(super_pass),
            None,
            false,
        )
        .context("required")?;
        let secret = issued.context("v2 login must issue a super password")?;
        let sess = respire::auth::read_session_json().context("required")?;
        assert_eq!(sess["vault_version"].as_i64(), Some(4));

        use_dir(&root.path().join("dev-v2-new"))?;
        respire::service::login(&base, "bob", "pass-1234", Some(&secret), None, false).context("required")?;
        assert_eq!(
            respire::auth::read_session_json().context("required")?["vault_version"].as_i64(),
            Some(4)
        );
        Ok(())
    }

    /// Legacy account with no vault: CLI login --super mints v3 on the spot.
    #[test]
    fn cli_http_legacy_account_gets_vault() -> Result<()> {
        let _lock = lock_cli_env();
        let root = tempfile::tempdir().context("required")?;
        let repo = repo()?;
        register_user(&repo, "carol")?;
        let base = spawn_live(repo.url.clone())?;
        use_dir(&root.path().join("dev-legacy"))?;
        let issued = respire::service::login(
            &base,
            "carol",
            "pass-1234",
            Some("super-pass"),
            None,
            false,
        )
        .context("required")?;
        let secret = issued.context("account without vault must issue a super password")?;
        let sess = respire::auth::read_session_json().context("required")?;
        assert_eq!(sess["vault_version"].as_i64(), Some(4));
        assert!(!sess.as_object().context("required")?.contains_key("secret_key"), "v4 must not store the plaintext key in session");

        use_dir(&root.path().join("dev-legacy-new"))?;
        respire::service::login(
            &base,
            "carol",
            "pass-1234",
            Some(&secret),
            Some(&secret),
            false,
        )
        .context("required")?;
        // headless bypass: ONEMEMORY_SUPER unlocks when no keyring is present
        std::env::set_var("ONEMEMORY_SUPER", &secret);
        respire::auth::load_local_session().context("required")?;
        std::env::remove_var("ONEMEMORY_SUPER");
        Ok(())
    }
