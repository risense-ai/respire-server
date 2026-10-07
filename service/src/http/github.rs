//! Fixed-origin GitHub authorization code flow. Provider tokens never enter storage.
use super::json::{json, server_error};
use crate::store::BlobRepo;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::{json as value, Value};
use sha2::{Digest, Sha256};
use std::{io::Read, time::Duration};

struct Config {
    client: String,
    secret: String,
    redirect: String,
}

pub(super) fn check_config() -> Result<()> {
    Config::read().map(|_| ())
}

impl Config {
    fn read() -> Result<Option<Self>> {
        let client = crate::env::var("RSRS_GITHUB_CLIENT_ID").unwrap_or_default();
        let secret = crate::env::var("RSRS_GITHUB_CLIENT_SECRET").unwrap_or_default();
        let redirect = crate::env::var("RSRS_GITHUB_REDIRECT_URI").unwrap_or_default();
        let dashboard = crate::env::var("RSRS_DASHBOARD_URL")
            .unwrap_or_else(|_| "https://dash.rsrs.rs".into());
        Self::parse(client, secret, redirect, &dashboard)
    }

    fn parse(
        client: String,
        secret: String,
        redirect: String,
        dashboard: &str,
    ) -> Result<Option<Self>> {
        if client.is_empty() && secret.is_empty() && redirect.is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(
            !client.is_empty() && !secret.is_empty(),
            "incomplete GitHub configuration"
        );
        let uri = url::Url::parse(&redirect).context("invalid GitHub callback")?;
        let dashboard = url::Url::parse(dashboard)?;
        anyhow::ensure!(
            uri.scheme() == "https"
                && uri.origin() == dashboard.origin()
                && uri.username().is_empty()
                && uri.password().is_none()
                && uri.path() == "/"
                && uri.query().is_none()
                && uri.fragment().is_none(),
            "GitHub callback must be the HTTPS dashboard root"
        );
        Ok(Some(Self {
            client,
            secret,
            redirect,
        }))
    }

    fn authorize(&self, state: &str, verifier: &str) -> Result<String> {
        let mut uri = url::Url::parse("https://github.com/login/oauth/authorize")?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        uri.query_pairs_mut().extend_pairs([
            ("client_id", self.client.as_str()),
            ("redirect_uri", self.redirect.as_str()),
            ("state", state),
            ("scope", ""),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("prompt", "select_account"),
        ]);
        Ok(uri.into())
    }

    fn identity(&self, code: &str, verifier: &str) -> Result<Identity> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(15))
            .redirects(0)
            .build();
        self.identity_at(
            &agent,
            code,
            verifier,
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
        )
    }

    fn identity_at(
        &self,
        agent: &ureq::Agent,
        code: &str,
        verifier: &str,
        token_uri: &str,
        user_uri: &str,
    ) -> Result<Identity> {
        let response = agent
            .post(token_uri)
            .set("Accept", "application/json")
            .set("User-Agent", "Respire")
            .send_form(&[
                ("client_id", &self.client),
                ("client_secret", &self.secret),
                ("redirect_uri", &self.redirect),
                ("code", code),
                ("code_verifier", verifier),
            ])
            .map_err(|_| anyhow::anyhow!("GitHub token exchange failed"))?;
        let token = read_json(response)?;
        let token = token
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .context("GitHub authorization rejected")?;
        let response = agent
            .get(user_uri)
            .set("Accept", "application/vnd.github+json")
            .set("User-Agent", "Respire")
            .set("Authorization", &format!("Bearer {token}"))
            .call()
            .map_err(|_| anyhow::anyhow!("GitHub identity request failed"))?;
        let identity: Identity = serde_json::from_value(read_json(response)?)?;
        anyhow::ensure!(
            identity.id > 0 && !identity.login.is_empty() && identity.login.len() <= 128,
            "invalid GitHub identity"
        );
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn config() -> Config {
        Config {
            client: "fixture-client".into(),
            secret: "fixture-secret".into(),
            redirect: "https://dash.example.invalid/".into(),
        }
    }

    #[test]
    fn configuration_is_disabled_or_complete_and_callback_is_exact() -> Result<()> {
        assert!(Config::parse("".into(), "".into(), "".into(), "invalid-unused")?.is_none());
        assert!(Config::parse(
            "client".into(),
            "".into(),
            "".into(),
            "https://dash.example.invalid"
        )
        .is_err());
        for redirect in [
            "http://dash.example.invalid/",
            "https://evil.example.invalid/",
            "https://dash.example.invalid/path",
            "https://dash.example.invalid/?query=1",
            "https://dash.example.invalid/#fragment",
            "https://user@dash.example.invalid/",
        ] {
            assert!(Config::parse(
                "client".into(),
                "secret".into(),
                redirect.into(),
                "https://dash.example.invalid"
            )
            .is_err());
        }
        assert!(Config::parse(
            "client".into(),
            "secret".into(),
            "https://dash.example.invalid/".into(),
            "https://dash.example.invalid"
        )?
        .is_some());
        Ok(())
    }

    #[test]
    fn authenticated_github_routes_preserve_session_and_reject_readonly_changes() -> Result<()> {
        let repo = crate::store::connect_unique()?;
        let token = repo
            .register("route-user", "hash", "salt")?
            .context("user")?;
        let handle = |method, path, body, token: &str| {
            crate::http::handle_full(&repo, method, path, body, Some(token), None)
        };
        assert_eq!(handle("GET", "/api/self/github", "", &token).0, 200);
        assert_eq!(
            handle("POST", "/api/self/github/vault", "{}", &token).0,
            400
        );
        assert_eq!(
            handle(
                "POST",
                "/api/self/github/vault",
                r#"{"kdf_salt":"bad","wrapped_urk":"bad","urk_nonce":"bad","version":4}"#,
                &token
            )
            .0,
            400
        );
        let (readonly, _) = repo.create_session_with("route-user", "readonly", true)?;
        assert_eq!(
            handle("POST", "/api/self/github/unbind", "", &readonly).0,
            403
        );
        assert!(repo.bind_github("route-user", 800, "route-provider")?);
        assert_eq!(handle("POST", "/api/self/github/unbind", "", &token).0, 200);
        assert_eq!(
            repo.try_user_from_token(&token)?,
            Some("route-user".to_owned())
        );
        repo.user_set_password("route-user", "", "salt")?;
        assert_eq!(handle("POST", "/api/self/github/unbind", "", &token).0, 409);
        Ok(())
    }

    #[test]
    fn authorization_uses_exact_callback_pkce_and_no_repository_scope() -> Result<()> {
        let uri = url::Url::parse(&config().authorize("state", "verifier")?)?;
        assert_eq!(uri.origin().ascii_serialization(), "https://github.com");
        let pairs: std::collections::HashMap<_, _> = uri.query_pairs().collect();
        assert_eq!(
            pairs.get("redirect_uri").context("callback")?,
            "https://dash.example.invalid/"
        );
        assert_eq!(pairs.get("code_challenge_method").context("PKCE")?, "S256");
        assert_eq!(
            pairs.get("code_challenge").context("challenge")?,
            &URL_SAFE_NO_PAD.encode(Sha256::digest(b"verifier"))
        );
        assert_eq!(pairs.get("scope").context("scope")?, "");
        Ok(())
    }

    fn provider() -> Result<(tiny_http::Server, String)> {
        let server =
            tiny_http::Server::http("127.0.0.1:0").map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let origin = format!("http://{}", server.server_addr());
        Ok((server, origin))
    }

    #[test]
    fn provider_exchange_revalidates_identity_and_handles_denial_and_bad_responses() -> Result<()> {
        for (token_json, user_json, expected) in [
            (
                r#"{"access_token":"fixture-token"}"#,
                Some(r#"{"id":42,"login":"fixture-login"}"#),
                true,
            ),
            (r#"{"error":"access_denied"}"#, None, false),
            ("not-json", None, false),
            (
                r#"{"access_token":"fixture-token"}"#,
                Some(r#"{"id":0,"login":"bad"}"#),
                false,
            ),
        ] {
            let (server, origin) = provider()?;
            let token_json = token_json.to_owned();
            let user_json = user_json.map(str::to_owned);
            let worker = std::thread::spawn(move || -> Result<()> {
                let mut request = server
                    .recv_timeout(Duration::from_secs(3))?
                    .context("token request")?;
                assert_eq!(request.url(), "/token");
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body)?;
                let form: std::collections::HashMap<_, _> =
                    url::form_urlencoded::parse(body.as_bytes()).collect();
                assert_eq!(
                    form.get("client_secret").context("secret")?,
                    "fixture-secret"
                );
                assert_eq!(
                    form.get("code_verifier").context("verifier")?,
                    "fixture-verifier"
                );
                request.respond(tiny_http::Response::from_string(token_json))?;
                if let Some(user_json) = user_json {
                    let request = server
                        .recv_timeout(Duration::from_secs(3))?
                        .context("identity request")?;
                    assert_eq!(request.url(), "/user");
                    assert!(request
                        .headers()
                        .iter()
                        .any(|h| h.field.equiv("Authorization")
                            && h.value.as_str() == "Bearer fixture-token"));
                    request.respond(tiny_http::Response::from_string(user_json))?;
                }
                Ok(())
            });
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(2))
                .redirects(0)
                .build();
            let reply = config().identity_at(
                &agent,
                "fixture-code",
                "fixture-verifier",
                &format!("{origin}/token"),
                &format!("{origin}/user"),
            );
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("provider fixture failed"))??;
            assert_eq!(reply.is_ok(), expected);
            if let Ok(identity) = reply {
                assert_eq!(identity.id, 42);
                assert_eq!(identity.login, "fixture-login");
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Identity {
    id: i64,
    login: String,
}

fn read_json(response: ureq::Response) -> Result<Value> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(262145)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 262144, "GitHub response too large");
    serde_json::from_slice(&bytes).context("invalid GitHub response")
}

pub(super) fn route(
    repo: &BlobRepo,
    method: &str,
    path: &str,
    body: &str,
    owner: Option<&str>,
) -> Option<(u16, String)> {
    let authenticated = owner.is_some();
    let base = if authenticated {
        "/api/self/github"
    } else {
        "/oauth/github"
    };
    if path != base
        && path != format!("{base}/start")
        && path != format!("{base}/exchange")
        && path != format!("{base}/unbind")
        && path != format!("{base}/vault")
    {
        return None;
    }
    if method == "GET" && path == "/api/self/github" {
        return Some(match repo.github_binding(owner.unwrap_or_default()) {
            Ok(reply) => json(200, reply),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/github/unbind" {
        return Some(match repo.unbind_github(owner.unwrap_or_default()) {
            Ok(true) => json(200, value!({"bound":false})),
            Ok(false) => json(
                409,
                value!({"error":"set a login password before unlinking GitHub"}),
            ),
            Err(e) => server_error(e),
        });
    }
    if method == "POST" && path == "/api/self/github/vault" {
        let Ok(input) = serde_json::from_str::<super::dto::VaultIn>(body) else {
            return Some(json(400, value!({"error":"bad json"})));
        };
        return Some(
            match repo.initialize_github_vault(
                owner.unwrap_or_default(),
                &input.kdf_salt,
                &input.wrapped_urk,
                &input.urk_nonce,
                input.version,
            ) {
                Ok(true) => json(200, value!({"ok":true})),
                Ok(false) => json(
                    409,
                    value!({"error":"existing vault or memories must be preserved"}),
                ),
                Err(e) if e.to_string() == "invalid initial vault" => {
                    json(400, value!({"error":"invalid initial vault"}))
                }
                Err(e) => server_error(e),
            },
        );
    }
    if method != "POST" {
        return Some(json(405, value!({"error":"method not allowed"})));
    }
    let config = match Config::read() {
        Ok(Some(config)) => config,
        Ok(None) => {
            return Some(json(
                503,
                value!({"error":"GitHub login is not configured"}),
            ))
        }
        Err(_) => return Some(json(503, value!({"error":"invalid GitHub configuration"}))),
    };
    if path == format!("{base}/start") {
        return Some(match repo.start_github_authorization(owner).and_then(|(state,verifier)| {
            Ok(value!({"state":state,"authorization_uri":config.authorize(&state,&verifier)?,"expires_in":600}))
        }) { Ok(reply)=>json(200,reply), Err(e)=>server_error(e) });
    }
    if path != format!("{base}/exchange") {
        return Some(json(404, value!({"error":"not found"})));
    }
    #[derive(Deserialize)]
    struct Exchange {
        state: String,
        code: String,
    }
    let Ok(input) = serde_json::from_str::<Exchange>(body) else {
        return Some(json(400, value!({"error":"bad json"})));
    };
    if input.state.len() != 64
        || !input.state.bytes().all(|b| b.is_ascii_hexdigit())
        || input.code.is_empty()
        || input.code.len() > 512
    {
        return Some(json(400, value!({"error":"invalid GitHub grant"})));
    }
    let verifier = match repo.take_github_authorization(&input.state, owner) {
        Ok(Some(verifier)) => verifier,
        Ok(None) => {
            return Some(json(
                400,
                value!({"error":"GitHub authorization expired or already used"}),
            ))
        }
        Err(e) => return Some(server_error(e)),
    };
    let identity = match config.identity(&input.code, &verifier) {
        Ok(identity) => identity,
        Err(_) => {
            return Some(json(
                502,
                value!({"error":"GitHub authorization failed; please start again"}),
            ))
        }
    };
    Some(if let Some(owner) = owner {
        match repo.bind_github(owner, identity.id, &identity.login) {
            Ok(true) => json(
                200,
                value!({"bound":true,"id":identity.id,"login":identity.login}),
            ),
            Ok(false) => json(
                409,
                value!({"error":"GitHub or Respire account is already linked"}),
            ),
            Err(e) => server_error(e),
        }
    } else {
        match repo.login_github(identity.id, &identity.login, "dashboard") {
            Ok(reply) => json(200, reply),
            Err(e)
                if matches!(
                    e.to_string().as_str(),
                    "account unavailable" | "account name conflict"
                ) =>
            {
                json(409, value!({"error":e.to_string()}))
            }
            Err(e) => server_error(e),
        }
    })
}
