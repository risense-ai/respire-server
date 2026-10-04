# Browser API boundary and staged frontend cutover

The producer is `risense-ai/respire-server`. Homepage, Dashboard and Admin are owned by `risense-ai/respire-site`. Cloud frontend
builds set the public `VITE_API_BASE_URL` to the chosen HTTPS API origin, normally
`https://api.rsrs.rs`. No secret belongs in a `VITE_*` variable.

## Exact API source proof

`GET /health` returns the existing `ok`, `service`, and `version` fields plus
`source_revision`. Official image workflows first verify checkout `HEAD` equals
`GITHUB_SHA` and tracked source is clean, then pass that full SHA as the
`RESPIRE_BUILD_REVISION` Docker build argument. `service/build.rs` validates it
and compiles it into the binary; changing runtime environment variables cannot
alter the reported revision. Ad-hoc builds with no provenance are explicitly
`unknown` and must fail strict hosted release acceptance. The Docker image smoke
checks the JSON revision against the exact CI checkout.

Consumers must check the API endpoint's compiled `source_revision` independently
of frontend build metadata and reject missing, unknown, or different revisions.
Do not accept a frontend-supplied version or a legacy nginx header as a replacement
for this API source proof. This is build provenance within the reviewed build
pipeline, not a claim of externally signed artifact attestation.

## Cross-origin contract

`RESPIRE_CORS_ALLOWED_ORIGINS` is a comma-separated list of **exact serialized
origins**, without a trailing slash. It is empty by default. For the production
Dashboard/Admin hostnames the intended value is:

```
https://dash.rsrs.rs,https://admin.rsrs.rs
```

This document describes source configuration, not a verification of live DNS,
proxy, account, or Pages configuration. Configure the API before publishing the
Pages frontends. Restart/recreate the API process to apply a changed allowlist.
Only HTTPS remote origins are accepted. Explicit `http://localhost:<port>` and
literal loopback origins support isolated development. `*`, wildcard suffixes,
`null`, userinfo, paths, queries, fragments and malformed ports fail startup.
Preview origins must be individually configured against an isolated test API;
do not put arbitrary `*.pages.dev` or previews into production's allowlist.

- Actual cloud requests retain the existing `GET` / `POST` JSON routes and
  explicit `Authorization: Bearer …` tokens. Do not send cookies or use
  `credentials: include`.
- `OPTIONS` for an approved origin returns `204` with allowed methods `GET, POST`
  and headers `Authorization, Content-Type`. Header-name matching is case
  insensitive. Preflight needs no token, body read, or database job. Denied
  origins/headers return `403`; denied/missing requested methods return `405`.
- Approved origins receive exactly one `Access-Control-Allow-Origin` on every
  application-generated response, including `401`, `403`, `408`, `413`, `429`
  and `5xx`. All responses vary on `Origin`; preflights additionally vary on the
  requested method/headers and have a five-minute browser preflight cache.
- CORS does not authenticate users or grant roles. Actual requests still pass
  through the same bearer, administrator role and read-only-session checks.
  Both trusted apps share the API boundary; origin is not an administrator role.
- Requests without `Origin` (native/CLI) and old same-origin nginx frontends
  retain existing processing. Unapproved origins receive no CORS permission;
  they are not a substitute for rejecting unauthorized API requests.
- HTTP parse failures before a request exists, capacity disconnects, upstream
  proxy errors and connection timeouts can be socket/network failures rather
  than decorated JSON. Configure the proxy to pass OPTIONS and response headers
  through; do not add a second conflicting CORS policy.

`service/openapi.yaml` remains a partial sync/self API schema, not a complete
Admin schema. The browser endpoint inventory is maintained alongside it; neither
moving frontends nor adding CORS changes JSON payloads, password hashing, TOTP
challenge tickets, ciphertext/vault formats, sessions, SMTP, or mail-code flows.
Record both deployed source SHAs and the producer contract revision in release
notes. Keep old client compatibility during migration.

## Consumed cloud endpoints

This producer-owned inventory records the moved console boundary from source
`84ad000ae50758756edb077c63c0a1b31eb9ada2`. It supplements the partial OpenAPI
schema. Request/response payloads remain implemented by the existing auth, self,
admin and sync routes and their PostgreSQL tests.

## Public authentication

- POST `/register`: derived user/pass hash/salt and device name; returns user token, followed by encrypted vault setup
- POST `/login`, `/login/totp`: password-derived auth or ticket/code challenge, user token only after challenge completion
- POST `/forgot`, `/reset`: existing email recovery flow
- POST `/admin/login`, `/admin/login/totp`: existing administrator auth/challenge flow

## User bearer

- GET `/api/self`, `/api/self/keys`, `/api/self/sessions`, `/api/self/vault`
- GET `/pull` with optional `since` cursor
- POST `/push`, `/forget`: encrypted memory record or memory ID
- POST `/api/self/sessions`, `/api/self/sessions/{id}/revoke`, `/api/self/rotate`
- POST `/api/self/vault`, `/api/self/password`
- POST `/api/self/email`, `/api/self/email/confirm`
- POST `/api/self/totp/begin`, `/api/self/totp/confirm`, `/api/self/totp/disable`
- POST `/api/self/purge`: existing explicit account confirmation

## Administrator bearer and existing role checks

- GET `/admin/me`, `/admin/admins`, `/admin/outbox`, `/admin/audit` (page query)
- GET `/admin/users` (`q`, `page`, `limit`, `status`, optional `export`)
- GET `/admin/users/{user}/sessions`
- POST `/admin/users`, `/admin/admins`, `/admin/admins/{user}/revoke`
- POST `/admin/users/{user}/sessions`, `/admin/users/{user}/sessions/{id}/revoke`
- POST `/admin/users/{user}/update`, `/admin/users/{user}/kick`, `/admin/users/{user}/restore`, `/admin/users/{user}/delete`, `/admin/users/{user}/purge`
- POST `/admin/password`, `/admin/totp/begin`, `/admin/totp/confirm`, `/admin/totp/disable`

Path parameters representing user names are URL-encoded by the retained consumer. No endpoint becomes authorized merely because its UI is present. Existing role filtering and producer enforcement remain unchanged. Email binding and TOTP business-policy changes are outside this PR.

## Ordered rollout and acceptance

1. Review and merge the API and Site changes. Build the API artifact only from
   the exact server revision that passes Server CI and Server image tests.
2. Deploy **only API** using [API deployment instructions](api-deployment.md),
   configure trusted origins, and verify preflight plus actual successful/error
   responses at the public API endpoint. Existing web containers, web image
   references, proxy routes, and DNS remain untouched.
3. Build/deploy Dashboard and Admin Pages from the reviewed Site revision.
   Exercise sign-in, invalid credentials, user/Admin TOTP, token expiry, viewer
   and read-only rejection, existing email/reset flows, vault unlock,
   encrypt/decrypt/sync, direct/deep-link reload, and Back/Forward. Use synthetic
   identities and a dedicated test mail environment for any mail acceptance.
   Do not assume isolated fixture tests prove a live SMTP or production account.
4. Only after both frontends and API pass acceptance, separately authorize and
   perform traffic migration. Keep the same hostname/scheme/port where possible
   so browser storage stays at the same origin. Otherwise require fresh sign-in;
   never move tokens or recovery material through URLs.
5. Retire legacy static containers/routes **only after** a verified rollback
   window and explicit operational approval. Source deletion does not stop those
   containers. Retain their immutable images/configs before the API-first rollout;
   API rollback must not require rebuilding the Site or retired web source.

The obsolete local `web` console command/API is retired, not deployed to Pages.
The native CLI/runtime, desktop frontend and independent loopback read-only
`access` API are separate and remain in place. No user profile/data files are
removed by this source change.

## External release acceptance dependency

The CLI repository's current `release.yml` `web-smoke` job checks out
`respire-server` at `RESPIRE_DEV_CONSOLE_SHA`, runs `admin-ui`, and checks Server CI
for that console revision. That remains usable with the retained historical
pre-extraction console SHA during API-first staging. Do not change that pin to a
new Server revision (which contains no frontend), or to a Site SHA without
migrating the workflow's source repository, directory and CI gate together.

The CLI `scripts/dev-api-coverage.json` also pins `server_source_sha`; its smoke
runner checks that against `RESPIRE_DEV_SERVER_SHA`. Review and refresh that
producer coverage contract when advancing the development API revision, before
expecting API-first acceptance to pass. This is an explicit dependent change,
not a reason to bypass the SHA check.

Before new Pages acceptance, update the CLI consumer to checkout the Site console
and its producer-appropriate CI workflow, and run a split-origin browser harness.
Track the API `RESPIRE_DEV_SERVER_SHA`, console `RESPIRE_DEV_CONSOLE_SHA`, and
homepage `RESPIRE_DEV_SITE_SHA` independently; they need not be equal. The legacy
harness expects its historical same-origin development routing and header
provenance. Source fixture tests do not make that live harness Pages-ready.
Keep old pins until the new acceptance consumer is reviewed and deployed; do not
silently waive release gates or dispatch hosted/mailbox acceptance in this change.

`scripts/read-dev-mail.py` is intentionally retained for compatibility with
backend/external acceptance commands. The Site console also carries its historical
copy. Neither helper is run by normal PR checks.
