# Manual DEV Passkey acceptance (Linux)

This is a synthetic API test, not a deployment job or browser/provider certification.
The `DEV passkey synthetic acceptance` workflow is **workflow_dispatch only**.
It has no URL, revision, credential or other inputs; no repository secrets are
needed. PR/push CI runs only offline safety tests and loopback HTTP test servers.

## Dispatch gate

An operator must first confirm the reviewed script/workflow revision, the deployed
DEV revision, and that any earlier interrupted fixture's sessions are revoked.
Do not overlap external/manual runs with the workflow. Its fixed concurrency group
serializes all workflow refs without cancelling an in-progress run. The workflow
does not deploy, publish an image, change server settings or target production.

The script fails before account creation unless all of these pass:

- API exactly `https://api.dev.rsrs.rs`, normal TLS validation, no redirects
- `/health`: service `respire`, OK, source revision exactly
  `686f1d1e84721675906e792c71b96cde4772429e`
- `/ready`: database ready and OK

At the pinned revision, `BlobRepo::ready` compares schema metadata to the exact
current migration version **9**. After creating each fresh account and checking
its identity, discovery must show both Passkey and trusted-browser features
enabled, RP `dash.dev.rsrs.rs`, origin `https://dash.dev.rsrs.rs`.
There is no revision override. Changing the deployed acceptance target requires
a reviewed code change. Use dot Linux or GitHub Linux, not the user's PC.

## What a successful run proves

The fixed workflow invocation includes the real **306-second expiry wait**. The
software authenticator creates P-256 WebAuthn credentials and correctly signed
assertions, with two fresh UV-required assertions before activation. Checks cover
trusted-browser wrapping/unlock, existing PRF-mode API compatibility, recovery
wrapper preservation, local AES-GCM round trips, account/session/device/mode
binding, replay, missing UV, signed invalid origin/RP/challenge/user handle,
cancellation at each enrollment phase, owned removal, same-URK rewrap and
reset/generation invalidation. Passkey responses require `Cache-Control: no-store`.

The PRF result is deliberately simulated HMAC input to the protocol HKDF. Trusted
mode uses an in-memory AES key. Recovery and memory values are synthetic AES-GCM
fixtures, not the production superpassword KDF or CLI/Core memory format. This
does not test Bitwarden, physical UV, browser PRF support, IndexedDB key persistence,
or the real frontend. Functional acceptance does not imply performance acceptance.

## Bounds and cleanup

- Hard 30-second total HTTP open/read/parse/check deadline, plus inactivity timeout
- Hard 1800-second monotonic run budget including the expiry wait and cleanup
- At most 180 requests; at most 1 MiB per response; no redirect or automatic retry
- Standalone Linux main thread; one SIGALRM owner; existing active alarms refused
- Workflow smoke step 32 minutes and job 40 minutes, leaving reporting/upload room

The report write occurs after the API budget; it does not permit additional HTTP
requests. An overall deadline stops requests and marks incomplete cleanup. Missing
or unfinished results after runner cancellation are **unknown/incomplete**, never
success. A final result needs `ok: true`, `expiry_tested: true` and completed cleanup.
`expiry_requested` alone is not proof the expiry stage ran.

At most two fresh randomly named `tb-smoke-...` accounts are created. No existing
user or admin credentials are accepted. Only newly created, identity-verified
accounts can be mutated. Cleanup revokes their own Passkeys, tracked pending
ceremonies and returned sessions, then requires the original token to receive 401.
Account/vault records, synthetic encrypted memory and ordinary audit history are
retained; this tool never purges accounts or deletes memory history.

The public journal is atomically replaced before registration and immediately
updated after confirmation. It contains only the generated username, client UTC
timestamps, canonical account UUID once available, safe route templates/status/
timing, check names and cleanup states. The creation-pending username is also
flushed to stdout before `POST /register` so an operator can identify uncertain
creation if the runner stops before artifact upload. Failed journal writes stop
new acceptance requests but still permit scoped cleanup with credentials already
in memory. Final journal failure cannot report success.

Passwords, pass hashes, tokens, session IDs, private authenticator keys, device
keys, URKs, PRF material, HTTP headers/bodies and exception details are not persisted
or printed. No token-storage permission is assumed. Session route diagnostics
use `:session_id`; query strings are removed. The artifact allowlist contains only
`progress.json` and `result.json`, retained seven days. Upload uses `always()` but
cannot be guaranteed after abrupt runner loss. For an interrupted run, use the
public username/UUID to verify and revoke only its synthetic sessions through an
authorized operator route; do not automatically retry registration or purge data.

## Offline checks and local fixture

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r scripts/dev-passkey-smoke/requirements.txt
.venv/bin/python -m unittest discover -s scripts/dev-passkey-smoke -v
```

These tests do not contact DEV. They exercise real loopback slow-stream deadlines,
redirect refusal, response caps, timer restoration, interrupted cleanup, signed
negative values, preflight-before-write, redaction, public-journal ordering/atomicity,
UUID validation, final-write errors and the workflow safety boundary.

For a disposable local API with the same source revision and RP/origin/flags:

```sh
.venv/bin/python scripts/dev-passkey-smoke/smoke.py \
  --local-test --base-url http://127.0.0.1:18787 --include-expiry \
  --journal /tmp/local-smoke-progress.json --report /tmp/local-smoke-result.json
```

Local mode accepts only HTTP `127.0.0.1` with an explicit port. It does not weaken
the source, readiness, protocol or feature checks. No local server or database is
started by the script. Do not dispatch live acceptance from PR CI.
