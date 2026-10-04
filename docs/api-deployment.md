# API-first deployment

The manual **API deployment artifact** workflow packages the server image, the API
Compose definition, the operator script and an exact checksum manifest. It runs
only from `main` and requires the latest push run of both `Server CI` (`ci.yml`) and
`Server image` (`server-image.yml`) for the dispatched SHA to have completed
successfully. It does not check out Site, build a console, package a web image,
publish a release, or connect to a host. Artifact creation is not a deployment.

Source ownership and production rollout are separate. The old web image/container
can keep serving the existing UI while the new API is validated. Nothing in this
path changes DNS, nginx, certificates, the web Compose project, or web ports. Deploy
the Site-owned console separately only after its existing session and dashboard
flows work against the new API. Keep the old web runtime until then.

Frontend builds, browser tests and hosted acceptance are Site's responsibility.
The coordinated [CLI cleanup](https://github.com/risense-ai/respire-cli/pull/19)
removes frontend/browser dependencies from CLI publication; it does not make CLI
fetch the Site frontend. CLI and Server API acceptance, including exact source-SHA
gates and API mailbox checks, remain required. See the
[acceptance ownership contract](browser-api-contract.md#acceptance-ownership-and-coordinated-cli-cleanup).
Source merges are separate from live deployment and traffic migration. CI cannot
replace the installation's live-host rollback rehearsal, Pages-domain checks or
mailbox-chain acceptance.

## Operator prerequisites

- An existing installation at `/opt/respire-dev`, `/opt/respire-prod` or `/opt/respire-rehearsal`, with
  `.env`, legacy `compose.yaml`, and the operator-created `.migration-verified`
  marker for a tested restore. This script cannot prepare an empty database.
- The existing `db` service must already be running under the same Compose project
  (`respire-dev`, `respire-prod` or `respire-rehearsal`). The script never starts or recreates it.
- Bash, GNU coreutils, `flock`, `gzip`, `curl`, Docker, and Compose v2 with `--wait`,
  `--no-deps`, and `--pull never` support. No registry credentials are needed to load
  the archive. Disk space must cover a full database dump and loaded server image.
- Retain the existing server image locally for rollback. Its container's immutable
  image ID is captured. A restored DB without a previous server is supported, but
  there is then no automatic selection of a rollback image.
- Coordinate a deployment window. Do not run any other deployment tool, backup
  restore, or Compose lifecycle command concurrently. The lock serializes this
  API script and its generated rollback script only.

Use the artifact from the exact reviewed SHA and verify its provenance before
executing a script from it. Checksums detect corruption, not a malicious publisher.
Do not pass unreviewed host environment overrides: Compose gives shell variables
precedence over env files. The script explicitly sets only the API image/bind/port;
other exported Compose variables remain the operator's responsibility.

## Deploy the API

Download and extract `api-deployment-<server SHA>` from the successful manual run.
Inspect its files and execute in an operator SSH session:

```bash
cd /path/to/extracted-artifact
sha256sum -c SHA256SUMS
bash ssh-deploy-api.sh dev <40-character-server-SHA> "$PWD"
bash ssh-deploy-api.sh rehearsal <40-character-server-SHA> "$PWD"
# After validating rehearsal, use the same reviewed artifact for prod:
bash ssh-deploy-api.sh prod <40-character-server-SHA> "$PWD"
```

The script verifies the complete manifest, revision, and API-only service list;
requires the restored DB; takes a custom-format `pg_dump`; and verifies that dump
using `pg_restore --exit-on-error --file=/dev/null` before stopping the old API.
This archive check complements, and does not replace, the prior operator-tested
restore. It then loads only the packaged image, checks its source revision label,
and pins its immutable image ID. The image compiles the same source SHA into
`/health.source_revision`; strict hosted acceptance checks that JSON field, not
a frontend or proxy-provided version. Only `server` is stopped/recreated. `up` always
uses `--no-deps --no-build --pull never ... server`.

Compose health and a loopback `/ready` request must both succeed. Production stays
on `127.0.0.1:18789`; rehearsal stays on `127.0.0.1:27789`; DEV stays on
`127.0.0.1:28789` under its independent `respire-dev` Compose project and database.
Only after success does
the script install these dedicated managed files:

- `compose-api.yaml`
- `api-deployment.env` (image ID and API bind/port overrides)
- `current-api-revision` (the successful source SHA)

The original `.env`, `deployment.env` (including web settings), `compose.yaml`,
`compose-web.yaml`, `current-revision`, and `current-site-revision` remain unchanged.
The existing optional `/opt/respire-secrets/mxroute.env` is read, never rewritten.
The `api-deployment.env` override is for the API project only; do not add it to a
web deployment command. Make operator-managed API configuration changes in `.env`
or the separately managed secret env, not in the generated image/port override.

For subsequent manual API inspection, use the same project, live env files and
`compose-api.yaml`. Avoid an unqualified `docker compose up` against the old
`compose.yaml`: it does not use the new API image pin by default.

## Failed or interrupted deployment

Each attempt creates a unique, private `api-releases/<SHA>-<timestamp>.<suffix>`
directory and a correspondingly unique `backups/pre-api-<attempt>.dump` plus checksum.
A retry never overwrites earlier rollback snapshots or backups. Snapshots include
sensitive env files, use private permissions, and must not be uploaded as build
artifacts or committed. There is no automatic retention/pruning; apply the
installation's reviewed backup retention policy after its rollback window.

A health failure exits nonzero. The dedicated live config and revision marker
remain at the last successful release, but the actual container may be stopped,
running the candidate, or unhealthy. The marker is not evidence of current health.
An `api-deployment-incomplete` file identifies the attempt and blocks another
rollout until recovery. Inspect the reported snapshot's `ROLLBACK.md`, logs and
readiness before any further action.

The pre-upgrade database dump is never automatically restored. Decide whether any
schema migration is compatible with the old image before an image rollback. For
an incompatible schema, plan an explicit operator-reviewed restore and maintenance
window; a container/image rollback alone cannot undo database changes.

After confirming schema compatibility, use the snapshot printed by the failed
attempt:

```bash
bash /opt/respire-prod/api-releases/<attempt>/rollback-api.sh --schema-compatible
```

The generated script uses the saved image ID, Compose definition and env files;
refuses drift in the shared live env files; requires the existing DB; and restarts
only `server`. After readiness succeeds, it restores dedicated API configuration
and the prior API revision marker, then clears the incomplete-attempt flag. It
never rewrites shared legacy/web configuration or changes DB data. A failed
rollback leaves the incomplete flag and requires further operator diagnosis.

For the first API rollout, no earlier `current-api-revision` exists. Successful
rollback then removes that dedicated marker and leaves legacy revision markers
alone. If no prior server image exists, or it was pruned, rollback refuses to guess.
If a failed attempt is recovered manually, remove its incomplete flag only after
verifying the active image, live API configuration, and `/ready` agree.

## Local safety tests

```bash
bash -n deploy/ssh-deploy-api.sh
python3 -m unittest discover -s deploy/tests -v
```

Tests substitute recording Docker/curl executables and fake installation directories
under `/tmp`; they never use a daemon, network, live database, or `/opt`. The test-root
hook requires both explicit test mode and a `/tmp/respire-api-test.*` directory.
CI-gate fixtures use local `jq` (included on GitHub runners) and skip explicitly
if it is unavailable. The PR safety workflow runs these tests, and artifact creation
runs them again.
These tests verify command isolation, state preservation and failure handling; a
real Docker/Compose rehearsal is still required before a production rollout.
