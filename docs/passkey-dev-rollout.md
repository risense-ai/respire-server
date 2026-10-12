# Passkey memory unlock: DEV rollout and recovery

This feature adds an optional browser decryption factor for an already signed-in
account. It does not replace login or the saved superpassword/recovery code. The
Server verifies WebAuthn; only the trusted Dashboard receives PRF output and
unwraps the existing 32-byte user root key (URK).

## Cryptographic and compatibility boundary

- Existing vault versions 1/2 (superpassword), 3 (superpassword plus Secret Key),
  and 4 (A3 recovery code) remain readable. Enrollment uses the existing browser
  unwrap routine and wraps the **same URK** under an independent PRF-derived key.
  Existing recovery wrappers and encrypted memories are not rewritten.
- Each credential has a server-generated, public 32-byte PRF input. The browser
  uses HKDF-SHA256 with domain `respire:passkey:urk-wrap:v1`, then AES-256-GCM with
  a random 12-byte nonce. Authenticated metadata binds the format domain,
  account UUID, exact RP ID, credential ID, URK generation and PRF input.
- WebAuthn registration and two subsequent assertions are separate, expiring,
  server-side ceremonies. Required user verification, signatures, challenge,
  origin and RP ID are checked with `webauthn-rs`. The second assertion must
  reproduce the decryption result locally before the wrapper is activated.
- PRF output, plaintext URK, KEK and superpassword are never API fields. Browser
  serialization deliberately excludes PRF output instead of forwarding
  `PublicKeyCredential.toJSON()` wholesale.
- PRF support is checked during the actual ceremonies. Basic passkey support is
  insufficient. Unsupported credentials, cancelled ceremonies or failed unwraps
  retain the superpassword fallback. Cancellation may leave an unused credential
  in the user's provider; removing a Server wrapper does not delete that provider
  credential.
- Passkeys protect stored key material, not an already compromised Dashboard or
  XSS. Removing a wrapper does not revoke URKs or ciphertext snapshots already
  copied. This is not full compromise recovery or bulk data-key rotation.
- No particular hardware, password manager, synchronization provider or browser
  combination is certified by unit tests. A virtual authenticator is synthetic
  protocol coverage, not evidence for Apple, 1Password, Bitwarden or another
  provider.

## Account and reset semantics

The additive PostgreSQL migration reaches schema 8. Existing vaults receive a
stable account UUID and `key_generation = 1`. Separate credential and ceremony
tables contain public verification material and opaque encrypted wrappers.

Ordinary login-password recovery does not touch the encrypted vault. The upgraded
Dashboard's superpassword rotation explicitly sends
`operation: "rewrap_same_urk"` and the current `expected_key_generation`; this
preserves Passkey wrappers. Server-side plaintext equality cannot be verified
without violating the key boundary, so this operation is an explicit client
contract and uses optimistic generation checks.

Destructive Dashboard reset uses `POST /api/self/vault/reset`, supplies the
expected generation, replaces the recovery wrapper and atomically invalidates
all Passkey wrappers and pending ceremonies while increasing the generation.
The operation preserves the existing destructive-reset warning: old memories
cannot be recovered with the newly generated URK.

Older clients cannot distinguish same-URK rewrap from destructive replacement.
Therefore a changed legacy vault POST conservatively increases generation and
invalidates Passkeys. An identical legacy write is a no-op for generation. This
may require re-enrollment after changing a recovery code in an older client; it
prevents stale wrappers being used after an unlabelled key replacement. CLI/Core
are not changed by this feature.

## DEV enablement

Do not merge Site's feature into a production-publishing branch to run DEV tests.
Use the existing Site `develop` deployment with its environment-specific API
base and Dashboard origin. Server and Site are independent deployables; deploy
and verify the Server API before the matching Dashboard.

Set these two values **only in the existing DEV operator configuration**:

```dotenv
RSRS_PASSKEY_RP_ID=dash.dev.rsrs.rs
RSRS_PASSKEY_ORIGIN=https://dash.dev.rsrs.rs
```

Both absent disables enrollment/unlock and leaves recovery-code flows available.
Partial or invalid configuration fails startup. Use the exact Dashboard hostname
as RP ID, not the shared `rsrs.rs` parent. DEV credentials will not work on the
production Dashboard. Do not change the existing CORS, database identity,
Dashboard URL, host networking or permissions as a side effect of this feature.
Confirm the DEV Dashboard is already in the trusted exact-origin CORS allowlist.

Follow [the existing API deployment procedure](api-deployment.md). It requires
successful CI and Server image checks for the exact source revision, a reviewed
API artifact, the authorized operator's existing DEV host access, the original
installation directory/Compose project/database, a verified backup and the
normal deployment lock. Artifact publication is not deployment. Do not create
SSH keys or borrow a user's computer credentials to bypass a missing deployment
route. Do not run `docker compose down -v` on an existing installation.

## Verification gates

Before any DEV handover, record the Server and Site commit SHAs and the results
of their exact-revision required checks. Verify `/health.source_revision`,
`/ready`, the selected Dashboard provenance and API base. Use only dedicated
synthetic accounts for automated mutating acceptance.

The acceptance checklist is:

1. Newly registered account saves and acknowledges its recovery code before
   optional enrollment; no automatic real-account credential enrollment.
2. Existing v4 and representative legacy vaults enroll after recovery unlock;
   pre-existing synthetic memory ciphertext remains unchanged and decrypts.
3. Lock/reload then Passkey unlock with user verification decrypts the same data.
   Repeat with two credentials and remove one; the other and recovery path work.
4. Cancel at registration and both assertion prompts, then retry. Unsupported
   PRF, wrong PRF, tampered nonce/ciphertext/metadata and stale account state fail
   closed without adding an active unusable wrapper.
5. Wrong account, session, RP/origin, challenge, credential, expired ceremony,
   missing user verification and replayed assertions are rejected.
6. Same-URK recovery-code rotation preserves Passkeys. Explicit destructive reset
   and changed legacy writes invalidate all old wrappers and in-flight actions.
7. Logout/account switch/navigation during enrollment or unlock leaves no
   plaintext or active stale decrypt operation; no PRF output or URK appears in
   network requests or browser storage.
8. Existing password login, recovery-code unlock, memory CRUD, sync, registration,
   token rotation and other console regressions remain green.

Record browser/provider versions separately for real-device acceptance. Do not
label an unrun browser stage as passed or treat mocked credentials as hardware
compatibility evidence.

## Disablement and rollback

First disable the feature by clearing both Passkey variables and restart the
**current schema-8-compatible** Server image; recovery-code operation remains.
Roll back the Dashboard independently to its prior reviewed DEV deployment.
Retain backups, the previous image and all operator configuration snapshots.

An old schema-7 Server explicitly refuses a schema-8 database. The generic image
rollback switch is **not** a safe database downgrade. Never blindly lower
`schema_meta`, drop Passkey tables, or restore a backup over later user writes.
If an old binary is necessary, an operator must stop writers and execute a
separately reviewed and rehearsed schema/data rollback or point it at a verified
restored copy, accounting for every write since the backup. Prefer a forward fix
or feature disablement when preserving those writes matters. No automatic
production deployment or rollback is part of the feature PR.

## References

- [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension)
- [webauthn-rs verification and server-state requirements](https://docs.rs/webauthn-rs/0.5.5/webauthn_rs/struct.Webauthn.html)
