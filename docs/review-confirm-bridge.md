# Passkey review-confirm bridge

This additive schema-11 API uses the existing authenticated account, enrolled
Passkey, and exact RP/origin configuration. It authorizes a specific review
intent; ordinary unlock receipts cannot authorize reviews. The server retains
only IDs, digests and approval receipts, never claim/evidence text or the URK.

All paths below are under `/api/self/passkeys` and use the current session token.
Writable sessions are required for POST. A disabled Passkey configuration leaves
this bridge unavailable. No new issuer, user, credential or permission is created.

1. The client computes canonical digests with Core and locally shows the complete
   claim, scope, evidence and target revision. After an explicit user choice,
   POST `/review/start` with `{credential_id,binding}`. `binding` contains owner
   (the authenticated username), local_library_id, id (complete canonical UUID),
   record_revision, expected_memory_revision, claim_digest and intent_digest.
   The three digests use `sha256:` plus 64 lowercase hex characters; the memory
   revision is the existing 32-character lowercase hex token.
2. Execute the returned `public_key` request using the browser WebAuthn API and
   POST `/review/finish` with `{ceremony_id,credential}`. Use the existing safe
   credential serializer. Do not submit PRF secrets, wrapper or key material.
   The account/session/configuration-bound ceremony expires after five minutes;
   even failed cryptographic verification consumes that ceremony.
3. The fixed configured CLI adapter POSTs `/review/consume` with
   `{event_id,binding}`. The server compares every binding field and atomically
   consumes the unexpired approval once. The adapter checks the returned account,
   purpose and exact binding before constructing its internal trusted approval.
   Local CAS/commit failure after consumption requires a new user approval.
   Server consumption and a local transaction are not a distributed transaction.
4. GET `/review/events/{event_id}` revalidates the historical claim without
   consuming again. Another device checks owner, id, record_revision and
   claim_digest against its record, but does not require its own local library ID
   to match the original submission. Submission expiry does not expire that
   historical claim. Current account generation, credential, RP/origin and
   revocation still determine validity; network errors fail closed.
5. POST `/review/revoke` with `{event_id,reason}` revokes an owned event
   idempotently. Credential removal and destructive vault generation changes also
   make historical event validation fail. A same-URK rewrap preserves it.

Receipts contain event_id, purpose=`review-confirm`, account_id, binding,
confirmed_by (`kind=human`, authenticated username and event_id), confirmed_at,
expires_at (Unix seconds), consumed_at, revoked_at, valid and
submission_available. Other timestamps use RFC3339. `valid` describes persistent
authority; `submission_available` also requires no prior consumption and an
unexpired five-minute submission window. A GET result is not a consumed approval.

The server validates the WebAuthn assertion, not whether the displayed sources
semantically prove the claim. The trusted host must show the exact candidate
before asking for user presence. An API caller cannot submit human/trusted flags,
choose a different issuer or turn an unlock into a review event.

No deployment or real authenticator ceremony is implied by these source changes.
The Dashboard action, fixed CLI adapter and a real user-presence run must be
integrated and verified before enabling verified production writes. Existing
Passkey software-authenticator tests exercise the API protocol only.
