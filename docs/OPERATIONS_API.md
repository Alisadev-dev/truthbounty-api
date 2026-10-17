# Protected Operations, Safe-Retry, Dead-Letter Replay and Audit API (UX-BE-004, #595; PREWAVE-BE-049)

Versioned, protected interfaces for the privileged operations boards. The API is
**read-only with respect to protocol state**: it publishes bounded operational
queue reads, safe-retry eligibility/submission, and audit-record lookup. No
endpoint edits claim, verification, dispute, settlement, reward, treasury,
governance, or pause state — contracts and canonical events remain authoritative.

OpenAPI version: **1.0.0** (surface added at API version `1.0`).

## Endpoints

All routes are admin-plane protected (`AdminGuard` + `RolesGuard`).

| Method | Path | Capability | Roles |
| --- | --- | --- | --- |
| `GET` | `/v1/operations/queue` | `OPERATIONS_QUEUE_READ` | super_admin, administrator, security_analyst, auditor |
| `GET` | `/v1/operations/queue/:id` | `OPERATIONS_QUEUE_READ` | super_admin, administrator, security_analyst, auditor |
| `GET` | `/v1/operations/queue/:id/retry-eligibility` | `OPERATIONS_RETRY_READ` | super_admin, administrator, security_analyst, auditor |
| `POST` | `/v1/operations/queue/:id/retry` | `OPERATIONS_RETRY_SUBMIT` | super_admin, administrator |
| `GET` | `/v1/operations/audit/:auditId` | `OPERATIONS_AUDIT_READ` | super_admin, administrator, security_analyst, auditor |
| `POST` | `/v1/operations/dead-letters/:id/replay` | `OPERATIONS_DEAD_LETTER_REPLAY` | super_admin, administrator |
| `POST` | `/v1/operations/dead-letters/replay-batch` | `OPERATIONS_DEAD_LETTER_REPLAY` | super_admin, administrator |

### Queue item shape

Every item carries immutable identifiers and the metadata the boards need to act
without guessing:

`id` (immutable work id), `releaseId`, `capability`, `authoritySource`,
`authorityExpiresAt`, `status`, `impact`, `duplicationRisk`, `freshness`,
`attempts`, `maxAttempts`, `retryable`, `version`, `updatedAt`, `summary`.

### Retry eligibility

`GET /v1/operations/queue/:id/retry-eligibility` returns:

```json
{ "id": "queue-001", "eligible": true, "reason": null, "attemptsRemaining": 4,
  "preconditionToken": "a1b2c3d4e5f60718293a4b5c6d7e8f90" }
```

The frontend determines retryability directly from `eligible`/`reason` — it
never has to infer it from other fields.

### Retry submission

`POST /v1/operations/queue/:id/retry` requires:

| Input | Where | Why |
| --- | --- | --- |
| `Idempotency-Key` | header | Duplicate keys replay the original outcome; they never re-execute. |
| `X-Precondition-Token` | header (or `preconditionToken` body) | Must match the item's current version, or the request is rejected as stale. |
| `X-Authority-Capability` | header | Must equal the item's required capability. |
| `X-Authority-Expires-At` | header (ISO) | Revalidated on every request; missing/expired/ambiguous fails closed. |
| `reason?`, `force?` | body | Audited replay context; `force` only bypasses plain non-retryable, never a confirmed duplication risk. |

Authentication is not authorization: capability and expiry are revalidated on
every request.

### Dead-letter replay

Replay is **denied by default**. A replay request must supply every one of the
following, or it fails closed before any work is enqueued:

| Input | Where | Why |
| --- | --- | --- |
| `Idempotency-Key` | header | Duplicate keys replay the stored outcome; one message never produces duplicate effects. |
| `X-Precondition-Token` | header (or `preconditionToken` body) | Must match the dead-letter record's current version, or the request is rejected as stale. |
| `X-Authority-Capability` | header | Must equal `OPERATIONS_DEAD_LETTER_REPLAY`. |
| `X-Authority-Expires-At` | header (ISO) | Revalidated on every request; missing/expired/ambiguous fails closed. |
| `X-Original-Payload-Hash` | header | Must equal the stored hash of the original payload; a mismatch is rejected. |
| `reason` | body (required) | Audited replay context; recorded immutably against the replay. |
| `dryRun` | body (default `true`) | When `true`, validates and reports the outcome without enqueuing. |
| `limit` | body (batch only) | Bounded batch size; requests above the server maximum are rejected. |

Replay is refused when the dead-letter record's `releaseId`, `chainId`,
`deploymentBlock`, `artifactChecksum`, or schema version is incompatible with
the current release. Stale, ambiguous, or missing release/schema state fails
closed.

Each accepted replay links the original dead-letter record to the replay
immutably: `originalId`, `originalPayloadHash`, `replayId`, `auditId`,
`releaseId`, `chainId`, `deploymentBlock`, and `artifactChecksum` are recorded
and never mutated. A message that has already been replayed cannot be replayed
again to produce a second effect.

### Bounded batch replay

`POST /v1/operations/dead-letters/replay-batch` accepts a `limit` and a
`dryRun` flag. Operators can stop a running batch by submitting a request with
`stop: true`; a stopped batch reports the count replayed so far and can be
resumed with `resume: true` from the recorded cursor. Partial failures are
reported per item with their own `auditId`; the batch never silently drops a
poison message — it is quarantined and reported.

## Canonical results

Every accepted or rejected protected request carries a **stable audit
identifier** (`auditId`). Rejections use the canonical envelope
`{ statusCode, errorCode, message, auditId, timestamp }` with one of:

| `errorCode` | HTTP | Meaning |
| --- | --- | --- |
| `DENIED` | 403 | Caller authority lacks the required capability. |
| `STALE_AUTHORITY` | 403 | Authority missing, expired, or ambiguous. |
| `STALE_PRECONDITION` | 409 | Precondition token missing/stale; re-read and retry. |
| `CONFLICT` | 409 | Idempotency key reused for a different item. |
| `ALREADY_COMPLETED` | 409 | The operation already completed. |
| `UNSAFE_TO_RETRY` | 409 | Quarantined item or confirmed duplication risk. |
| `NOT_RETRYABLE` | 409 | Item is not eligible for retry (use `force` to override). |
| `DEPENDENCY_UNAVAILABLE` | 503 | Required dependency unavailable. |
| `RATE_LIMITED` | 429 | Throttled by the wallet/route throttler. |
| `REPLAY_DENIED` | 403 | Replay capability missing or replay disabled by default. |
| `REPLAY_INCOMPATIBLE` | 409 | Release/schema/chain/artifact mismatch; replay refused. |
| `REPLAY_DUPLICATE` | 409 | Message already replayed; no second effect is produced. |

## Guarantees

1. **No duplicate protocol mutation.** A retry re-enqueues existing work through
   the queue source, which carries its own deterministic idempotency key; a
   duplicate `Idempotency-Key` replays the stored outcome instead of re-running.
2. **Fail closed.** Missing, stale, revoked, or ambiguous authority never
   defaults to allowed.
3. **Sanitized audit.** Records exclude secrets, protected evidence,
   credentials, raw authorization headers, and internal topology.
4. **Read-only protocol outcomes.** No operational endpoint edits protocol
   state; the only write-shaped handler is the idempotent retry submission.
5. **Replay is denied by default.** Dead-letter replay requires the protected
   capability, reason, bounds, dry run, original payload hash, and an audit
   record; missing or stale state fails closed. Original and replay references
   are linked immutably, and one message cannot produce duplicate effects.

## Fixtures

Deterministic, sanitized frontend fixtures for every state live in
`test/fixtures/contracts/operations-contract.fixtures.ts`, validated by
`operations-contract.spec.ts` (vocabulary, exact field sets, sanitization), and
dead-letter replay fixtures validated by `dead-letter-replay.spec.ts`
(unauthorized, stale release, duplicate replay, batch limit, poison message,
partial failure, and audit tests).
