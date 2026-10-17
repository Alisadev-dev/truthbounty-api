/**
 * @file authorization-matrix.ts
 * @description Canonical API Authorization Matrix for TruthBounty V2 backend.
 *
 * DESIGN INVARIANTS
 * ─────────────────
 * 1. Chain-derived state (Optimism/EVM contracts + canonical events) is authoritative.
 *    The API NEVER invents, mutates, or overrides protocol truth.
 * 2. Authorization fails CLOSED — any uncertainty (missing user, missing role,
 *    misconfigured guard, degraded dependency) must deny access, never silently permit.
 * 3. Two independent identity planes:
 *    - App-User plane  : wallet-authenticated users tracked in Prisma (SQLite/PostgreSQL).
 *      Roles: contributor | moderator | admin  (UserRole enum from Prisma schema)
 *    - Admin plane     : operator principals tracked in TypeORM admin_users table.
 *      Roles: super_admin > administrator > security_analyst = governance_operator > moderator > auditor
 * 4. TypeORM is the ONLY ORM for domain persistence (PostgreSQL). Prisma manages the
 *    auth-adjacent user/wallet models (SQLite in dev, PostgreSQL-compatible in prod).
 *    No second domain ORM is introduced.
 * 5. This file is the machine-readable source of truth for route-level authorization.
 *    Any change to guards or decorators must be reflected here.
 *
 * ROUTE AUTHORIZATION TABLE
 * ──────────────────────────────────────────────────────────────────────────────────
 * Notation:
 *   PUBLIC    — no authentication required
 *   AUTHN     — valid JWT required (any authenticated user)
 *   ROLE(x)   — JWT + Prisma UserRole ∈ x  (app-user plane)
 *   ADMIN(x)  — JWT + AdminGuard (DB lookup) + AdminRoleHierarchy ≥ x  (admin plane)
 *   SERVICE   — x-service-api-key header (service-to-service only)
 *
 * ┌─────────────────────────────────────────────────┬──────────────────────────────────────────┐
 * │ Route                                           │ Authorization                            │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ POST   /auth/challenge                          │ PUBLIC + rate-limited                    │
 * │ POST   /auth/login                              │ PUBLIC + rate-limited                    │
 * │ POST   /auth/refresh                            │ PUBLIC + rate-limited                    │
 * │ GET    /auth/health                             │ PUBLIC                                   │
 * │ POST   /auth/logout                             │ AUTHN                                    │
 * │ GET    /auth/profile                            │ AUTHN                                    │
 * │ DELETE /auth/sessions/:address                  │ AUTHN + AdminOnly (env-list gate)        │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /claims/latest                           │ PUBLIC                                   │
 * │ GET    /claims/user/:wallet                     │ PUBLIC                                   │
 * │ GET    /claims/:id                              │ PUBLIC                                   │
 * │ POST   /claims                                  │ AUTHN (any authenticated user)           │
 * │ POST   /claims/:claimId/evidence                │ AUTHN (any authenticated user)           │
 * │ PUT    /claims/evidence/:evidenceId             │ AUTHN (any authenticated user)           │
 * │ GET    /claims/:claimId/evidence                │ PUBLIC                                   │
 * │ GET    /claims/:claimId/evidence/latest         │ PUBLIC                                   │
 * │ GET    /claims/evidence/:evidenceId             │ PUBLIC                                   │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ POST   /disputes                                │ AUTHN (any authenticated user)           │
 * │ PATCH  /disputes/:id/start-review               │ ROLE(moderator,admin)                    │
 * │ PATCH  /disputes/:id/resolve                    │ ROLE(moderator,admin)                    │
 * │ PATCH  /disputes/:id/reject                     │ ROLE(moderator,admin)                    │
 * │ GET    /disputes/claim/:claimId                 │ PUBLIC                                   │
 * │ GET    /disputes/expired                        │ PUBLIC                                   │
 * │ GET    /disputes                                │ PUBLIC                                   │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /rewards                                 │ PUBLIC                                   │
 * │ GET    /rewards/:id                             │ PUBLIC                                   │
 * │ POST   /rewards                                 │ ROLE(admin)                              │
 * │ PATCH  /rewards/:id                             │ ROLE(admin)                              │
 * │ DELETE /rewards/:id                             │ ROLE(admin)                              │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /staking/projects/:claimId/entitlement   │ PUBLIC                                   │
 * │ GET    /staking/projects/:claimId/stake         │ PUBLIC                                   │
 * │ POST   /staking/projects/:claimId/locks         │ AUTHN (any authenticated user)           │
 * │ POST   /staking/projects/:claimId/withdrawals   │ AUTHN (any authenticated user)           │
 * │ POST   /staking/projects/:claimId/reconcile     │ ROLE(admin)                              │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /governance/proposals                    │ PUBLIC                                   │
 * │ GET    /governance/proposals/active             │ PUBLIC                                   │
 * │ GET    /governance/proposals/:id                │ PUBLIC                                   │
 * │ GET    /governance/proposals/:id/votes          │ PUBLIC                                   │
 * │ GET    /governance/stats                        │ PUBLIC                                   │
 * │ POST   /governance/proposals                    │ AUTHN (any authenticated user)           │
 * │ POST   /governance/proposals/:id/votes          │ AUTHN (any authenticated user)           │
 * │ PATCH  /governance/proposals/:id/activate       │ ROLE(moderator,admin)                    │
 * │ PATCH  /governance/proposals/:id/execute        │ ROLE(admin)                              │
 * │ PATCH  /governance/proposals/:id/cancel         │ ROLE(moderator,admin)                    │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ POST   /identity/users                          │ AUTHN (any authenticated user)           │
 * │ GET    /identity/users/:id                      │ PUBLIC                                   │
 * │ POST   /identity/users/:id/wallets              │ AUTHN (any authenticated user)           │
 * │ DELETE /identity/users/:id/wallets/:chain/:addr │ AUTHN (any authenticated user)           │
 * │ POST   /identity/users/:id/verify-worldcoin     │ AUTHN (any authenticated user)           │
 * │ GET    /identity/users/:id/sybil-score          │ PUBLIC                                   │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /audit/*                                 │ ADMIN(auditor)                           │
 * │ POST   /audit/export                            │ ADMIN(auditor)                           │
 * │ POST   /audit/legal-hold/*                      │ ADMIN(administrator)                     │
 * │ PATCH  /audit/legal-hold/:id/remove             │ ADMIN(administrator)                     │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /analytics/*                             │ ROLE(moderator,admin) or ADMIN(auditor)  │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /metrics                                 │ Bearer METRICS_TOKEN                     │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /admin/jobs/metrics                      │ ADMIN(auditor)                           │
 * │ GET    /admin/jobs/metrics/:queue               │ ADMIN(auditor)                           │
 * │ POST   /admin/jobs/enqueue                      │ ADMIN(administrator)                     │
 * │ POST   /admin/jobs/retry/:queue                 │ ADMIN(administrator)                     │
 * │ POST   /admin/jobs/cancel/:queue                │ ADMIN(administrator)                     │
 * │ POST   /admin/jobs/pause/:queue                 │ ADMIN(administrator)                     │
 * │ POST   /admin/jobs/resume/:queue                │ ADMIN(administrator)                     │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ POST   /admin/dead-letter/replay                │ ADMIN(administrator) + capability        │
 * │ POST   /admin/dead-letter/replay/dry-run        │ ADMIN(administrator) + capability        │
 * │ POST   /admin/dead-letter/replay/:batchId/pause │ ADMIN(administrator) + capability        │
 * │ POST   /admin/dead-letter/replay/:batchId/resume│ ADMIN(administrator) + capability        │
 * │ GET    /admin/dead-letter/replay/:batchId       │ ADMIN(auditor)                           │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ GET    /v2/events/*                             │ PUBLIC (read-only chain projections)     │
 * │ GET    /v2/evidence/*                           │ PUBLIC (read-only chain projections)     │
 * │ GET    /v2/verification/*                       │ PUBLIC (read-only chain projections)     │
 * │ GET    /v2/disputes/*                           │ PUBLIC (read-only chain projections)     │
 * ├─────────────────────────────────────────────────┼──────────────────────────────────────────┤
 * │ POST   /admin/auth/login                        │ PUBLIC (returns admin identity only)     │
 * │ All other /admin/* routes                       │ ADMIN(varies, see AdminController)       │
 * └─────────────────────────────────────────────────┴──────────────────────────────────────────┘
 *
 * FAILURE-CLOSED INVARIANTS
 * ─────────────────────────
 * • Missing JWT on a guarded route  → 401 Unauthorized
 * • Valid JWT but insufficient role → 403 Forbidden
 * • Admin DB lookup fails or admin is inactive → 403 Forbidden
 * • Service key missing or mismatched → 401 Unauthorized
 * • Any guard throws unexpectedly → NestJS exception filter returns 5xx; never silently permits
 *
 * DEAD-LETTER REPLAY INVARIANTS (PREWAVE-BE-049)
 * ──────────────────────────────────────────────
 * • Replay is DENIED BY DEFAULT. Absence of an explicit capability grant, reason,
 *   bounds, dry-run confirmation, original payload hash, or audit record → deny.
 * • A replay MUST be bound to the original message's chain ID, release ID,
 *   deployment block, and artifact checksum. Any mismatch or staleness → deny.
 * • One message cannot produce duplicate effects: the original payload hash is
 *   recorded immutably and a second replay of the same hash is rejected as a
 *   duplicate (idempotency key = hash(originalPayload) + releaseId + chainId).
 * • Original and replay references are linked immutably in the audit record;
 *   neither side may be mutated after the fact.
 * • Operators may pause/resume bounded batches; each batch enforces a hard
 *   upper bound on message count and fails closed on partial failure.
 * • Poison messages are quarantined, never retried indefinitely, and never
 *   silently dropped.
 *
 * NON-GOALS (protocol boundary)
 * ──────────────────────────────
 * • This matrix does NOT grant the API authority to settle rewards, resolve disputes,
 *   mutate governance outcomes, or override smart-contract events.
 * • All such state is reproduced deterministically from canonical Optimism/EVM events.
 * • No Stellar, Soroban, Freighter, or alternate-chain paths are introduced.
 */

/**
 * App-user roles matching the Prisma `UserRole` enum (contributor | moderator | admin).
 * Also kept in sync with TypeORM `UserRole` (USER ≡ contributor, MODERATOR ≡ moderator, ADMIN/SUPER_ADMIN ≡ admin).
 */
export type AppUserRole = 'contributor' | 'moderator' | 'admin';

/** All valid AppUserRole values. */
export const APP_USER_ROLES: readonly AppUserRole[] = [
  'contributor',
  'moderator',
  'admin',
] as const;

/**
 * Helper: returns true if the candidate string is a known AppUserRole.
 */
export function isAppUserRole(value: unknown): value is AppUserRole {
  return (
    typeof value === 'string' &&
    (APP_USER_ROLES as readonly string[]).includes(value)
  );
}

/**
 * Dead-letter replay capabilities (PREWAVE-BE-049).
 *
 * These are the ONLY capabilities that authorize replay operations. They are
 * intentionally distinct from route-level admin roles: holding an admin role
 * is necessary but NOT sufficient to replay. A principal must additionally be
 * granted the specific capability below.
 */
export type DeadLetterReplayCapability =
  | 'dead_letter:replay:dry_run'
  | 'dead_letter:replay:execute'
  | 'dead_letter:replay:pause'
  | 'dead_letter:replay:resume'
  | 'dead_letter:replay:read';

/** All valid DeadLetterReplayCapability values. */
export const DEAD_LETTER_REPLAY_CAPABILITIES: readonly DeadLetterReplayCapability[] =
  [
    'dead_letter:replay:dry_run',
    'dead_letter:replay:execute',
    'dead_letter:replay:pause',
    'dead_letter:replay:resume',
    'dead_letter:replay:read',
  ] as const;

/**
 * Helper: returns true if the candidate string is a known replay capability.
 */
export function isDeadLetterReplayCapability(
  value: unknown,
): value is DeadLetterReplayCapability {
  return (
    typeof value === 'string' &&
    (DEAD_LETTER_REPLAY_CAPABILITIES as readonly string[]).includes(value)
  );
}

/**
 * Immutable binding required to authorize a dead-letter replay.
 *
 * Every field is mandatory. Missing, stale, ambiguous, or mismatched values
 * MUST cause the replay to fail closed.
 */
export interface DeadLetterReplayBinding {
  /** Chain ID of the canonical source chain (e.g. Optimism mainnet). */
  readonly chainId: number;
  /** Release identifier the original message was produced under. */
  readonly releaseId: string;
  /** Deployment block of the contract set that emitted the original message. */
  readonly deploymentBlock: number;
  /** Artifact checksum of the deployed contract set. */
  readonly artifactChecksum: string;
}

/**
 * Request shape for a dead-letter replay operation.
 *
 * `originalPayloadHash` is the idempotency anchor: the same hash cannot be
 * replayed twice for the same (chainId, releaseId) tuple.
 */
export interface DeadLetterReplayRequest {
  /** Capability asserted by the caller; must be granted to the principal. */
  readonly capability: DeadLetterReplayCapability;
  /** Human-readable justification; required, non-empty. */
  readonly reason: string;
  /** Hard upper bound on messages processed in this batch. */
  readonly batchLimit: number;
  /** When true, no effects are produced; only a plan is returned. */
  readonly dryRun: boolean;
  /** SHA-256 (hex) of the original message payload. */
  readonly originalPayloadHash: string;
  /** Immutable binding to the canonical chain/release state. */
  readonly binding: DeadLetterReplayBinding;
  /** Audit correlation ID linking original and replay records. */
  readonly auditCorrelationId: string;
}

/** Maximum number of messages a single replay batch may process. */
export const DEAD_LETTER_REPLAY_MAX_BATCH = 100 as const;

/**
 * Fail-closed validation of a replay request.
 *
 * Returns `{ ok: true }` only when every precondition is satisfied. Any
 * uncertainty yields `{ ok: false, code }` so callers can deny by default.
 */
export function validateDeadLetterReplayRequest(
  request: Partial<DeadLetterReplayRequest> | null | undefined,
):
  | { readonly ok: true }
  | { readonly ok: false; readonly code: DeadLetterReplayDenyCode } {
  if (!request) {
    return { ok: false, code: 'MISSING_REQUEST' };
  }
  if (!isDeadLetterReplayCapability(request.capability)) {
    return { ok: false, code: 'MISSING_CAPABILITY' };
  }
  if (
    typeof request.reason !== 'string' ||
    request.reason.trim().length === 0
  ) {
    return { ok: false, code: 'MISSING_REASON' };
  }
  if (
    typeof request.batchLimit !== 'number' ||
    !Number.isInteger(request.batchLimit) ||
    request.batchLimit <= 0
  ) {
    return { ok: false, code: 'INVALID_BOUNDS' };
  }
  if (request.batchLimit > DEAD_LETTER_REPLAY_MAX_BATCH) {
    return { ok: false, code: 'BATCH_LIMIT_EXCEEDED' };
  }
  if (typeof request.dryRun !== 'boolean') {
    return { ok: false, code: 'MISSING_DRY_RUN' };
  }
  if (
    typeof request.originalPayloadHash !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(request.originalPayloadHash)
  ) {
    return { ok: false, code: 'INVALID_PAYLOAD_HASH' };
  }
  if (
    typeof request.auditCorrelationId !== 'string' ||
    request.auditCorrelationId.trim().length === 0
  ) {
    return { ok: false, code: 'MISSING_AUDIT_RECORD' };
  }
  const binding = request.binding;
  if (!binding) {
    return { ok: false, code: 'MISSING_BINDING' };
  }
  if (
    typeof binding.chainId !== 'number' ||
    !Number.isInteger(binding.chainId) ||
    binding.chainId <= 0
  ) {
    return { ok: false, code: 'INVALID_CHAIN_ID' };
  }
  if (
    typeof binding.releaseId !== 'string' ||
    binding.releaseId.trim().length === 0
  ) {
    return { ok: false, code: 'MISSING_RELEASE_ID' };
  }
  if (
    typeof binding.deploymentBlock !== 'number' ||
    !Number.isInteger(binding.deploymentBlock) ||
    binding.deploymentBlock < 0
  ) {
    return { ok: false, code: 'INVALID_DEPLOYMENT_BLOCK' };
  }
  if (
    typeof binding.artifactChecksum !== 'string' ||
    binding.artifactChecksum.trim().length === 0
  ) {
    return { ok: false, code: 'MISSING_ARTIFACT_CHECKSUM' };
  }
  return { ok: true };
}

/**
 * Denial codes emitted by replay authorization. These are stable, machine-
 * readable reasons so audit records can distinguish failure modes.
 */
export type DeadLetterReplayDenyCode =
  | 'MISSING_REQUEST'
  | 'MISSING_CAPABILITY'
  | 'MISSING_REASON'
  | 'INVALID_BOUNDS'
  | 'BATCH_LIMIT_EXCEEDED'
  | 'MISSING_DRY_RUN'
  | 'INVALID_PAYLOAD_HASH'
  | 'MISSING_AUDIT_RECORD'
  | 'MISSING_BINDING'
  | 'INVALID_CHAIN_ID'
  | 'MISSING_RELEASE_ID'
  | 'INVALID_DEPLOYMENT_BLOCK'
  | 'MISSING_ARTIFACT_CHECKSUM'
  | 'STALE_RELEASE'
  | 'DUPLICATE_REPLAY'
  | 'POISON_MESSAGE'
  | 'PARTIAL_FAILURE';

/**
 * Idempotency key for a replay. Two replays with the same key MUST NOT both
 * produce effects; the second is rejected as `DUPLICATE_REPLAY`.
 */
export function deadLetterReplayIdempotencyKey(
  binding: DeadLetterReplayBinding,
  originalPayloadHash: string,
): string {
  return [
    binding.chainId.toString(),
    binding.releaseId,
    binding.deploymentBlock.toString(),
    binding.artifactChecksum,
    originalPayloadHash.toLowerCase(),
  ].join(':');
}

/**
 * Returns true when the supplied binding matches the currently active
 * chain/release state. Any mismatch is treated as stale and MUST deny replay.
 */
export function isDeadLetterReplayBindingCurrent(
  binding: DeadLetterReplayBinding,
  active: DeadLetterReplayBinding,
): boolean {
  return (
    binding.chainId === active.chainId &&
    binding.releaseId === active.releaseId &&
    binding.deploymentBlock === active.deploymentBlock &&
    binding.artifactChecksum === active.artifactChecksum
  );
}
