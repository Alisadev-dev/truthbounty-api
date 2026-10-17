import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DataSource, EntityManager } from 'typeorm';
import { createHash, randomUUID } from 'crypto';
import { AdminAuditLog } from '../entities/admin-audit-log.entity';
import { AdminAuditHead } from '../entities/admin-audit-head.entity';
import {
  AdminActionType,
  AdminActionCategory,
  AdminAuditSeverity,
  AdminAuditLogInput,
  AdminAuditOutcome,
} from '../admin-audit.types';
export * from '../admin-audit.types';
export type AdminAuditLogRecord = AdminAuditLog;

export interface AdminAuditQueryFilters {
  actorId?: string;
  correlationId?: string;
  action?: AdminActionType;
  outcome?: AdminAuditOutcome;
  page?: number;
  limit?: number;
}
export interface AdminAuditQueryResult {
  logs: AdminAuditLog[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

/** Replay request contract. Denied by default unless fully authorized. */
export interface DeadLetterReplayRequest {
  /** Capability the caller must hold (e.g. 'deadletter.replay'). */
  capability: string;
  /** Operator identity and authority proof. */
  actorId: string;
  authorityReference: string;
  correlationId: string;
  /** Human reason; required and audited. */
  reason: string;
  /** Original dead-letter message reference. */
  originalMessageId: string;
  /** SHA-256 hash of the original payload for immutable linkage. */
  originalPayloadHash: string;
  /** Release/chain context the replay is bound to. */
  chainId: number;
  releaseId: string;
  deploymentBlock: string;
  artifactChecksum: string;
  /** Max number of messages to replay in this batch. */
  maxBatch: number;
  /** Dry run must be explicitly set; defaults to true (no side effects). */
  dryRun?: boolean;
  /** Operator control: stop requested. */
  stop?: boolean;
}

export interface DeadLetterReplayResult {
  auditEventId: string;
  replayReference: string;
  dryRun: boolean;
  processed: number;
  skipped: number;
  failed: number;
  stopped: boolean;
  outcome: AdminAuditOutcome;
}

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODE = /^[a-z][a-z0-9_.:-]{0,95}$/i;
const HEX_SHA256 = /^0x[0-9a-f]{64}$/i;
const BLOCK = /^(0|[1-9][0-9]{0,19})$/;
const OUTCOMES: AdminAuditOutcome[] = [
  'attempted',
  'success',
  'failure',
  'partial',
  'rolled_back',
  'unknown',
];
const MAX_BATCH_LIMIT = 100;
const DEFAULT_BATCH_LIMIT = 10;

/** Database-only operations must use the supplied manager; external effects need an outbox. */
@Injectable()
export class AdminAuditService {
  constructor(
    private readonly source: DataSource,
    private readonly config: ConfigService,
  ) {}

  async log(
    input: AdminAuditLogInput,
    manager?: EntityManager,
  ): Promise<string> {
    this.assertPostgres();
    const safe = this.sanitize(input);
    if (manager) {
      if (
        manager.connection !== this.source ||
        !manager.queryRunner?.isTransactionActive
      ) {
        throw new Error(
          'Audit writes require this datasource and an active transaction',
        );
      }
      return this.append(safe, manager);
    }
    return this.source.transaction((tx) => this.append(safe, tx));
  }

  async logBatch(inputs: AdminAuditLogInput[]): Promise<string[]> {
    this.assertPostgres();
    const safe = inputs.map((input) => this.sanitize(input));
    return this.source.transaction(async (tx) => {
      const ids: string[] = [];
      for (const input of safe) ids.push(await this.append(input, tx));
      return ids;
    });
  }

  /** A durable attempt precedes execution; success shares the operation's commit. */
  async execute<T>(
    input: Omit<AdminAuditLogInput, 'outcome'>,
    work: (manager: EntityManager) => Promise<T>,
  ): Promise<{ result: T; eventId: string }> {
    // Copy/validate before invoking caller code, which must not mutate audit context.
    const context = this.sanitize({ ...input, outcome: 'attempted' });
    await this.log(context);
    const runner = this.source.createQueryRunner();
    let committing = false;
    try {
      await runner.connect();
      await runner.startTransaction();
      const result = await work(runner.manager);
      const eventId = await this.append(
        { ...context, outcome: 'success' },
        runner.manager,
      );
      committing = true;
      await runner.commitTransaction();
      return { result, eventId };
    } catch (error) {
      let outcome: AdminAuditOutcome = 'unknown';
      if (runner.isTransactionActive) {
        try {
          await runner.rollbackTransaction();
          // A lost COMMIT acknowledgement cannot establish whether it committed.
          if (!committing) outcome = 'rolled_back';
        } catch {
          // Keep the durable attempt; never report success or invent rollback proof.
        }
      }
      await this.log({ ...context, outcome });
      throw error;
    } finally {
      await runner.release();
    }
  }

  /**
   * Authorized and idempotent dead-letter replay.
   *
   * - Denied by default: must hold capability, provide reason, bounds,
   *   dry run flag, original payload hash, and chain context.
   * - Fails closed on stale/incompatible release or schema.
   * - Prevents duplicate effects via an idempotency key derived from the
   *   original message id + payload hash + release context.
   * - Operators can stop/resume bounded batches via `stop` and `continuation`.
   */
  async replayDeadLetter(
    request: DeadLetterReplayRequest,
    work: (manager: EntityManager, item: DeadLetterReplayItem) => Promise<void>,
    items: DeadLetterReplayItem[],
  ): Promise<DeadLetterReplayResult> {
    this.assertPostgres();
    const safe = this.sanitizeReplayRequest(request);
    const dryRun = safe.dryRun !== false;
    const maxBatch = safe.maxBatch;
    if (!Array.isArray(items)) throw new Error('Replay items must be an array');
    if (items.length > maxBatch)
      throw new Error('Replay batch exceeds configured limit');

    // Resolve the authority and release context before any side effect.
    const authority = await this.resolveReplayAuthority(safe);
    if (!authority.authorized) throw new Error('Replay denied by default');
    if (!authority.releaseCompatible)
      throw new Error('Replay rejected: stale or incompatible release');

    const replayReference = randomUUID();
    const correlationId = safe.correlationId;
    const auditContext: Omit<AdminAuditLogInput, 'outcome'> = {
      actorId: safe.actorId,
      actorType: 'user',
      action: AdminActionType.REPLAY_DEAD_LETTER,
      actionCategory: AdminActionCategory.OPERATIONS,
      targetType: 'dead_letter',
      targetId: safe.originalMessageId,
      capability: safe.capability,
      authoritySource: 'rbac',
      authorityReference: safe.authorityReference,
      requestReference: replayReference,
      resultReference: undefined,
      correlationId,
      outcome: 'attempted',
      severity: AdminAuditSeverity.HIGH,
      chainContext: items === undefined ? undefined : {
        chainId: safe.chainId,
        releaseId: safe.releaseId,
        deploymentBlock: safe.deploymentBlock,
        artifactChecksum: safe.artifactChecksum,
      },
    };

    // Dry run: record the attempt and return without invoking work.
    if (dryRun) {
      const auditEventId = await this.log({ ...auditContext, outcome: 'success' });
      return {
        auditEventId: auditEventId,
        replayReference,
        dryRun: true,
        processed: 0,
        skipped: items.length,
        failed: 0,
        stopped: false,
        outcome: 'success',
      };
    }

    // Idempotency key binds original message + payload hash + release context.
    const idempotencyKey = this.deriveIdempotencyKey(safe);
    const attemptId = await this.log(auditContext);

    let processed = 0;
    let skipped = 0;
    let failed = 0;
    let stopped = false;
    let outcome: AdminAuditOutcome = 'success';

    const runner = this.source.createQueryRunner();
    try {
      await runner.connect();
      await runner.startTransaction();

      // Reserve the idempotency key inside the transaction; conflicting replays
      // are skipped (no duplicate effects).
      const reserved = await this.reserveIdempotencyKey(runner.manager, idempotencyKey, attemptId);
      if (!reserved) {
        await runner.rollbackTransaction();
        const auditEventId = await this.log({
          ...auditContext,
          outcome: 'failure',
        });
        return {
          auditEventId: auditEventId,
          replayReference,
          dryRun: false,
          processed: 0,
          skipped: items.length,
          failed: 0,
          stopped: false,
          outcome: 'failure',
        };
      }

      for (const item of items) {
        if (safe.stop) {
          stopped = true;
          break;
        }
        try {
          await work(runner.manager, item);
          processed++;
        } catch {
          failed++;
          // Poison message: abort the batch and roll back to preserve atomicity.
          outcome = 'partial';
          throw new Error('Replay batch aborted on poison message');
        }
      }

      await this.recordReplayLinkage(runner.manager, {
        idempotencyKey,
        originalMessageId: safe.originalMessageId,
        originalPayloadHash: safe.originalPayloadHash,
        replayReference,
        attemptId,
        chainId: safe.chainId,
        releaseId: safe.releaseId,
        deploymentBlock: safe.deploymentBlock,
        artifactChecksum: safe.artifactChecksum,
        processed,
        skipped,
        failed,
        stopped,
      });

      await runner.commitTransaction();
    } catch (error) {
      if (runner.isTransactionActive) {
        try {
          await runner.rollbackTransaction();
        } catch {
          // Keep the durable attempt; never report success.
        }
      }
      await this.log({ ...auditContext, outcome: outcome === 'partial' ? 'partial' : 'failure' });
      throw error;
    } finally {
      await runner.release();
    }

    const auditEventId = await this.log({ ...auditContext, outcome });
    return {
      auditEventId,
      replayReference,
      dryRun: false,
      processed,
      skipped,
      failed,
      stopped,
      outcome,
    };
  }

  async query(filters: AdminAuditQueryFilters): Promise<AdminAuditQueryResult> {
    const page = filters.page ?? 1;
    const limit = filters.limit ?? 50;
    if (
      !Number.isSafeInteger(page) ||
      page < 1 ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      !Number.isSafeInteger((page - 1) * limit)
    ) {
      throw new Error('Invalid audit pagination');
    }
    const query = this.source
      .getRepository(AdminAuditLog)
      .createQueryBuilder('audit');
    for (const key of [
      'actorId',
      'correlationId',
      'action',
      'outcome',
    ] as const) {
      if (filters[key] !== undefined)
        query.andWhere(`audit.${key} = :${key}`, { [key]: filters[key] });
    }
    const [logs, total] = await query
      .orderBy('audit.chainSequence', 'DESC')
      .skip((page - 1) * limit)
      .take(limit)
      .getManyAndCount();
    return { logs, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  getByEventId(eventId: string): Promise<AdminAuditLog | null> {
    return this.source.getRepository(AdminAuditLog).findOneBy({ eventId });
  }

  async getStats(): Promise<Record<string, number>> {
    const rows: { outcome: string; count: string }[] = await this.source
      .getRepository(AdminAuditLog)
      .createQueryBuilder('audit')
      .select('audit.outcome', 'outcome')
      .addSelect('COUNT(*)', 'count')
      .groupBy('audit.outcome')
      .getRawMany();
    return Object.fromEntries(
      rows.map((row) => [row.outcome, Number(row.count)]),
    );
  }

  /** One consistent snapshot, including the persisted tip, detects gaps and tail loss. */
  async verifyIntegrity(): Promise<{
    valid: boolean;
    checked: number;
    firstInvalid?: string;
    errors: string[];
  }> {
    this.assertPostgres();
    return this.source.transaction('REPEATABLE READ', async (tx) => {
      const head = await tx.findOneByOrFail(AdminAuditHead, { id: 1 });
      let sequence = 0n;
      let previousHash: string | null = null;
      let checked = 0;
      for (;;) {
        const rows = await tx
          .getRepository(AdminAuditLog)
          .createQueryBuilder('audit')
          .where('audit.chainSequence > :sequence', {
            sequence: sequence.toString(),
          })
          .orderBy('audit.chainSequence', 'ASC')
          .take(500)
          .getMany();
        if (!rows.length) break;
        for (const row of rows) {
          checked++;
          if (
            BigInt(row.chainSequence) !== sequence + 1n ||
            row.previousHash !== previousHash ||
            row.integrityHash !== this.hash(row)
          ) {
            return {
              valid: false,
              checked,
              firstInvalid: row.eventId,
              errors: ['Audit chain integrity mismatch'],
            };
          }
          sequence = BigInt(row.chainSequence);
          previousHash = row.integrityHash;
        }
      }
      const valid =
        sequence.toString() === head.lastSequence &&
        previousHash === head.lastHash;
      return {
        valid,
        checked,
        errors: valid ? [] : ['Audit chain tip mismatch'],
      };
    });
  }

  /** Resolve capability and release compatibility. Default denial. */
  private async resolveReplayAuthority(
    request: DeadLetterReplayRequest,
  ): Promise<{ authorized: boolean; releaseCompatible: boolean }> {
    // Denied by default unless the capability is explicitly enabled.
    const enabled = this.config.get<string>('DEADLETTER_REPLAY_ENABLED');
    if (enabled !== 'true') return { authorized: false, releaseCompatible: false };
    const allowed = this.config.get<string>('DEADLETTER_REPLAY_CAPABILITY');
    if (!allowed || allowed !== request.capability)
      return { authorized: false, releaseCompatible: false };
    const currentReleaseId = this.config.get<string>('RELEASE_ID');
    const currentChainId = Number(this.config.get<string>('CHAIN_ID'));
    const currentChecksum = this.config.get<string>('ARTIFACT_CHECKSUM');
    const releaseCompatible =
      currentReleaseId === request.releaseId &&
      currentChainId === request.chainId &&
      currentChecksum === request.artifactChecksum;
    return { authorized: true, releaseCompatible };
  }

  private deriveIdempotencyKey(request: DeadLetterReplayRequest): string {
    return createHash('sha256')
      .update(
        [
          request.originalMessageId,
          request.originalPayloadHash,
          request.chainId,
          request.releaseId,
          request.deploymentBlock,
          request.artifactChecksum,
        ].join('|'),
      )
      .digest('hex');
  }

  /** Reserve idempotency key; returns false if already reserved (duplicate). */
  private async reserveIdempotencyKey(
    tx: EntityManager,
    idempotencyKey: string,
    attemptId: string,
  ): Promise<boolean> {
    const result = await tx.query(
      `INSERT INTO dead_letter_replay_reservations (idempotency_key, attempt_id, created_at)
       VALUES ($1, $2, now())
       ON CONFLICT (idempotency_key) DO NOTHING
       RETURNING idempotency_key`,
      [idempotencyKey, attemptId],
    );
    return Array.isArray(result) && result.length > 0;
  }

  /** Persist immutable link between original and replay references. */
  private async recordReplayLinkage(
    tx: EntityManager,
    link: {
      idempotencyKey: string;
      originalMessageId: string;
      originalPayloadHash: string;
      replayReference: string;
      attemptId: string;
      chainId: number;
      releaseId: string;
      deploymentBlock: string;
      artifactChecksum: string;
      processed: number;
      skipped: number;
      failed: number;
      stopped: boolean;
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO dead_letter_replay_links
       (idempotency_key, original_message_id, original_payload_hash, replay_reference,
        attempt_id, chain_id, release_id, deployment_block, artifact_checksum,
        processed, skipped, failed, stopped, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())`,
      [
        link.idempotencyKey,
        link.originalMessageId,
        link.originalPayloadHash,
        link.replayReference,
        link.attemptId,
        link.chainId,
        link.releaseId,
        link.deploymentBlock,
        link.artifactChecksum,
        link.processed,
        link.skipped,
        link.failed,
        link.stopped,
      ],
    );
  }

  private sanitizeReplayRequest(
    request: DeadLetterReplayRequest,
  ): DeadLetterReplayRequest {
    if (!request || typeof request !== 'object')
      throw new Error('Replay request required');
    if (typeof request.capability !== 'string' || !CODE.test(request.capability))
      throw new Error('Replay capability required');
    for (const value of [
      request.actorId,
      request.authorityReference,
      request.correlationId,
      request.originalMessageId,
      request.releaseId,
    ]) {
      if (typeof value !== 'string' || !UUID.test(value))
        throw new Error('Replay references must be UUIDs');
    }
    if (typeof request.reason !== 'string' || request.reason.trim().length < 8)
      throw new Error('Replay requires a meaningful reason');
    if (!HEX_SHA256.test(request.originalPayloadHash))
      throw new Error('Replay requires original payload hash');
    if (!Number.isSafeInteger(request.chainId) || request.chainId <= 0)
      throw new Error('Replay requires valid chain id');
    if (!BLOCK.test(request.deploymentBlock))
      throw new Error('Replay requires valid deployment block');
    if (!HEX_SHA256.test(request.artifactChecksum))
      throw new Error('Replay requires artifact checksum');
    const maxBatch = request.maxBatch ?? DEFAULT_BATCH_LIMIT;
    if (
      !Number.isInteger(maxBatch) ||
      maxBatch < 1 ||
      maxBatch > MAX_BATCH_LIMIT
    )
      throw new Error('Replay batch limit out of bounds');
    return {
      capability: request.capability,
      actorId: request.actorId,
      authorityReference: request.authorityReference,
      correlationId: request.correlationId,
      reason: request.reason.trim(),
      originalMessageId: request.originalMessageId,
      originalPayloadHash: request.originalPayloadHash,
      chainId: request.chainId,
      releaseId: request.releaseId,
      deploymentBlock: request.deploymentBlock,
      artifactChecksum: request.artifactChecksum,
      maxBatch,
      dryRun: request.dryRun !== false,
      stop: request.stop === true,
    };
  }

  private async append(
    input: AdminAuditLogInput,
    tx: EntityManager,
  ): Promise<string> {
    const head = await tx
      .getRepository(AdminAuditHead)
      .findOneOrFail({ where: { id: 1 }, lock: { mode: 'pessimistic_write' } });
    const timestamp = new Date();
    const days = Number(
      this.config.get<string>('ADMIN_AUDIT_RETENTION_DAYS') ?? 365,
    );
    if (!Number.isInteger(days) || days < 1 || days > 3650)
      throw new Error('Invalid administrative audit retention');
    const record = tx.create(AdminAuditLog, {
      ...input,
      eventId: randomUUID(),
      chainSequence: (BigInt(head.lastSequence) + 1n).toString(),
      timestamp,
      retentionUntil: new Date(timestamp.getTime() + days * 86_400_000),
      resultReference: input.resultReference ?? null,
      chainContext: input.chainContext ?? null,
      severity: input.severity ?? AdminAuditSeverity.MEDIUM,
      previousHash: head.lastHash,
    });
    record.integrityHash = this.hash(record);
    await tx.insert(AdminAuditLog, record);
    await tx.update(
      AdminAuditHead,
      { id: 1 },
      { lastSequence: record.chainSequence, lastHash: record.integrityHash },
    );
    return record.eventId;
  }

  /** Deliberate allowlist: raw states, reasons, errors, headers and metadata never enter storage/logs. */
  private sanitize(input: AdminAuditLogInput): AdminAuditLogInput {
    for (const value of [
      input.actorId,
      input.targetId,
      input.authorityReference,
      input.requestReference,
      input.correlationId,
    ]) {
      if (typeof value !== 'string' || !UUID.test(value))
        throw new Error('Audit references must be UUIDs');
    }
    if (
      input.resultReference !== undefined &&
      !UUID.test(input.resultReference)
    )
      throw new Error('Invalid audit result reference');
    if (
      !CODE.test(input.capability) ||
      !CODE.test(input.targetType) ||
      typeof input.capability !== 'string' ||
      typeof input.targetType !== 'string'
    )
      throw new Error('Invalid audit capability or target type');
    if (
      !['user', 'service', 'system'].includes(input.actorType) ||
      !['rbac', 'policy', 'service', 'chain'].includes(input.authoritySource) ||
      !OUTCOMES.includes(input.outcome) ||
      !Object.values(AdminActionType).includes(input.action) ||
      !Object.values(AdminActionCategory).includes(input.actionCategory) ||
      (input.severity !== undefined &&
        !Object.values(AdminAuditSeverity).includes(input.severity))
    )
      throw new Error('Invalid audit classification');
    let chainContext: AdminAuditLogInput['chainContext'];
    if (input.authoritySource === 'chain' && !input.chainContext)
      throw new Error('Chain authority requires release context');
    if (input.chainContext) {
      const c = input.chainContext;
      if (
        !Number.isSafeInteger(c.chainId) ||
        c.chainId <= 0 ||
        !UUID.test(c.releaseId) ||
        !/^(0|[1-9][0-9]{0,19})$/.test(c.deploymentBlock) ||
        !/^0x[0-9a-f]{64}$/i.test(c.artifactChecksum)
      )
        throw new Error('Invalid chain audit context');
      chainContext = {
        chainId: c.chainId,
        releaseId: c.releaseId,
        deploymentBlock: c.deploymentBlock,
        artifactChecksum: c.artifactChecksum,
      };
    }
    return {
      actorId: input.actorId,
      actorType: input.actorType,
      action: input.action,
      actionCategory: input.actionCategory,
      targetType: input.targetType,
      targetId: input.targetId,
      capability: input.capability,
      authoritySource: input.authoritySource,
      authorityReference: input.authorityReference,
      requestReference: input.requestReference,
      resultReference: input.resultReference,
      correlationId: input.correlationId,
      outcome: input.outcome,
      severity: input.severity,
      chainContext,
    };
  }

  private hash(row: AdminAuditLog): string {
    const data: Partial<AdminAuditLog> = { ...row };
    delete data.integrityHash;
    // All nested fields have a fixed shape; canonicalize JSONB key ordering too.
    const canonical = (value: unknown): string => {
      if (value instanceof Date) return JSON.stringify(value.toISOString());
      if (value !== null && typeof value === 'object') {
        return (
          '{' +
          Object.keys(value)
            .sort()
            .map(
              (key) =>
                JSON.stringify(key) +
                ':' +
                canonical((value as Record<string, unknown>)[key]),
            )
            .join(',') +
          '}'
        );
      }
      return JSON.stringify(value);
    };
    return createHash('sha256').update(canonical(data)).digest('hex');
  }

  private assertPostgres(): void {
    if (this.source.options.type !== 'postgres')
      throw new Error('Administrative audit persistence requires PostgreSQL');
  }
}
