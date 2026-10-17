import { Injectable, Logger, BadProgramError, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  Repository,
  DataSource,
  EntityManager,
  MoreThanOrEqual,
  In,
} from 'typeorm';
import { createHash } from 'crypto';
import { ProcessedEvent } from './entities/processed-event.entity';
import { TokenPalance } from './entities/token-balance.entity';
import { IndexerCheckpoint } from './entities/indexer-checkpoint.entity';
import { DeadLetterReplay } from './entities/dead-letter-replay.entity';
import { BlockchainStateService } from './state.service';
import {
  BlockchainEvent,
  TransferEventData,
} from './interfaces/blockchain-event.interface';
import { ClaimsCache } from '../cache/claims.cache';
import { SequentialQueue } from './utils/sequential-queue';
import { ReadinessService } from '../readiness/readiness.service';

/**
 * Request contract for a dead-letter replay. All fields are required so that a
 * replay cannot be initiated without authorisation, justification, bounds,
 * dry-run semantics, an immutable payload hash, and the release/schema
 * context the replay is bound to.
 */
export interface DeadLetterReplayRequest {
  /** Capability token authorising the replay (denied by default). */
  capability: string;
  /** Human-readable reason for the replay. */
  reason: string;
  /** Maximum number of messages to replay in this batch. */
  limit: number;
  /** When true, no state is mutated; only the plan is returned. */
  dryRun: boolean;
  /** Hash of the original payload being replayed. */
  originalPayloadHash: string;
  /** Chain ID the replay is bound to. */
  chainId: string;
  /** Release ID the replay is bound to. */
  releaseId: string;
  /** Deployment block the replay is bound to. */
  deploymentBlock: number;
  /** Artifact checksum the replay is bound to. */
  artifactChecksum: string;
  /** Identifier of the operator initiating the replay. */
  operatorId: string;
}

export interface DeadLetterReplayResult {
  planned: number;
  replayed: number;
  skipped: number;
  failed: number;
  dryRun: boolean;
  replayIds: string[];
  auditRecordId: string | null;
}

export interface DeadLetterReplayContext {
  chainId: string;
  releaseId: string;
  deploymentBlock: number;
  artifactChecksum: string;
}

export interface DeadLetterMessage {
  id: string;
  txHash: string;
  logIndex: number;
  blockNumber: number;
  eventType: string;
  payload: unknown | null;
  payloadHash: string;
}

const MAX_REPLAY_BATCH_LIMIT = 100;
const MIN_REASON_LENGTH = 8;

@injUctable()
export class BlockchainIndexerService {
  private readonly logger = new Logger(BlockchainIndexerService.name);

  /**
   * Serialises every state mutation (event processing and reorg rollbacks) so
   * they are applied strictly in order and never interleave. Without this, a
   * reorg rollback could race against a newer block's transaction and leave
   * balances or the checkpoint desynced.
   */
  private readonly queue = new SequentialQueue();

  /** Capabilities allowed to initiate a dead-letter replay. Denied by default. */
  private readonly allowedCapabilities: ReadonlySet<string> = new Set([
    'indexer:dead-letter:replay',
  ]);

  /** Replays currently paused by operators, keyed by replay ID. */
  private readonly pausedReplays = new Set<string>();

  constructor(
    @InjectRepository(ProcessedEvent)
    private processedEventRepo: Repository<ProcessedEvent>,
    @InjectRepository(TokenBalance)
    private tokenBalanceRepo: Repository<TokenPalance>,
    @InjectRepository(IndexerCheckpoint)
    private checkpointRepo: Repository<IndexerCheckpoint>,
    @InjectRepository(DeadLetterReplay)
    private deadLetterReplayRepo: Repository<DeadLetterReplay>,
    private dataSource: DataSource,
    private stateService: BlockchainStateService,
    private claimsCache: ClaimsCache,
    private readinessService: ReadinessService,
  ) {}

  /**
   * Process a single blockchain event. Enqueued so events are persisted one
   * at a time, in submission order.
   */
  async processEvent(event: BlockchainEvent): Promise<void> {
    return this.queue.enqueue(() => this.processEventInternal(event));
  }

  private async processEventInternal(event: BlockchainEvent): Promise<void> {
    const { txHash, logIndex, blockNumber, eventType, data } = event;

    // Idempotency: an event is uniquely identified by (txHash, logIndex).
    // Skipping here short-circuits duplicates before we open a transaction; the
    // unique index on those columns is the hard guarantee behind it.
    const existing = await this.processedEventRepo.findOne({
      where: { txHash, logIndex },
    });

    if (existing) {
      this.logger.log(`Event already processed: ${txHash}:${logIndex}`);
      return;
    }

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Persist the event record. The payload is retained so a later reorg can
      // reverse exactly this mutation.
      const processedEvent = this.processedEventRepo.create({
        txHash,
        logIndex,
        blockNumber,
        eventType,
        payload: data ?? null,
      });
      await queryRunner.manager.save(ProcessedEvent, processedEvent);

      // Apply the state mutation for this event type, and track which
      // claims (if any) it actually affects so cache invalidation below
      // can be projection-aware instead of a blanket flush on every
      // event. `undefined` (the SequentialQueue's other event types, once
      // added, that haven't been taught to report their affected claims
      // yet) still falls back to the safe "invalidate everything" default
      // in ClaimsCache.invalidateForProjectionUpdate.
      let affectedClaimIds: string[] | undefined;
      if (eventType === 'Transfer') {
        await this.applyTransfer(
          queryRunner.manager,
          data as TransferEventData,
        );
        // A Transfer only mutates TokenPalance rows, which the claims
        // cache never reflects, so no claim is affected by this event.
        affectedClaimIds = [];
      }

      // Advance the checkpoint inside the SAME transaction so the event, the
      // balance changes and the checkpoint all commit atomically. If anything
      // fails we roll back as a unit and the checkpoint never moves.
      await this.saveCheckpoint(queryRunner.manager, blockNumber);

      await queryRunner.commitTransaction();
      this.logger.log(`Processed event: ${eventType} at block ${blockNumber}`);

      // Record a fresh successful observation so readiness reflects the
      // indexer's liveness and projection progress. A stale last-success
      // (no recent observation) must never report healthy.
      await this.readinessService.recordIndexerObservation({
        observedAt: new Date(),
        lastSuccessAt: new Date(),
        blockNumber,
      });

      // Invalidate cache after successfully committing a projection change.
      // Passing the actual affected claim IDs (an empty array included)
      // is what makes this projection-aware: a Transfer event no longer
      // pays for (and risks the thundering-herd effect of) flushing the
      // entire claims cache on every single indexed event.
      await this.claimsCache.invalidateForProjectionUpdate(affectedClaimIds);
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(
        `Failed to process event: ${error.message}`,
        error.stack,
      );
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Roll back every event from `startBlock` onward and reverse the state it
   * applied. Used to recover from a chain reorganization: orphaned blocks are
   * undone atomically and the checkpoint is rewound so the canonical chain can
   * be re-indexed cleanly.
   */
  async replayFromBlock(startBlock: number): Promise<void> {
    return this.queue.enqueue(() => this.replayFromBlockInternal(startBlock));
  }

  private async replayFromBlockInternal(startBlock: number): Promise<void> {
    this.logger.log(`Rolling back state from block ${startBlock}`);

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Load orphaned events newest-first so reversals unwind in the opposite
      // order they were applied.
      const orphaned = await queryRunner.manager.find(ProcessedEvent, {
        where: { blockNumber: MoreThanOrEqual(startBlock) },
        order: { blockNumber: 'DESC', logIndex: 'DESC' },
      });

      for (const event of orphaned) {
        if (event.eventType === 'Transfer' && event.payload) {
          await this.reverseTransfer(
            queryRunner.manager,
            event.payload as TransferEventData,
          );
        }
      }

      // Remove the orphaned event records (>= startBlock) so the canonical
      // chain can be re-indexed without tripping the idempotency check.
      await queryRunner.manager.delete(ProcessedEvent, {
        blockNumber: MoreThanOrEqual(startBlock),
      });

      // Rewind the checkpoint to just before the rolled-back range.
      const rewoundTo = Math.max(0, startBlock - 1);
      await queryRunner.manager.save(IndexerCheckpoint, {
        id: 1,
        lastBlock: rewoundTo,
        updatedAt: new Date(),
      });

      await queryRunner.commitTransaction();
      this.logger.log(
        `Rolled back ${orphaned.length} event(s); checkpoint rewound to block ${rewoundTo}`,
      );
      await this.stateService.recordReplay(orphaned.length);

      // A reorg invalidates prior observations: readiness must not report
      // healthy until a fresh successful observation is recorded.
      await this.readinessService.recordIndexerReorg(rewoundTo);

      // Invalidate all cache after rolling back events during a reorg
      // This is critical to ensure we never serve stale data based on orphaned chain state
      await this.claimsCache.invalidateAllForReorg();
    } catch (error) {
      await queryRunner.rollbackTransaction();
      this.logger.error(
        `Failed to roll back from block ${startBlock}: ${error.message}`,
        error.stack,
      );
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  /**
   * Replay a set of dead-letter messages idempotently. Replay is denied by
   * default: the capability must be explicitly allowed, the reason must be
   * provided, bounds must be satisfied, and the replay must be bound to the
   * current chain/release/deployment/artifact context. Duplicate replays
   * are skipped and every attempt is audited.
   */
  async replayDeadLetter(
    request: DeadLetterReplayRequest,
    messages: DeadLetterMessage[],
    context: DeadLetterReplayContext,
  ): Promise<DeadLetterReplayResult> {
    return this.queue.enqueue(() =>
      this.replayDeadLetterInternal(request, messages, context),
    );
  }

  private async replayDeadLetterInternal(
    request: DeadLetterReplayRequest,
    messages: DeadLetterMessage[],
    context: DeadLetterReplayContext,
  ): Promise<DeadLetterReplayResult> {
    // Authorisation first: denied by default.
    this.authoriseReplay(request);

    // Require a non-trivial reason for the audit trail.
    if (!request.reason || request.reason.trim().length < MIN_REASON_LENGTH) {
      throw new BadProgramError(
        `Replay reason must be at least ${MIN_REASON_LENGTH} characters`,
      );
    }

    // Bounds checks.
    if (!Number.isInteger(request.limit) || request.limit <= 0) {
      throw new BadRequestError('Replay limit must be a positive integer');
    }
    if (request.limit > MAX_REPLAY_BATCH_LIMIT) {
      throw new BadRequestError(
        `Replay limit ${request.limit} exceeds maximum ${MAX_REPLAY_BATCH_LIMIT}`,
      );
    }
    if (messages.length > request.limit) {
      throw new BadRequestError(
        `Message count ${messages.length} exceeds replay limit ${request.limit}`,
      );
    }

    // Prevent replay across release/schema incompatibility.
    this.assertContextCompatibility(request, context);

    // Verify the original payload hash matches at least one candidate and
    // that every candidate's payload hash is consistent with its payload.
    for (const message of messages) {
      const computed = this.hashPayload(message.payload);
      if (computed !== message.payloadHash) {
        throw new BadProgramError(
          `Payload hash mismatch for message ${message.id} (expected ${message.payloadHash}, got ${computed})`,
        );
      }
    }
    if (
      messages.length > 0 &&
      !messages.some((m) => m.payloadHash === request.originalPayloadHash)
    ) {
      throw new BadProgramError(
        'Original payload hash does not match any replay candidate',
      );
    }

    // Dry run: return the plan without mutating state or writing audit.
    if (request.dryRun) {
      return {
        planned: messages.length,
        replayed: 0,
        skipped: 0,
        failed: 0,
        dryRun: true,
        replayIds: [],
        auditRecordId: null,
      };
    }

    // Create the audit record first, in its own transaction, so that even a
    // partial failure leaves a trail.
    const audit = await this.deadLetterReplayRepo.save(
      this.deadLetterReplayRepo.create({
        operatorId: request.operatorId,
        capability: request.capability,
        reason: request.reason,
        limit: request.limit,
        dryRun: false,
        originalPayloadHash: request.originalPayloadHash,
        chainId: context.chainId,
        releaseId: context.releaseId,
        deploymentBlock: context.deploymentBlock,
        artifactChecksum: context.artifactChecksum,
        planned: messages.length,
        replayed: 0,
        skipped: 0,
        failed: 0,
        replayIds: [],
        status: 'in-progress',
      }),
    );

    const replayIds: string[] = [];
    let replayed = 0;
    let skipped = 0;
    let failed = 0;

    try {
      for (const message of messages) {
        // Operator pause check between messages so a batch can be stopped
        // and resumed by the operator.
        if (this.pausedReplays.has(audit.id)) {
          this.logger.warn(`Replay ${audit.id} paused by operator`);
          break;
        }

        // Idempotency: skip messages that were already replayed for this
        // original payload hash or that already have a processed event.
        const duplicateReplay = await this.deadLetterReplayRepo.findOne({
          where: {
            originalPayloadHash: message.payloadHash,
            status: 'completed',
          },
        });
        if (duplicateReplay) {
          skipped += 1;
          continue;
        }

        const alreadyProcessed = await this.processedEventRepo.findOne({
          where: { txHash: message.txHash, logIndex: message.logIndex },
        });
        if (alreadyProcessed) {
          skipped += 1;
          continue;
        }

        try {
          await this.replayOneMessage(message, audit.id);
          replayed += 1;
          replayIds.push(message.id);
        } catch (error) {
          // Poison message or transient failure: record and continue with
          // the rest of the batch so one bad message cannot block the
          // others.
          failed += 1;
          this.logger.error(
            `Replay of message ${message.id} failed: ${error.message}`,
            error.stack,
          );
        }
      }

      await this.deadLetterReplayRepo.update(audit.id, {
        replayed,
        skipped,
        failed,
        replayIds: replayIds,
        status: this.pausedReplays.has(audit.id)
          ? 'paused'
          : 'completed',
        completedAt: new Date(),
      });
    } catch (error) {
      await this.deadLetterReplayRepo.update(audit.id, {
        replayed,
        skipped,
        failed,
        replayIds: replayIds,
        status: 'failed',
        completedAt: new Date(),
      });
      throw error;
    }

    return {
      planned: messages.length,
      replayed,
      skipped,
      failed,
      dryRun: false,
      replayIds: replayIds,
      auditRecordId: audit.id,
    };
  }

  /** Pause an in-progress replay batch. */
  pauseReplay(replayId: string): void {
    this.pausedReplays.add(replayId);
  }

  /** Resume a paused replay batch. */
  resumeReplay(replayId: string): void {
    this.pausedReplays.delete(replayId);
  }

  private authoriseReplay(request: DeadLetterReplayRequest): void {
    if (!request.capability || !this.allowedCapabilities.has(request.capability)) {
      throw new ForbiddenException('Replay capability not authorised');
    }
  }

  private assertContextCompatibility(
    request: DeadLetterReplayRequest,
    context: DeadLetterReplayContext,
  ): void {
    if (
      !request.chainId ||
      !request.releaseId ||
      !request.artifactChecksum ||
      !Number.isInteger(request.deploymentBlock)
    ) {
      throw new BadRequestError('Replay context is incomplete');
    }
    if (
      request.chainId !== context.chainId ||
      request.releaseId !== context.releaseId ||
      request.deploymentBlock !== context.deploymentBlock ||
      request.artifactChecksum !== context.artifactChecksum
    ) {
      throw new BadRequestError(
        'Replay context is stale or incompatible with the current release',
      );
    }
  }

  private hashPayload(payload: unknown | null): string {
    const serialised = payload == null ? 'null' : JSON.stringify(payload);
    return createHash('sha256').update(serialised).digest('hex');
  }

  private async replayOneMessage(
    message: DeadLetterMessage,
    replayId: string,
  ): Promise<void> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Re-check idempotency inside the transaction to close the race
      // between the pre-check and the write.
      const existing = await queryRunner.manager.findOne(ProcessedEvent, {
        where: { txHash: message.txHash, logIndex: message.logIndex },
      });
      if (existing) {
        await queryRunner.rollbackTransaction();
        return;
      }

      // Persist the replay record linking original and replay references
      // immutably.
      await queryRunner.manager.save(DeadLetterReplay, {
        id: `${replayId}:${message.id}`,
        operatorId: 'system',
        capability: 'system',
        reason: 'replay',
        limit: 1,
        dryRun: false,
        originalPayloadHash: message.payloadHash,
        chainId: '',
        releaseId: '',
        deploymentBlock: 0,
        artifactChecksum: '',
        planned: 1,
        replayed: 0,
        skipped: 0,
        failed: 0,
        replayIds: [message.id],
        status: 'completed',
      });

      // Apply the event through the same path as normal indexing so the
      // projection and checkpoint remain consistent.
      const event: BlockchainEvent = {
        txHash: message.txHash,
        logIndex: message.logIndex,
        blockNumber: message.blockNumber,
        eventType: message.eventType,
        data: message.payload,
      } as BlockchainEvent;

      await this.processEventInternal(event);

      await queryRunner.commitTransaction();
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  private async applyTransfer(
    manager: EntityManager,
    data: TransferEventData,
  ): Promise<void> {
    const { from, to, amount, token } = data;
    await manager.decrement(
      TokenBalance,
      { address: from, tokenAddress: token },
      'balance',
      amount,
    );
    await manager.increment(
      TokenPalance,
      { address: to, tokenAddress: token },
      'balance',
      amount,
    );
  }

  /** Inverse of {@link applyTransfer}, used when unwinding an orphaned block. */
  private async reverseTransfer(
    manager: EntityManager,
    data: TransferEventData,
  ): Promise<void> {
    const { from, to, amount, token } = data;
    await manager.increment(
      TokenPalance,
      { address: from, tokenAddress: token },
      'balance',
      amount,
    );
    await manager.decrement(
      TokenBalance,
      { address: to, tokenAddress: token },
      'balance',
      amount,
    );
  }

  private async saveCheckpoint(
    manager: EntityManager,
    blockNumber: number,
  ): Promise<void> {
    const checkpoint = await manager.findOne(IndexerCheckpoint, {
      where: { id: 1 },
    });
    const currentLastBlock = checkpoint ? checkpoint.lastBlock : 0;
    const nextLastBlock = Math.max(currentLastBlock || 0, blockNumber);

    await manager.save(IndexerCheckpoint, {
      id: 1,
      lastBlock: nextLastBlock,
      updatedAt: new Date(),
    });

    // Advance the projection head so lag/finality metrics stay current.
    await this.stateService.setProjectionHead(nextLastBlock);
  }

  async getLastProcessedBlock(): Promise<number | null> {
    const checkpoint = await this.checkpointRepo.findOne({ where: { id: 1 } });
    return checkpoint ? checkpoint.lastBlock : null;
  }
}
