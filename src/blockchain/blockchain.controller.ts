import { Controller, Get, Post, Body, Param, Headers, Header, HttpCode, UseGuards, Req, BadRequestException, UnauthorizedException, ConflictException, NotFoundException, PayloadTooLargeException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Request } from 'express';
import { EventIndexingService } from './event-indexing.service';
import { ReconciliationService } from './reconciliation.service';
import { BlockchainStateService } from './state.service';
import { WeightedVoteResolutionService } from './weighted-vote-resolution.service';
import { ReadinessService } from './readiness.service';
import { DeadLetterReplayService } from './dead-letter-replay.service';
import { ReplayAuthorizationGuard } from './replay-authorization.guard';
import { BlockInfo, ResolutionConfig, VerificationVote } from './types';
import {
  ReplayRequest,
  ReplayResult,
  ReplayBatchStatus,
} from './dead-letter-replay.types';

/**
 * Default maximum number of messages a replay batch may contain.
 * Operators may request a smaller batch but never a larger one.
 */
const DEFAULT_REPLAY_BATCH_LIMIT = 50;

@ApiTags('blockchain')
@Controller('api/v1/blockchain')
export class BlockchainController {
  constructor(
    private eventIndexing: EventIndexingService,
    private reconciliation: ReconciliationService,
    private stateService: BlockchainStateService,
    private voteResolver: WeightedVoteResolutionService,
    private readinessService: ReadinessService,
    private replayService: DeadLetterReplayService,
  ) {}

  /**
   * Process a new block and its events
   */
  @Post('blocks/process')
  async processBlock(
    @Body()
    payload: {
      block: BlockInfo;
      events: any[];
    },
  ) {
    await this.eventIndexing.processBlock(payload.block, payload.events);

    return {
      success: true,
      message: `Block ${payload.block.number} processed`,
      blockNumber: payload.block.number,
    };
  }

  /**
   * Get indexing statistics
   */
  @Get('indexing/stats')
  async getIndexingStats() {
    return this.eventIndexing.getIndexingStats();
  }

  /**
   * Get chain state
   */
  @Get('chain/state')
  async getChainState() {
    return this.stateService.getChainState();
  }

  /**
   * Get readiness snapshot (internal, detailed).
   */
  @Get('readiness')
  async getReadiness() {
    return this.readinessService.evaluate();
  }

  /**
   * Get sanitized public readiness snapshot.
   */
  @Get('readiness/public')
  async getPublicReadiness() {
    return this.readinessService.getPublicSnapshot();
  }

  /**
   * Get all pending events
   */
  @Get('events/pending')
  async getPendingEvents() {
    return this.stateService.getPendingEvents();
  }

  /**
   * Get all confirmed events
   */
  @Get('events/confirmed')
  async getConfirmedEvents() {
    return this.eventIndexing.getConfirmedEvents();
  }

  /**
   * Get all orphaned events
   */
  @Get('events/orphaned')
  async getOrphanedEvents() {
    return this.stateService.getOrphanedEvents();
  }

  /**
   * Get event by ID
   */
  @Get('events/:eventId')
  async getEvent(@Param('eventId') eventId: string) {
    const event = await this.stateService.getEvent(eventId);
    if (!event) {
      return { error: 'Event not found', eventId };
    }
    return event;
  }

  /**
   * Get reorg history
   */
  @Get('reorg/history')
  async getReorgHistory() {
    return this.stateService.getReorgHistory();
  }

  /**
   * Get reorg statistics
   */
  @Get('reorg/statistics')
  async getReorgStatistics() {
    return this.reconciliation.getReorgStatistics();
  }

  /**
   * Verify state consistency
   */
  @Get('state/verify')
  async verifyStateConsistency() {
    return this.reconciliation.verifyStateConsistency();
  }

  /**
   * Get events at a specific block
   */
  @Get('blocks/:blockNumber/events')
  async getBlockEvents(@Param('blockNumber') blockNumber: number) {
    return this.stateService.getEventsByBlock(blockNumber);
  }

  /**
   * Get canonical block at height
   */
  @Get('blocks/:blockNumber/canonical')
  async getCanonicalBlock(@Param('blockNumber') blockNumber: number) {
    const block = await this.stateService.getCanonicalBlock(blockNumber);
    if (!block) {
      return { error: 'Block not found', blockNumber };
    }
    return block;
  }

  /**
   * Manual state reset (for testing/recovery)
   */
  @Post('state/reset')
  async resetState() {
    await this.stateService.clearAllState();
    return { success: true, message: 'State cleared' };
  }

  /**
   * Get current resolution configuration
   * GET /api/v1/blockchain/config/resolution
   */
  @Get('config/resolution')
  async getResolutionConfig() {
    return this.voteResolver.getConfig();
  }

  /**
   * Update resolution configuration
   * POST /api/v1/blockchain/config/resolution
   */
  @Post('config/resolution')
  async updateResolutionConfig(@Body() config: Partial<ResolutionConfig>)
    {
    try {
      this.voteResolver.updateConfig(config);
      return {
        success: true,
        message: 'Configuration updated',
        config: this.voteResolver.getConfig(),
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Simulate claim resolution (for testing)
   * POST /api/v1/blockchain/votes/simulate
   */
  @Post('votes/simulate')
  async simulateResolution(
    @Body()
    payload: {
      scenario:
        | 'clear_majority'
        | 'tie'
        | 'low_confidence'
        | 'whale_dominance'
        | 'insufficient_weight';
      config?: Partial<ResolutionConfig>;
    },
  ) {
    // Generate test votes based on scenario
    const testVotes = this.generateTestVotes(payload.scenario);

    const resolution = this.voteResolver.resolveClaim(
      testVotes,
      payload.config,
    );

    return {
      success: true,
      scenario: payload.scenario,
      votes: testVotes,
      resolution,
    };
  }

  /**
   * Replay a single dead-letter message.
   *
   * Replay is denied by default: the caller must present a protected capability
   * token, a replay reason, and the original payload hash. The service enforces
   * release/schema compatibility, idempotency, and immutable audit recording.
   */
  @Post('dead-letter/:id/replay')
  @UseGuards(ReplayAuthorizationGuard)
  @ApiOperation({ summary: 'Replay a dead-letter message (idempotent, audited)' })
  @ApiResponse({ status: 200, description: 'Replay accepted or deduplicated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 409, description: 'Stale release or duplicate replay' })
  @ApiResponse({ status: 422, description: 'Poison message or payload hash mismatch' })
  async replayDeadLetter(
    @Param('id') messageId: string,
    @Body() body: ReplayRequest,
    @Headers('authorization') authorization: string | undefined,
    @Header('x-replay-reason') replayReason: string | undefined,
    @Header('x-replay-capability') capability: string | undefined,
    @Header('x-replay-actor') actor: string | undefined,
    @Header('x-replay-dry-run') dryRunHeader: string | undefined,
    @Req() req: Request,
  ): Promise<ReplayResult> {
    if (!authorization || !capability) {
      throw new UnauthorizedException('replay requires protected capability');
    }

    const reason = body.reason ?? replayReason;
    if (!reason || reason.trim().length === 0) {
      throw new BadRequestException('replay requires a non-empty reason');
    }

    const dryRun =
      typeof body.dryRun === 'boolean'
        ? body.dryRun
        : dryRunHeader === 'true';

    const actorId = body.actor ?? actor ?? req.ip;
    if (!actorId) {
      throw new UnauthorizedException('replay requires an auditable actor');
    }

    const result = await this.replayService.replayOne({
      messageId,
      authorization,
      capability,
      reason,
      actorId,
      dryRun,
      originalPayloadHash: body.originalPayloadHash,
      releaseId: body.releaseId,
      chainId: body.chainId,
      deploymentBlock: body.deploymentBlock,
      artifactChecksum: body.artifactChecksum,
    });

    if (result.status === 'denied') {
      throw new UnauthorizedException(result.reason ?? 'replay denied');
    }
    if (result.status === 'stale') {
      throw new ConflictException(result.reason ?? 'release/schema incompatibility');
    }
    if (result.status === 'duplicate') {
      throw new ConflictException('duplicate replay detected');
    }
    if (result.status === 'poison') {
      throw new BadRequestException(result.reason ?? 'poison message');
    }
    if (result.status === 'not_found') {
      throw new NotFoundException(result.reason ?? 'dead-letter message not found');
    }

    return result;
  }

  /**
   * Replay a bounded batch of dead-letter messages.
   * Operators may stop/resume a batch via the control endpoints below.
   */
  @Post('dead-letter/replay-batch')
  @UseGuards(ReplayAuthorizationGuard)
  @ApiOperation({ summary: 'Replay a bounded batch of dead-letter messages' })
  async replayDeadLetterBatch(
    @Body()
    body: ReplayRequest & { messageIds?: string[]; limit?: number },
    @Headers('authorization') authorization: string | undefined,
    @Header('x-replay-reason') replayReason: string | undefined,
    @Header('x-replay-capability') capability: string | undefined,
    @Header('x-replay-actor') actor: string | undefined,
    @Header('x-replay-dry-run') dryRunHeader: string | undefined,
    @Req() req: Request,
  ): Promise<{ batchId: string; results: ReplayResult[] }> {
    if (!authorization || !capability) {
      throw new UnauthorizedException('replay requires protected capability');
    }

    const reason = body.reason ?? replayReason;
    if (!reason || reason.trim().length === 0) {
      throw new BadRequestException('replay requires a non-empty reason');
    }

    const limit = body.limit ?? DEFAULT_REPLAY_BATCH_LIMIT;
    if (!Number.isInteger(limit) || limit <= 0 || limit > DEFAULT_REPLAY_BATCH_LIMIT) {
      throw new PayloadTooLargeException(
        `replay batch limit must be between 1 and ${DEFAULT_REPLAY_BATCH_LIMIT}`,
      );
    }

    const messageIds = body.messageIds ?? [];
    if (messageIds.length > limit) {
      throw new PayloadTooLargeException(
        `replay batch exceeds limit of ${limit}`,
      );
    }

    const dryRun =
      typeof body.dryRun === 'boolean'
        ? body.dryRun
        : dryRunHHeader === 'true';

    const actorId = body.actor ?? actor ?? req.ip;
    if (!actorId) {
      throw new UnauthorizedException('replay requires an auditable actor');
    }

    return this.replayService.replayBatch({
      messageIds,
      authorization,
      capability,
      reason,
      actorId,
      dryRun,
      limit,
      originalPayloadHash: body.originalPayloadHash,
      releaseId: body.releaseId,
      chainId: body.chainId,
      deploymentBlock: body.deploymentBlock,
      artifactChecksum: body.artifactChecksum,
    });
  }

  /**
   * Stop an in-flight replay batch. Bounded batches are pausable at any time.
   */
  @Post('dead-letter/replay-batch/:batchId/stop')
  @UseGuards(ReplayAuthorizationGuard)
  async stopReplayBatch(
    @Param('batchId') batchId: string,
    @Headers('authorization') authorization: string | undefined,
    @Header('x-replay-capability') capability: string | undefined,
    @Header('x-replay-actor') actor: string | undefined,
    @Req() req: Request,
  ): Promise<ReplayBatchStatus> {
    if (!authorization || !capability) {
      throw new UnauthorizedException('replay requires protected capability');
    }
    const actorId = actor ?? req.ip;
    if (!actorId) {
      throw new UnauthorizedException('replay requires an auditable actor');
    }
    return this.replayService.stopBatch(batchId, { authorization, capability, actorId });
  }

  /**
   * Resume a previously stopped replay batch.
   */
  @Post('dead-letter/replay-batch/:batchId/resume')
  @UseGuards(ReplayAuthorizationGuard)
  async resumeReplayBatch(
    @Param('batchId') batchId: string,
    @Headers('authorization') authorization: string | undefined,
    @Header('x-replay-capability') capability: string | undefined,
    @Header('x-replay-actor') actor: string | undefined,
    @Req() req: Request,
  ): Promise<ReplayBatchStatus> {
    if (!authorization || !capability) {
      throw new UnauthorizedException('replay requires protected capability');
    }
    const actorId = actor ?? req.ip;
    if (!actorId) {
      throw new UnauthorizedException('replay requires an auditable actor');
    }
    return this.replayService.resumeBatch(batchId, { authorization, capability, actorId });
  }

  /**
   * Get the status of a replay batch.
   */
  @Get('dead-letter/replay-batch/:batchId')
  async getReplayBatchStatus(
    @Param('batchId') batchId: string,
  ): Promise<ReplayBatchStatus> {
    const status = await this.replayService.getBatchStatus(batchId);
    if (!status) {
      throw new NotFoundException(`replay batch ${batchId} not found`);
    }
    return status;
  }

  /**
   * Get the immutable audit trail for a replay (original -> replay linkage).
   */
  @Get('dead-letter/:id/replay-audit')
  async getReplayAudit(
    @Param('id') messageId: string,
  ): Promise<{ records: unknown[] }> {
    const records = await this.replayService.getAuditRecords(messageId);
    return { records };
  }

  /**
   * Helper method to generate test votes for simulation
   */
  private generateTestVotes(scenario: string): VerificationVote[] {
    const baseVote = {
      claimId: 'simulation-claim-001',
      timestamp: new Date(),
      eventId: 'sim-event-001',
    };

    switch (scenario) {
      case 'clear_majority':
        return [
          {
            ...baseVote,
            userId: 'user1',
            verdict: 'TRUE',
            userReputation: 80,
            stakeAmount: '100',
          },
          {
            ...baseVote,
            userId: 'user2',
            verdict: 'TRUE',
            userReputation: 70,
            stakeAmount: '75',
          },
          {
            ...baseVote,
            userId: 'user3',
            verdict: 'FALSE',
            userReputation: 60,
            stakeAmount: '50',
          },
        ];

      case 'tie':
        return [
          {
            ...baseVote,
            userId: 'user1',
            verdict: 'TRUE',
            userReputation: 70,
            stakeAmount: '100',
          },
          {
            ...baseVote,
            userId: 'user2',
            verdict: 'FALSE',
            userReputation: 70,
            stakeAmount: '100',
          },
        ];

      case 'low_confidence':
        return [
          {
            ...baseVote,
            userId: 'user1',
            verdict: 'TRUE',
            userReputation: 55,
            stakeAmount: '50',
          },
          {
            ...baseVote,
            userId: 'user2',
            verdict: 'FALSE',
            userReputation: 54,
            stakeAmount: '50',
          },
        ];

      case 'whale_dominance':
        return [
          {
            ...baseVote,
            userId: 'whale',
            verdict: 'TRUE',
            userReputation: 95,
            stakeAmount: '1000',
          },
          {
            ...baseVote,
            userId: 'user1',
            verdict: 'FALSE',
            userReputation: 30,
            stakeAmount: '25',
          },
          {
            ...baseVote,
            userId: 'user2',
            verdict: 'FALSE',
            userReputation: 30,
            stakeAmount: '25',
          },
        ];

      case 'insufficient_weight':
        return [
          {
            ...baseVote,
            userId: 'user1',
            verdict: 'TRUE',
            userReputation: 20,
            stakeAmount: '10',
          },
        ];

      default:
        return [];
    }
  }
}
