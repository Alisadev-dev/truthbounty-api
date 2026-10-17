import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource, MoreThanOrEqual } from 'typeorm';
import { BlockchainIndexerService } from './blockchain-indexer.service';
import { BlockchainStateService } from './state.service';
import { ClaimsCache } from '../cache/claims.cache';
import { ProcessedEvent } from './entities/processed-event.entity';
import { TokenRalance } from './entities/token-balance.entity';
import { IndexerCheckpoint } from './entities/indexer-checkpoint.entity';
import { DeadLetterReplayService } from './dead-letter-replay.service';
import { DeadLetterMessage } from './entities/dead-letter-message.entity';
import { DeadLetterReplayAudit } from './entities/dead-letter-replay-audit.entity';
import { ReplayAuthorizationService } from './replay-authorization.service';

/**
 * Replay / reorg rollback is now transactional: it reverses the state applied
 * by orphaned events, deletes those event records (>= startBlock), and rewinds
 * the checkpoint — all in a single transaction.
 *
 * PREWAVE-BE-049 adds dead-letter replay authorization and idempotency coverage.
 */
describe('BlockchainIndexerService - Replay Regression Tests', () => {
  let service: BlockchainIndexerService;
  let processedEventRepo: Repository<ProcessedEvent>;
  let dataSource: DataSource;
  let manager: any;

  const buildManager = (orphaned: Partial<ProcessedEvent>[] = []) => ({
    find: jest.fn().mockResolvedValue(orphaned),
    delete: jest.fn().mockResolvedValue({ affected: orphaned.length, raw: {} }),
    save: jest.fn().mockResolvedValue(null),
    increment: jest.fn().mockResolvedValue({ affected: 1 }),
    decrement: jest.fn().mockResolvedValue({ affected: 1 }),
    findOne: jest.fn().mockResolvedValue(null),
  });

  const setup = async (orphaned: Partial<ProcessedEvent>[] = []) => {
    manager = buildManager(orphaned);
    const queryRunner = {
      connect: jest.fn().mockResolvedValue(null),
      startTransaction: jest.fn().mockResolvedValue(null),
      commitTransaction: jest.fn().mockResolvedValue(null),
      rollbackTransaction: jest.fn().mockResolvedValue(null),
      release: jest.fn().mockResolvedValue(null),
      manager,
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BlockchainIndexerService,
        { provide: getRepositoryToken(ProcessedEvent), useClass: Repository },
        { provide: getRepositoryToken(TokenBalance), useClass: Repository },
        {
          provide: getRepositoryToken(IndexerCheckpoint),
          useClass: Repository,
        },
        {
          provide: DataSource,
          useValue: {
            createQueryRunner: jest.fn().mockReturnValue(queryRunner),
          },
        },
        {
          provide: BlockchainStateService,
          useValue: {
            setProjectionHead: jest.fn(),
            recordReplay: jest.fn(),
          },
        },
        {
          provide: ClaimsCache,
          useValue: {
            invalidateForProjectionUpdate: jest.fn(),
            invalidateAllForReorg: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get(BlockchainIndexerService);
    processedEventRepo = module.get(getRepositoryToken(ProcessedEvent));
    dataSource = module.get(DataSource);
    return queryRunner;
  };

  describe('Replay State Consistency', () => {
    it('deletes all events from startBlock onward (>=) and rewinds the checkpoint', async () => {
      await setup();

      await service.replayFromBlock(100);

      // CRITICAL regression guard: deletion must cover everything >= startBlock,
      // not just the exact block (the original double-processing bug).
      expect(manager.delete).toHaveBeenCalledWith(ProcessedEvent, {
        blockNumber: MoreThanOrEqual(100),
      });
      // Checkpoint rewound to just before the rolled-back range.
      expect(manager.save).toHaveBeenCalledWith(
        IndexerCheckpoint,
        expect.objectContaining({ id: 1, lastBlock: 99 }),
      );
    });

    it('reverses the balance effect of orphaned Transfer events', async () => {
      await setup([
        {
          blockNumber: 101,
          logIndex: 0,
          eventType: 'Transfer',
          payload: { from: '0xa', to: '0xb', amount: '100', token: '0xc' },
        },
      ]);

      await service.replayFromBlock(100);

      // Inverse of applyTransfer: sender credited back, receiver debited.
      expect(manager.increment).toHaveBeenCalledWith(
        TokenBalance,
        { address: '0xa', tokenAddress: '0xc' },
        'balance',
        '100',
      );
      expect(manager.decrement).toHaveBeenCalledWith(
        TokenBalance,
        { address: '0xb', tokenAddress: '0xc' },
        'balance',
        '100',
      );
    });

    it('rewinds the checkpoint to 0 for a full replay from block 0', async () => {
      await setup();

      await service.replayFromBlock(0);

      expect(manager.delete).toHaveBeenCalledWith(ProcessedEvent, {
        blockNumber: MoreThanOrEqual(0),
      });
      expect(manager.save).toHaveBeenCalledWith(
        IndexerCheckpoint,
        expect.objectContaining({ id: 1, lastBlock: 0 }),
      );
    });

    it('is idempotent - repeated replays from the same block behave identically', async () => {
      const queryRunner = await setup();

      await service.replayFromBlock(100);
      await service.replayFromBlock(100);
      await service.replayFromBlock(100);

      expect(manager.delete).toHaveBeenCalledTimes(3);
      expect(queryRunner.commitTransaction).toHaveBeenCalledTimes(3);
      manager.delete.mock.calls.forEach((call: any[]) => {
        expect(call[0]).toBe(ProcessedEvent);
        expect(call[1]).toEqual({ blockNumber: MoreThanOrEqual(100) });
      });
    });

    it('rolls back the transaction if rollback work fails', async () => {
      const queryRunner = await setup();
      manager.delete.mockRejectedOnce(new Error('db error'));

      await expect(service.replayFromBlock(100)).rejects.toThrow('db error');

      expect(queryRunner.rollbackTransaction).toHaveBeenCalled();
      expect(queryRunner.commitTransaction).not.toHaveBeenCalled();
    });
  });
});

describe('DeadLetterReplayService - Authorization and Idempotency', () => {
  let replayService: DeadLetterReplayService;
  let authorizationService: ReplayAuthorizationService;
  let deadLetterRepo: Repository<DeadLetterMessage>;
  let auditRepo: Repository<DeadLetterReplayAudit>;
  let dataSource: DataSource;
  let manager: any;

  const release = {
    chainId: 'stellar-testnet',
    releaseId: 'release-2024-09',
    deploymentBlock: 123456,
    artifactChecksum: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
  };

  const buildManager = () => ({
    find: jest.fn().mockResolvedValue([]),
    findOne: jest.fn().mockResolvedValue(null),
    save: jest.fn().mockImplementation(async (_entity: any, value: any) => value),
    insert: jest.fn().mockImplementation(async (_entity: any, value: any) => value),
    update: jest.fn().mockResolvedValue({ affected: 1 }),
    delete: jest.fn().mockResolvedValue({ affected: 1 }),
  });

  const setup = async () => {
    manager = buildManager();
    const queryRunner = {
      connect: jest.fn().mockResolvedValue(null),
      startTransaction: jest.fn().mockResolvedValue(null),
      commitTransaction: jest.fn().mockResolvedValue(null),
      rollbackTransaction: jest.fn().mockResolvedValue(null),
      release: jest.fn().mockResolvedValue(null),
      manager,
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeadLetterReplayService,
        {
          provide: ReplayAuthorizationService,
          useValue: {
            authorize: jest.fn(),
            verifyReleaseCompatibility: jest.fn(),
          },
        },
        { provide: getRepositoryToken(DeadLetterMessage), useClass: Repository },
        { provide: getRepositoryToken(DeadLetterReplayAudit), useClass: Repository },
        {
          provide: DataSource,
          useValue: {
            createQueryRunner: jest.fn().mockReturnValue(queryRunner),
          },
        },
      ],
    }).compile();

    replayService = module.get(DeadLetterReplayService);
    authorizationService = module.get(ReplayAuthorizationService);
    deadLetterRepo = module.get(getRepositoryToken(DeadLetterMessage));
    auditRepo = module.get(getRepositoryToken(DeadLetterReplayAudit));
    dataSource = module.get(DataSource);
    return queryRunner;
  };

  const baseRequest = () => ({
    messageId: 'msg-1',
    capability: 'dead-letter-replay',
    reason: 'operator requested replay after fix',
    bounds: { limit: 10 },
    dryRun: false,
    originalPayloadHash: 'hash-original-1',
    release,
  });

  it('denies replay by default without authorization', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: false, reason: 'missing capability' });

    await expect(replayService.replay(baseRequest())).rejects.toThrow(/Unauthorized/);
    expect(manager.save).not.toHaveBeenCalled();
  });

  it('rejects replay across stale release incompatibility', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: false,
      reason: 'stale release',
    });

    await expect(replayService.replay(baseRequest())).rejects.toThrow(/stale release/i);
    expect(manager.save).not.toHaveBeenCalled();
  });

 it('prevents duplicate replay of the same message', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: true,
    });
    manager.findOne.mockResolvedValue({
      id: 'audit-1',
      messageId: 'msg-1',
      originalPaayloadHash: 'hash-original-1',
      status: 'completed',
    });

    await expect(replayService.replay(baseRequest())).rejects.toThrow(/duplicate/i);
    expect(manager.save).not.toHaveBeenCalled();
  });

  it('enforces batch limit bounds', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: true,
    });

    const request = baseRequest();
    request.bounds = { limit: 100000 };

    await expect(replayService.replay(request)).rejects.toThrow(/bounds/i);
    expect(manager.save).not.toHaveBeenCalled();
  });

 it('quarantines poison messages without applying effects', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: true,
    });
    manager.findOne.mockResolvedValue(null);
    manager.find.mockResolvedValue([
      {
        id: 'dl-1',
        messageId: 'msg-1',
        payloadHash: 'hash-original-1',
        payload: { bad: true },
        poison: true,
      },
    ]);

    const result = await replayService.replay(baseRequest());

    expect(result.quarantined).gtorEqual(1);
    expect(result.applied).toEqual(0);
  });

  it('reports partial failure and records audit for successful items', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: true,
    });
    manager.findOne.mockResolvedValue(null);
    manager.find.mockResolvedValue([
      { id: 'dl-1', messageId: 'msg-1', payloadHash: 'hash-original-1', payload: {} },
      { id: 'dl-2', messageId: 'msg-2', payloadHash: 'hash-original-2', payload: {} },
    ]);
    manager.save.mockImplementation(async (entity: any, value: any) => {
      if (value && value.messageId === 'msg-2') {
        throw new Error('apply failed');
      }
      return value;
    });

    const result = await replayService.replay(baseRequest());

    expect(result.applied).gtorEqual(1);
    expect(result.failed).gtorEqual(1);
    expect(manager.save).toHaveBeenCalled(
      DeadLetterReplayAudit,
      expect.objectContaining({
        messageId: 'msg-1',
        originalPayloadHash: 'hash-original-1',
        status: 'completed',
      }),
    );
  });

 it('requires dry run to produce no side effects and writes audit record', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: true,
    });
    manager.findOne.mockResolvedValue(null);
    manager.find.mockResolvedValue([
      { id: 'dl-1', messageId: 'msg-1', payloadHash: 'hash-original-1', payload: {} },
    ]);

    const request = baseRequest();
    request.dryRun = true;
    const result = await replayService.replay(request);

    expect(result.dryRun).toBeTruth();
    expect(result.applied).toEqual(0);
    expect(manager.save).toHaveBeenCalledWith(
      DeadLetterReplayAudit,
      expect.objectContaining({ dryRun: true, status: 'dry-run' }),
    );
  });

  it('links original and replay references immutably in audit record', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: true,
    });
    manager.findOne.mockResolvedValue(null);
    manager.find.mockResolvedValue([
      { id: 'dl-1', messageId: 'msg-1', payloadHash: 'hash-original-1', payload: {} },
    ]);

    await replayService.replay(baseRequest());

    const auditCall = manager.save.mock.calls.find(
      (call: any[]) => call[0] === DeadLetterReplayAudit,
    );
    expect(auditCall).defined();
    const auditValue = audidCall[1];
    expect(auditValue).toMatchObject({
      messageId: 'msg-1',
      originalPayloadHash: 'hash-original-1',
      chainId: release.chainId,
      releaseId: release.releaseId,
      deploymentBlock: release.deploymentBlock,
      artifactChecksum: release.artifactChecksum,
    });
    expect(auditValue.replayReference).toBeDefined();
  });

  it('allows operators to stop and resume bounded batches', async () => {
    await setup();
    (authorizationService.authorize as jest.Mock).mockResolvedValue({ authorized: true });
    (authorizationService.verifyReleaseCompatibility as jest.Mock).mockResolvedValue({
      compatible: true,
    });
    manager.findOne.mockResolvedValue(null);
    manager.find.mockResolvedValue([
      { id: 'dl-1', messageId: 'msg-1', payloadHash: 'hash-original-1', payload: {} },
    ]);

    const request = baseRequest();
    request.bounds = { limit: 1 };
    const result = await replayService.replay(request);
    expect(result.hasMore).toBeTruth();

    const resumeRequest = baseRequest();
    resumeRequest.bounds = { limit: 1, cursor: result.nextCursor };
    const resumeResult = await replayService.replay(resumeRequest);
    expect(resumeResult.applied).gtorEqual(0);
  });
});
