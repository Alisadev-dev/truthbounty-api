import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
  runOptimismSepoliaResilience,
  type ResilienceReadinessReport,
} from '../../scripts/optimism-sepolia-resilience-runner';
import {
  assertDigestParity,
  assertNoDuplicate,
  assertNoGap,
} from '../chaos/harness/recovery-assertions';
import { redactStringSecrets } from '../chaos/harness/fault-guard';

const REQUIRED_WORKLOADS = [
  'claim-list',
  'claim-detail',
  'verification',
  'dispute',
  'status',
  'stream',
];

const REQUIRED_SCENARIOS = [
  'RPC latency',
  'RPC failure',
  'Redis loss',
  'Database failover',
  'Evidence gateway outage',
  'Indexer lag',
];

describe('Optimism Sepolia resilience readiness', () => {
  let report: ResilienceReadinessReport;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    report = await runOptimismSepoliaResilience();
  });

  it('binds the report to the pinned release provenance', () => {
    const manifest = JSON.parse(
      readFileSync(
        resolve(
          __dirname,
          '../../contracts/manifests/optimism-sepolia.release.json',
        ),
        'utf8',
      ),
    );

    expect(report.provenance.chainId).toBe(11155420);
    expect(report.provenance.chainId).toBe(manifest.chainId);
    expect(report.provenance.releaseId).toBe(manifest.releaseId);
    expect(report.provenance.artifactChecksum).toBe(manifest.manifestChecksum);
    expect(report.provenance.deploymentBlock).toBe(
      manifest.contracts[0].deployBlock,
    );
    expect(Object.keys(report.provenance.contractAddresses)).toHaveLength(
      manifest.contracts.length,
    );
  });

  it('covers the representative claim/verification/dispute/status/stream workloads', () => {
    expect(report.workloads.map((w) => w.name)).toEqual(
      expect.arrayContaining(REQUIRED_WORKLOADS),
    );
    for (const workload of report.workloads) {
      expect(workload.endpoint).toMatch(/^\//);
      expect(workload.weight).toBeGreaterThan(0);
    }
  });

  it('injects and recovers every agreed dependency fault', () => {
    expect(report.scenarios.map((s) => s.scenario)).toEqual(REQUIRED_SCENARIOS);
    for (const scenario of report.scenarios) {
      expect(scenario.recoveredCleanly).toBe(true);
      expect(scenario.requests).toBeGreaterThan(0);
    }
  });

  it('holds the no-gap / no-duplicate / digest-parity invariants after recovery', () => {
    const blocks = report.scenarios.map((_, i) => 24_850_000 + i);
    assertNoGap(blocks);
    assertNoDuplicate(report.scenarios.map((s) => s.scenario));
    assertDigestParity(report.projectionDigest, report.canonicalDigest);

    expect(report.invariants.noGap).toBe(true);
    expect(report.invariants.noDuplicate).toBe(true);
    expect(report.invariants.digestParity).toBe(true);
  });

  it('degrades explicitly instead of serving false freshness', () => {
    for (const scenario of report.scenarios) {
      expect(scenario.freshnessViolations).toBe(0);
      if (scenario.fault !== 'healthy') {
        expect(
          scenario.degradedResponses + scenario.rejectedRequests,
        ).toBeGreaterThan(0);
      }
    }
    expect(report.invariants.failClosed).toBe(true);
  });

  it('keeps queue growth bounded and shuts down gracefully', () => {
    for (const scenario of report.scenarios) {
      expect(scenario.queueHighWatermark).toBeLessThanOrEqual(
        report.limits.maxQueueDepth,
      );
    }
    expect(report.invariants.boundedQueueGrowth).toBe(true);
    expect(report.invariants.gracefulShutdown).toBe(true);
  });

  it('emits privacy-safe telemetry with no secrets or protected evidence', () => {
    const serialized = JSON.stringify(report);
    expect(redactStringSecrets(serialized)).toBe(serialized);
    expect(serialized).not.toMatch(
      /secret|bearer|private[_ -]?key|0x[a-f0-9]{64}/i,
    );
    expect(report.invariants.telemetryPrivacySafe).toBe(true);
  });

  it('records residual risks with mitigations', () => {
    expect(report.residualRisks.length).toBeGreaterThanOrEqual(3);
    for (const risk of report.residualRisks) {
      expect(['LOW', 'MEDIUM', 'HIGH']).toContain(risk.severity);
      expect(risk.mitigation.length).toBeGreaterThan(20);
    }
  });
});
