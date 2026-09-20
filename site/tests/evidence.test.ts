import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evidenceState, parseEvidence, type Evidence } from '../src/evidence.ts';
import { RELEASED_PIN, starterWorkflow } from '../src/integration.ts';

const NOW = Date.parse('2026-09-20T12:00:00Z');
function fixture(): Evidence {
  return {
    schemaVersion: 1, publishedAt: '2026-09-20T11:00:00Z', checkedAt: '2026-09-20T11:00:00Z', availability: 'available', reason: null,
    source: { repository: 'OKHP3/skillz', branch: 'main', headCommit: 'a'.repeat(40), workflowUrl: 'https://github.com/OKHP3/skillz/actions/workflows/skill-security.yml' },
    control: { repository: 'OKHP3/skillz-shield', version: 'v1.0.2', commit: 'b'.repeat(40), releaseUrl: 'https://github.com/OKHP3/skillz-shield/releases/tag/v1.0.2', consumerPin: 'b'.repeat(40), consumerActionUrl: 'https://github.com/OKHP3/skillz-shield/tree/' + 'b'.repeat(40) },
    scan: { observedAt: '2026-09-20T10:00:00Z', sourceCommit: 'a'.repeat(40), sourceMatchesCurrent: true, runId: 100, runUrl: 'https://github.com/OKHP3/skillz/actions/runs/100', scope: 'full', decision: 'pass', complete: true, inventoryCount: 8, expectedPackages: 8, completedPackages: 8, highOrCriticalFindings: 0, findingsBySeverity: { critical: 0, high: 0, medium: 3, low: 1, info: 0 }, controlPin: 'b'.repeat(40), controlActionUrl: 'https://github.com/OKHP3/skillz-shield/tree/' + 'b'.repeat(40), toolchainFingerprint: 'c'.repeat(64), engines: [{ id: 'cisco', name: 'Cisco Skill Scanner', repository: 'cisco-ai-defense/skill-scanner', version: '2.1.0', commit: 'd'.repeat(40), wheelSha256: 'e'.repeat(64), lockSha256: 'f'.repeat(64), projectSha256: '1'.repeat(64) }, { id: 'nvidia', name: 'NVIDIA SkillSpector', repository: 'NVIDIA/SkillSpector', version: '2.11.2', commit: 'd'.repeat(40), wheelSha256: 'e'.repeat(64), lockSha256: 'f'.repeat(64), projectSha256: '1'.repeat(64) }] },
  };
}

test('published evidence conforms to the frontend contract', () => {
  const data = JSON.parse(readFileSync(new URL('../public/data/evidence.json', import.meta.url), 'utf8').replace(/^\uFEFF/, ''));
  assert.equal(parseEvidence(data).schemaVersion, 1);
});

test('a completed scan never gets a safety-certified label', () => {
  assert.deepEqual(evidenceState(parseEvidence(fixture()), NOW), { label: 'Scan completed', tone: 'neutral', historical: false });
});

test('incomplete coverage is visible and cannot claim pass', () => {
  const data = fixture();
  data.scan!.completedPackages = 2;
  assert.throws(() => parseEvidence(data));
  data.scan!.complete = false;
  assert.throws(() => parseEvidence(data));
  data.scan!.decision = 'incomplete';
  assert.equal(evidenceState(parseEvidence(data), NOW).label, 'Analysis incomplete');
});

test('empty inventory, partial full-scan inventory, and excess completion are rejected', () => {
  for (const change of [{ inventoryCount: 0, expectedPackages: 0, completedPackages: 0 }, { inventoryCount: 9 }, { completedPackages: 10 }]) {
    const data = fixture(); Object.assign(data.scan!, change); assert.throws(() => parseEvidence(data));
  }
});

test('severity totals and review decisions must agree', () => {
  const data = fixture();
  data.scan!.highOrCriticalFindings = 2;
  assert.throws(() => parseEvidence(data));
  data.scan!.findingsBySeverity.high = 2;
  assert.throws(() => parseEvidence(data));
  data.scan!.decision = 'review-required';
  assert.equal(evidenceState(parseEvidence(data), NOW).label, 'Review required');
});

test('both official engines and exact immutable pins are required', () => {
  for (const mutation of [
    (data: Evidence) => { data.scan!.engines.pop(); },
    (data: Evidence) => { data.scan!.engines[1] = data.scan!.engines[0]; },
    (data: Evidence) => { data.scan!.engines[1].id = 'unknown'; delete (data.scan!.engines[1] as Partial<Record<string, unknown>>).repository; },
    (data: Evidence) => { data.scan!.engines[0].wheelSha256 = 'unknown'; },
  ]) { const data = fixture(); mutation(data); assert.throws(() => parseEvidence(data)); }
});

test('unsafe links and source-match contradictions cannot be rendered', () => {
  const unsafe = fixture(); unsafe.source.workflowUrl = 'javascript:alert(1)'; assert.throws(() => parseEvidence(unsafe));
  const mismatch = fixture(); mismatch.source.headCommit = '0'.repeat(40); assert.throws(() => parseEvidence(mismatch));
});

test('stale refresh, old observed time, and different source revision each remain historical', () => {
  const stale = fixture(); stale.availability = 'stale'; stale.reason = 'refresh-unavailable';
  const old = fixture(); old.scan!.observedAt = '2026-09-01T10:00:00Z';
  const different = fixture(); different.source.headCommit = '0'.repeat(40); different.scan!.sourceMatchesCurrent = false;
  for (const value of [stale, old, different]) {
    const state = evidenceState(parseEvidence(value), NOW);
    assert.equal(state.historical, true); assert.equal(state.label, 'Historical scan completed');
  }
});

test('unavailable evidence never defaults to zero findings or completed scan', () => {
  const data = fixture(); data.scan = null; data.availability = 'unavailable';
  assert.equal(evidenceState(parseEvidence(data), NOW).label, 'Evidence unavailable');
  data.availability = 'available'; assert.throws(() => parseEvidence(data));
});

test('starter workflow pins all four phases and skips costly work for empty plans', () => {
  const workflow = starterWorkflow(RELEASED_PIN);
  assert.equal(workflow.split(`uses: OKHP3/skillz-shield@${RELEASED_PIN}`).length - 1, 4);
  assert.equal(workflow.split("if: steps.plan.outputs.scan == 'true'").length - 1, 3);
  for (const mode of ['plan', 'resolve', 'install', 'scan']) assert.ok(workflow.includes(`mode: ${mode}`));
  assert.ok(workflow.includes('contents: read')); assert.ok(workflow.includes('persist-credentials: false'));
  assert.throws(() => starterWorkflow('main'));
});
