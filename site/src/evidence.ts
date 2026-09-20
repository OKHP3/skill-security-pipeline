export type Engine = {
  id: string; name: string; repository: string; version: string; commit: string;
  wheelSha256: string; lockSha256: string; projectSha256: string;
};
export type Evidence = {
  schemaVersion: 1;
  publishedAt: string;
  checkedAt: string;
  availability: 'available' | 'stale' | 'unavailable';
  reason: string | null;
  source: { repository: string; branch: string; headCommit: string | null; workflowUrl: string };
  control: {
    repository: string; version: string | null; commit: string | null; releaseUrl: string | null;
    consumerPin: string | null; consumerActionUrl: string | null;
  };
  scan: null | {
    observedAt: string; sourceCommit: string; sourceMatchesCurrent: boolean;
    runId: number; runUrl: string; scope: 'full'; decision: 'pass' | 'review-required' | 'incomplete';
    complete: boolean; inventoryCount: number; expectedPackages: number; completedPackages: number;
    highOrCriticalFindings: number; findingsBySeverity: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
    controlPin: string; controlActionUrl: string; toolchainFingerprint: string; engines: Engine[];
  };
};

const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const count = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
const date = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value));
const hex = (value: unknown, size: number) => typeof value === 'string' && new RegExp(`^[a-f0-9]{${size}}$`).test(value);
const optionalHex = (value: unknown, size: number) => value === null || hex(value, size);
const optionalText = (value: unknown) => value === null || typeof value === 'string';
const githubUrl = (value: unknown) => typeof value === 'string' && /^https:\/\/github\.com\/[A-Za-z0-9_.\-/]+$/.test(value);
const optionalUrl = (value: unknown) => value === null || githubUrl(value);

/** Reject incompatible evidence instead of showing reassuring defaults. */
export function parseEvidence(value: unknown): Evidence {
  if (!record(value) || value.schemaVersion !== 1 || !date(value.publishedAt) || !date(value.checkedAt)
    || !['available', 'stale', 'unavailable'].includes(String(value.availability)) || !optionalText(value.reason)) {
    throw new Error('Evidence format unavailable');
  }
  const { source, control, scan } = value;
  if (!record(source) || source.repository !== 'OKHP3/skillz' || source.branch !== 'main'
    || !optionalHex(source.headCommit, 40) || !githubUrl(source.workflowUrl)
    || !record(control) || control.repository !== 'OKHP3/skillz-shield' || !optionalText(control.version)
    || !optionalHex(control.commit, 40) || !optionalHex(control.consumerPin, 40)
    || !optionalUrl(control.releaseUrl) || !optionalUrl(control.consumerActionUrl)) throw new Error('Evidence provenance unavailable');
  if (scan === null) {
    if (value.availability !== 'unavailable') throw new Error('Missing scan evidence');
    return value as Evidence;
  }
  if (!record(scan) || !date(scan.observedAt) || !hex(scan.sourceCommit, 40) || typeof scan.sourceMatchesCurrent !== 'boolean'
    || !count(scan.runId) || !githubUrl(scan.runUrl) || scan.scope !== 'full'
    || !['pass', 'review-required', 'incomplete'].includes(String(scan.decision)) || typeof scan.complete !== 'boolean'
    || !count(scan.inventoryCount) || !count(scan.expectedPackages) || scan.expectedPackages === 0
    || scan.expectedPackages !== scan.inventoryCount || !count(scan.completedPackages)
    || scan.completedPackages > scan.expectedPackages || !count(scan.highOrCriticalFindings)
    || !hex(scan.controlPin, 40) || !githubUrl(scan.controlActionUrl) || !hex(scan.toolchainFingerprint, 64)
    || !record(scan.findingsBySeverity) || !['critical', 'high', 'medium', 'low', 'info'].every(k => count(scan.findingsBySeverity && (scan.findingsBySeverity as Record<string, unknown>)[k]))
    || !Array.isArray(scan.engines) || scan.engines.length !== 2) throw new Error('Scan evidence unavailable');
  const vendors: Record<string, string> = { cisco: 'cisco-ai-defense/skill-scanner', nvidia: 'NVIDIA/SkillSpector' };
  if (new Set(scan.engines.map(e => record(e) ? e.id : '')).size !== 2 || !scan.engines.every(e => record(e)
    && typeof e.id === 'string' && Object.hasOwn(vendors, e.id) && e.repository === vendors[e.id] && typeof e.name === 'string' && typeof e.version === 'string'
    && hex(e.commit, 40) && hex(e.wheelSha256, 64) && hex(e.lockSha256, 64) && hex(e.projectSha256, 64))) throw new Error('Engine pins unavailable');
  const expectedDecision = !scan.complete ? 'incomplete' : scan.highOrCriticalFindings > 0 ? 'review-required' : 'pass';
  if (scan.complete !== (scan.completedPackages === scan.expectedPackages)
    || scan.highOrCriticalFindings !== Number(scan.findingsBySeverity.critical) + Number(scan.findingsBySeverity.high)
    || scan.decision !== expectedDecision
    || (scan.sourceMatchesCurrent && scan.sourceCommit !== source.headCommit)) throw new Error('Contradictory scan evidence');
  return value as Evidence;
}

export function evidenceState(evidence: Evidence, now = Date.now()) {
  const { scan } = evidence;
  if (!scan) return { label: 'Evidence unavailable', tone: 'neutral', historical: true } as const;
  const historical = evidence.availability !== 'available' || !scan.sourceMatchesCurrent
    || now - Date.parse(scan.observedAt) > 8 * 24 * 60 * 60 * 1000;
  if (!scan.complete || scan.decision === 'incomplete') return { label: 'Analysis incomplete', tone: 'warning', historical } as const;
  if (scan.decision === 'review-required') return { label: 'Review required', tone: 'warning', historical } as const;
  return { label: historical ? 'Historical scan completed' : 'Scan completed', tone: 'neutral', historical } as const;
}

export function formatDate(value: string) {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
    hourCycle: 'h23', timeZone: 'UTC', timeZoneName: 'short',
  }).format(new Date(value));
}
