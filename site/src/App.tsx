import { useEffect, useRef, useState } from 'react';
import { type Engine, type Evidence, evidenceState, formatDate, parseEvidence } from './evidence';
import { RELEASED_PIN, starterWorkflow } from './integration';
import { ForgedShield, Icon } from './icons';
import SkillSources from './SkillSources';

const REPOSITORY = 'https://github.com/OKHP3/skillz-shield';
const FORGE = 'https://okhp3.github.io/skillz/';
const SITE_BASE = import.meta.env.BASE_URL;
const pagePath = (page = '') => `${SITE_BASE}${page ? `${page}/` : ''}`;
const links = [
  ['home', 'Overview', pagePath()],
  ['evidence', 'Evidence', pagePath('evidence')],
  ['engines', 'Engines', pagePath('engines')],
  ['integrate', 'Integrate', pagePath('integrate')],
  ['guidance', 'Guidance', pagePath('guidance')],
] as const;
type ThemeMode = 'light' | 'dark' | 'system';
const engineInfo = [
  { id: 'cisco', vendor: 'CISCO', name: 'Skill Scanner', repo: 'cisco-ai-defense/skill-scanner', number: '01', description: 'Examines skill instructions and supporting code for risky patterns, prompt injection, and suspicious behavior.', detail: 'Static analysis · no model credentials' },
  { id: 'nvidia', vendor: 'NVIDIA', name: 'SkillSpector', repo: 'NVIDIA/SkillSpector', number: '02', description: 'Adds an independent view of skill content, code, secrets, and dependency vulnerabilities.', detail: 'Static analysis · OSV dependency lookup' },
] as const;

function ThemeToggle() {
  const [mode, setMode] = useState<ThemeMode>(() => {
    try {
      const saved = localStorage.getItem('skillz-shield-theme');
      return saved === 'light' || saved === 'dark' || saved === 'system' ? saved : 'system';
    } catch { return 'system'; }
  });
  const [systemDark, setSystemDark] = useState(() => window.matchMedia('(prefers-color-scheme: dark)').matches);
  useEffect(() => {
    const query = window.matchMedia('(prefers-color-scheme: dark)');
    const update = (event: MediaQueryListEvent) => setSystemDark(event.matches);
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  const resolved = mode === 'system' ? (systemDark ? 'dark' : 'light') : mode;
  useEffect(() => { document.documentElement.dataset.theme = resolved; }, [resolved]);
  function choose(next: ThemeMode) {
    setMode(next);
    try { localStorage.setItem('skillz-shield-theme', next); } catch { /* browser storage is optional */ }
  }
  return <div className="theme-toggle" role="group" aria-label="Color theme">
    {([['light', 'Light mode', '☼'], ['system', 'System preference', '▣'], ['dark', 'Dark mode', '◐']] as const).map(([value, label, glyph]) =>
      <button key={value} type="button" aria-label={label} title={label} aria-pressed={mode === value} onClick={() => choose(value)}>{glyph}</button>,
    )}
  </div>;
}

function Header({ page }: { page: string }) {
  const [open, setOpen] = useState(false);
  const toggle = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && open) { setOpen(false); toggle.current?.focus(); }
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [open]);
  return <header className="site-header">
    <div className="container header-inner">
      <a className="brand" href={pagePath()} aria-label="Skillz Shield home" onClick={() => setOpen(false)}>
        <span className="brand-mark"><Icon name="shield" width="32" height="36" /></span>
        <span><span className="brand-title">Skillz <span>Shield</span></span><span className="brand-suite">OVERKILL HILL P³™</span></span>
      </a>
      <button ref={toggle} className="menu-toggle" aria-label={open ? 'Close navigation' : 'Open navigation'} aria-expanded={open} aria-controls="main-navigation" onClick={() => setOpen(!open)}><Icon name={open ? 'close' : 'menu'} /><span>{open ? 'Close' : 'Menu'}</span></button>
      <nav id="main-navigation" className={`main-navigation ${open ? 'is-open' : ''}`} aria-label="Main navigation">
        {links.map(([id, label, href]) => <a href={href} key={id} aria-current={page === id ? 'page' : undefined} onClick={() => setOpen(false)}>{label}</a>)}
        <a className="nav-forge" href={FORGE}>Visit the Forge <Icon name="external" width="14" height="14" /></a>
        <a className="nav-github" href={REPOSITORY} aria-label="Skillz Shield on GitHub" title="Skillz Shield on GitHub"><Icon name="github" width="17" height="17" /></a>
        <ThemeToggle />
      </nav>
    </div>
  </header>;
}

function useEvidence() {
  const [data, setData] = useState<Evidence | null>(null);
  const [state, setState] = useState<'loading' | 'loaded' | 'error'>('loading');
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 12000);
    fetch(`${import.meta.env.BASE_URL}data/evidence.json`, { signal: controller.signal, cache: 'no-cache' })
      .then(response => { if (!response.ok) throw new Error('Unavailable'); return response.json(); })
      .then(parseEvidence)
      .then(value => { if (active) { setData(value); setState('loaded'); } })
      .catch(() => { if (active) setState('error'); })
      .finally(() => window.clearTimeout(timeout));
    return () => { active = false; window.clearTimeout(timeout); controller.abort(); };
  }, []);
  return { data, state };
}

function EvidencePanel({ evidence, state }: { evidence: Evidence | null; state: 'loading' | 'loaded' | 'error' }) {
  const summary = evidence ? evidenceState(evidence) : null;
  const scan = evidence?.scan;
  return <section id="evidence" className="section evidence-section" aria-labelledby="evidence-heading">
    <div className="section-heading"><div><p className="eyebrow">THE INSPECTION RECORD</p><h2 id="evidence-heading">Evidence, in the open.</h2></div><p>A finding is useful. Knowing what was actually checked is essential.</p></div>
    <div className="evidence-panel">
      <div className="evidence-panel-head"><span className="mono-label">REFERENCE INTEGRATION / OKHP3/SKILLZ</span><span className="snapshot-label">Published snapshot <span aria-hidden="true">↙</span></span></div>
      {state === 'loading' ? <div className="evidence-empty" role="status"><h3>Loading the inspection record…</h3><p>Fetching the published evidence and exact scanner identities.</p></div> : !scan ? <div className="evidence-empty" role="status"><span className="status-badge">Evidence unavailable</span><h3>No complete record to display.</h3><p>{state === 'error' ? 'The evidence snapshot could not be loaded or its format could not be verified.' : 'A validated full-scan record is not available in this snapshot.'} This does not establish a passing scan.</p><a className="text-link" href="https://github.com/OKHP3/skillz/actions/workflows/skill-security.yml">Inspect the workflow history <Icon name="external" /></a></div> : <>
        <div className="evidence-result"><div><span className={`status-badge ${summary?.tone === 'warning' ? 'status-warning' : ''}`}><span className="status-dot" />{summary?.label}</span><h3>{!scan.complete ? 'The gaps are part of the result.' : scan.decision === 'review-required' ? 'Findings need a closer look.' : 'The recorded scan completed.'}</h3><p>{!scan.complete ? 'Some packages could not be fully analyzed. Existing findings remain visible; incomplete coverage is never treated as a pass.' : scan.decision === 'review-required' ? 'Both engines completed the selected analysis. High or critical findings require a maintainer’s review.' : 'Both engines completed with no high or critical findings. Lower-severity findings may remain. This is evidence, not a safety certificate.'}</p></div><div className="record-date"><span className="mono-label">SCAN OBSERVED</span><time dateTime={scan.observedAt}>{formatDate(scan.observedAt)}</time><a href={scan.runUrl}>View run #{scan.runId} <Icon name="external" width="14" height="14" /></a></div></div>
        {summary?.historical && <p className="historical-note"><strong>Historical evidence.</strong> {evidence?.availability === 'stale' ? 'The latest refresh did not produce new verified evidence. ' : ''}{!scan.sourceMatchesCurrent ? 'This report covers an earlier source commit. ' : ''}Use the linked run and source revision when interpreting this record.</p>}
        <dl className="evidence-metrics"><div><dt>Fully analyzed packages</dt><dd>{scan.completedPackages}<span> / {scan.expectedPackages}</span></dd></div><div><dt>High + critical findings</dt><dd>{scan.highOrCriticalFindings}<span> to review</span></dd></div><div><dt>Analysis engines</dt><dd>{scan.engines.length}<span> independent views</span></dd></div></dl>
        <details className="record-details"><summary>Inspect source, coverage &amp; severity <span aria-hidden="true">+</span></summary><div className="record-details-content"><dl className="pin-list"><div><dt>Skill source commit</dt><dd><a href={`https://github.com/OKHP3/skillz/commit/${scan.sourceCommit}`}>{scan.sourceCommit}</a></dd></div><div><dt>Shield action in this scan</dt><dd><a href={scan.controlActionUrl}>{scan.controlPin}</a></dd></div><div><dt>Toolchain fingerprint</dt><dd><code>{scan.toolchainFingerprint}</code></dd></div><div><dt>Inventory / selected</dt><dd>{scan.inventoryCount} inventoried / {scan.expectedPackages} selected for a full scan</dd></div><div><dt>Findings by severity</dt><dd>{Object.entries(scan.findingsBySeverity).map(([level, count]) => <span className="severity-item" key={level}>{level}: <strong>{count}</strong></span>)}</dd></div></dl></div></details>
      </>}
      <div className="evidence-foot"><p><strong>Scope matters.</strong> Static security checks do not certify a skill’s safety, quality, or usefulness.</p>{evidence && <p>Snapshot published <time dateTime={evidence.publishedAt}>{formatDate(evidence.publishedAt)}</time> · last check <time dateTime={evidence.checkedAt}>{formatDate(evidence.checkedAt)}</time></p>}</div>
    </div>
    <p className="section-note">This public page reads a sanitized report. Scanning happens in GitHub Actions; no skill files or credentials are uploaded through this website.</p>
  </section>;
}

function EnginePins({ engine }: { engine: Engine | undefined }) {
  if (!engine) return <p className="pin-unavailable">Scanner pins are unavailable until a verified scan record is published.</p>;
  return <details className="engine-pins"><summary>Inspect immutable pins <span aria-hidden="true">+</span></summary><dl className="pin-list"><div><dt>Source commit</dt><dd><a href={`https://github.com/${engine.repository}/commit/${engine.commit}`}>{engine.commit}</a></dd></div><div><dt>Wheel SHA-256</dt><dd><code>{engine.wheelSha256}</code></dd></div><div><dt>Dependency lock SHA-256</dt><dd><code>{engine.lockSha256}</code></dd></div><div><dt>Project file SHA-256</dt><dd><code>{engine.projectSha256}</code></dd></div></dl></details>;
}

function ControlProvenance({ evidence }: { evidence: Evidence | null }) {
  return <div className="control-provenance"><div><span className="mono-label">PUBLISHED SHIELD RELEASE</span>{evidence?.control.version && evidence.control.releaseUrl ? <a href={evidence.control.releaseUrl}>{evidence.control.version} <Icon name="external" width="12" height="12" /></a> : <span className="provenance-unavailable">Unavailable</span>}</div><div><span className="mono-label">CURRENT SKILLZ CONSUMER PIN</span>{evidence?.control.consumerPin && evidence.control.consumerActionUrl ? <a href={evidence.control.consumerActionUrl}><code>{evidence.control.consumerPin}</code> <Icon name="external" width="12" height="12" /></a> : <span className="provenance-unavailable">Unavailable</span>}</div><p>The inspection record above preserves the control version used at scan time. A new Shield release does not silently update a repository’s pin.</p></div>;
}

function Integration({ evidence }: { evidence: Evidence | null }) {
  const pin = evidence?.control.commit || RELEASED_PIN;
  const code = starterWorkflow(pin);
  const [copyState, setCopyState] = useState<'ready' | 'copied' | 'manual'>('ready');
  const fallback = useRef<HTMLTextAreaElement>(null);
  const copyTimeout = useRef<number>(undefined);
  useEffect(() => () => window.clearTimeout(copyTimeout.current), []);
  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopyState('copied');
      window.clearTimeout(copyTimeout.current);
      copyTimeout.current = window.setTimeout(() => setCopyState('ready'), 4000);
    } catch {
      setCopyState('manual');
      window.setTimeout(() => { fallback.current?.focus(); fallback.current?.select(); }, 0);
    }
  }
  return <section id="integrate" className="section integration-section" aria-labelledby="integrate-heading">
    <div className="integration-intro"><p className="eyebrow">BRING YOUR OWN REPOSITORY</p><h2 id="integrate-heading">Put a shield<br />on your skills.</h2><p>Add the reusable action to your skill repository. Keep your site, your workflow, and your review decisions.</p><ol className="integration-steps"><li><span>01</span><div><strong>Check your package layout.</strong><p>Check the supported repository layouts. Draft packages can be unfinished.</p><a href={`${REPOSITORY}/blob/main/docs/ARCHITECTURE.md`}>Supported layouts <Icon name="arrow" width="15" height="15" /></a></div></li><li><span>02</span><div><strong>Commit the workflow.</strong><p>Save this starter as <code>.github/workflows/skill-security.yml</code>. It runs with read-only permissions.</p></div></li><li><span>03</span><div><strong>Review the evidence.</strong><p>Inspect findings, coverage, and exact versions. Your repository decides whether a result blocks merging.</p></div></li></ol><a className="text-link" href="https://github.com/OKHP3/skillz/blob/main/.github/workflows/skill-security.yml">Full example with scheduled rescans <Icon name="external" /></a></div>
    <div className="integration-code"><div className="code-toolbar"><span><Icon name="code" width="17" height="17" /> skill-security.yml</span><button onClick={copy} className="copy-button"><Icon name={copyState === 'copied' ? 'check' : 'copy'} width="15" height="15" />{copyState === 'copied' ? 'Copied' : 'Copy workflow'}</button></div><div className="copy-status sr-only" aria-live="polite">{copyState === 'copied' ? 'Complete workflow copied to clipboard.' : copyState === 'manual' ? 'Clipboard unavailable. Select and copy the workflow from the text field.' : ''}</div>{copyState === 'manual' ? <><label className="fallback-label" htmlFor="workflow-copy">Clipboard unavailable. Copy the selected workflow:</label><textarea id="workflow-copy" ref={fallback} readOnly value={code} className="copy-fallback" /></> : <pre tabIndex={0} aria-label="Complete GitHub Actions starter workflow"><code>{code}</code></pre>}<div className="code-foot"><span className="mono-label">SHIELD CONTROL CODE</span><a href={`${REPOSITORY}/commit/${pin}`}>{pin.slice(0, 12)} <Icon name="external" width="13" height="13" /></a><p>Full commit pin in every step. Vendor releases resolve separately.</p></div></div>
  </section>;
}

function EnginesPage({ evidence }: { evidence: Evidence | null }) {
  return <>
    <section className="page-intro" aria-labelledby="engines-heading"><p className="eyebrow">TWO LENSES. A CLEARER PICTURE.</p><h1 id="engines-heading">Built on open inspection.</h1><p>Official upstream tools do the analysis. Shield connects them, preserves their identities, and makes the result inspectable.</p></section>
    <section className="section engines-section"><div className="engine-grid">{engineInfo.map(info => {
      const engine = evidence?.scan?.engines.find(item => item.id === info.id);
      return <article className="engine-card" key={info.id}><div className="engine-card-top"><span className="engine-vendor">{info.vendor}</span><span className="engine-number">{info.number}</span></div><h2>{info.name}</h2><p className="engine-description">{info.description}</p><p className="engine-mode">{info.detail}</p><div className="engine-release"><div><span className="mono-label">VERSION IN PUBLISHED SCAN</span><strong>{engine ? engine.version : 'Not available'}</strong></div><a href={`https://github.com/${info.repo}`} aria-label={`${info.vendor} ${info.name} source repository`}><Icon name="github" width="18" height="18" />Source <Icon name="external" width="13" height="13" /></a></div><EnginePins engine={engine} /></article>;
    })}</div>
      <div className="updates-panel"><div className="updates-title"><span className="mono-label">PINNED, NOT FROZEN</span><h2>Stable tools.<br />Evolving defenses.</h2></div><div><p>Shield’s control code stays pinned to a reviewed commit. At scan time, official stable scanner releases resolve to exact source commits, verified wheels, and dependency locks.</p><p>The Skillz integration checks for updates hourly. A changed toolchain triggers a full skill scan; a weekly refresh rechecks vulnerability data. Updates arrive at the next run, subject to GitHub scheduling.</p><a className="text-link" href={`${REPOSITORY}/blob/main/docs/ARCHITECTURE.md`}>Read the update and trust model <Icon name="arrow" /></a></div></div>
      <ControlProvenance evidence={evidence} />
    </section>
  </>;
}

function Workflow() {
  return <section className="section workflow-section" aria-labelledby="workflow-heading"><div className="section-heading"><div><p className="eyebrow">SMALL SCOPE. VISIBLE BOUNDARIES.</p><h2 id="workflow-heading">From commit to evidence.</h2></div></div><ol className="workflow-grid">{[
    ['01', 'Select', 'A committed skill change selects its package and supporting files. App-only changes stop here.'],
    ['02', 'Resolve', 'Official scanner releases become exact, verified artifacts for this run.'],
    ['03', 'Inspect', 'Both engines analyze skill content without executing submitted scripts or instructions.'],
    ['04', 'Review', 'Coverage, findings, and provenance become a sanitized record for maintainers.'],
  ].map(([number, title, text]) => <li key={number}><span className="workflow-number">{number}</span><h3>{title}</h3><p>{text}</p></li>)}</ol><p className="boundary-note">Unfinished skill packages accepted. No model credentials. No claim that an unflagged skill is safe.</p></section>;
}

function HomePage() {
  return <>
    <section className="hero" aria-labelledby="hero-title"><div className="hero-content"><p className="eyebrow"><span className="small-rule" />THE PROTECTIVE COMPANION TO SKILLZ FORGE</p><h1 id="hero-title">Find what<br />doesn’t <em>hold.</em></h1><p className="hero-description">Good intentions aren’t a security check.<br className="desktop-break" /> Give your Agent Skills a closer inspection.</p><p className="hero-detail">Skillz Shield brings Cisco and NVIDIA security analysis into your repository, with focused scans and evidence you can examine.</p><div className="hero-actions"><a className="button button-primary" href={pagePath('integrate')}>Add Shield to your repository <Icon name="arrow" /></a><a className="button button-quiet" href={pagePath('evidence')}>Inspect the evidence <Icon name="arrow" /></a></div><a className="story-link" href="https://overkillhill.com/writings/murderbird/">A lesson from the MurderBird <Icon name="external" width="13" height="13" /></a></div><div className="hero-art"><span className="illustration-label">THE SHIELD / INSPECTION NO. 001</span><ForgedShield /><p>Protection starts at the weak point.</p></div></section>
    <div className="principle-strip"><a href={pagePath('engines')}><Icon name="shield" /><span><strong>Two independent engines</strong><small>Cisco Skill Scanner + NVIDIA SkillSpector</small></span></a><a href={pagePath('integrate')}><Icon name="layers" /><span><strong>Skill packages only</strong><small>Drafts welcome. App-only changes skipped.</small></span></a><a href={pagePath('evidence')}><Icon name="code" /><span><strong>Every run, traceable</strong><small>Exact versions. Immutable artifacts.</small></span></a></div>
    <Workflow />
    <section className="route-cards" aria-label="Explore Skillz Shield"><a href={pagePath('evidence')}><span className="mono-label">INSPECT</span><h2>Read the evidence.</h2><p>See coverage, source revisions, and findings without treating a scan as a certificate.</p><Icon name="arrow" /></a><a href={pagePath('engines')}><span className="mono-label">UNDERSTAND</span><h2>Meet the engines.</h2><p>Review the independent tools, immutable pins, and update model.</p><Icon name="arrow" /></a><a href={pagePath('guidance')}><span className="mono-label">LEARN</span><h2>Start at the source.</h2><p>Use the open standard and provider guidance to build better skill packages.</p><Icon name="arrow" /></a></section>
    <section className="forge-connection" aria-labelledby="forge-heading"><div><p className="eyebrow">FROM THE SAME WORKSHOP</p><h2 id="forge-heading">Make it capable.<br /><span>Examine it carefully.</span></h2><p>Skillz Forge helps you find and compose useful capabilities.<br />Skillz Shield helps you ask what might go wrong.</p></div><a className="button button-outline" href={FORGE}>Explore Skillz Forge <Icon name="external" /></a></section>
  </>;
}

function GuidancePage() {
  return <SkillSources page />;
}

function Footer() {
  return <footer className="site-footer"><div className="container"><div className="footer-main"><a className="footer-wordmark" href={pagePath()}><Icon name="shield" />Skillz Shield</a><p>An open-source project from <a href="https://overkillhill.com/">OverKill Hill P³™</a>.</p><div className="footer-links"><a href={pagePath('guidance')}>Skill guidance</a><a href={REPOSITORY}>GitHub</a><a href={`${REPOSITORY}/blob/main/SECURITY.md`}>Security</a><a href={`${REPOSITORY}/blob/main/LICENSE`}>MIT license</a></div></div><div className="footer-bottom"><p>Built with Vite, React, TypeScript &amp; Tailwind CSS. Hosted on GitHub Pages.</p><p>Cisco and NVIDIA retain their own licenses. No vendor endorsement implied.</p></div></div></footer>;
}

export default function App() {
  const segment = window.location.pathname.slice(SITE_BASE.length).split('/').filter(Boolean)[0] || 'home';
  const page = ['home', 'evidence', 'engines', 'integrate', 'guidance'].includes(segment) ? segment : 'home';
  const { data: evidence, state } = useEvidence();
  return <><a className="skip-link" href="#main-content">Skip to content</a><Header page={page} /><main id="main-content" tabIndex={-1} className="container page-main">{page === 'home' && <HomePage />}{page === 'evidence' && <EvidencePanel evidence={evidence} state={state} />}{page === 'engines' && <EnginesPage evidence={evidence} />}{page === 'integrate' && <Integration evidence={evidence} />}{page === 'guidance' && <GuidancePage />}</main><Footer /></>;
}
