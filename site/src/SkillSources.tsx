import { Icon } from './icons';

const catalogs = [
  { label: 'OpenAI plugins', url: 'https://github.com/openai/plugins', legacy: true },
  { label: 'Anthropic', url: 'https://github.com/anthropics/skills' },
  { label: 'Microsoft', url: 'https://github.com/microsoft/skills#skill-catalog' },
  { label: 'Vercel', url: 'https://github.com/vercel-labs/agent-skills' },
  { label: 'Cloudflare', url: 'https://github.com/cloudflare/skills' },
  { label: 'Google', url: 'https://github.com/google/skills' },
  { label: 'Microsoft Learn', url: 'https://github.com/MicrosoftDocs/Agent-Skills' },
  { label: 'Notion', url: 'https://github.com/makenotion/skills' },
  { label: 'OpenClaw', url: 'https://github.com/openclaw/agent-skills' },
  { label: 'NVIDIA', url: 'https://github.com/NVIDIA/skills' },
];

export default function SkillSources() {
  return <section id="skill-guidance" className="section sources-section" aria-labelledby="sources-heading">
    <div className="section-heading">
      <div><p className="eyebrow">SKILL BASICS &amp; SOURCES</p><h2 id="sources-heading">Start at the source.</h2></div>
      <p>An Agent Skill packages instructions and supporting files for a task. For authoring guidance and examples, go to the sources below.</p>
    </div>
    <a className="sources-feature" href="https://agentskills.io/skill-creation/best-practices">
      <span><span className="mono-label">AUTHORING GUIDANCE</span><strong>Agent Skills best practices</strong></span>
      <Icon name="external" />
    </a>
    <div className="sources-catalogs">
      <h3>Provider &amp; project catalogs</h3>
      <ul>{catalogs.map(source => <li key={source.url}>
        <a href={source.url}>{source.label}<Icon name="external" width="13" height="13" /></a>
        {source.legacy && <a className="sources-legacy" href="https://github.com/openai/skills">Previous skills catalog · deprecated</a>}
      </li>)}</ul>
    </div>
    <div className="sources-community">
      <span className="mono-label">COMMUNITY-CURATED COLLECTION</span>
      <a href="https://awesome-copilot.github.com/skills/">Awesome Copilot <Icon name="external" width="14" height="14" /></a>
    </div>
  </section>;
}
