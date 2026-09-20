# Changelog

Material changes to Skillz Shield are recorded here. Consumers use full commit
pins; release tags identify reviewed milestones and are not moved.

## Unreleased

- Split the public Shield companion into separate Overview, Evidence, Engines,
  Integrate, and Guidance pages, each directly addressable on GitHub Pages.
- Bring Forge-style GitHub access and a persisted light, dark, or system-display
  choice into Shield's sticky navigation, including a compact keyboard-safe menu.
- Add compact skill guidance and source links, with Agent Skills best practices,
  provider and project catalogs, and a separately labeled community collection.
  Identify OpenAI's deprecated skills catalog and current plugins destination.
- Add a standalone Vite, React, TypeScript, and Tailwind SPA on GitHub Pages,
  reusing Forge's typefaces and component patterns with an inverted dark palette.
- Publish sanitized security evidence and exact scanner identities separately
  from the current Shield action pin, with explicit incomplete and stale states.
- Separate website builds from scanner verification so frontend-only changes
  do not run the real-engine smoke suite or expand skill scan scope.

## [1.0.2](https://github.com/OKHP3/skillz-shield/releases/tag/v1.0.2) - 2026-09-19

- Rename the project from `skill-security-pipeline` to **Skillz Shield**, with
  repository identity `OKHP3/skillz-shield` and an explicit relationship to
  OverKill Hill's Skillz Forge and MurderBird story.
- Expand the README and add architecture, contribution, security-reporting, and
  agent-operation documentation.
- Add contribution templates, portable text-file settings, private vulnerability
  reporting, and a clearly proposed roadmap for a static web companion.
- Brand the Action, verification workflow, summaries, and outbound user agent as
  Skillz Shield without changing scanner scope or decision rules.

## [1.0.1](https://github.com/OKHP3/skillz-shield/releases/tag/v1.0.1) - 2026-09-19

Commit: `f81a2ba9cda9be52312b7ebbb793a80ac1b41934`.

- Treat NVIDIA-declared input exclusions as incomplete package coverage, even
  when the upstream report describes its narrower analysis as complete.
- Retain sanitized exclusion counts and add regression coverage for excluded
  package content.
- Report count-only progress during large inventories.

## [1.0.0](https://github.com/OKHP3/skillz-shield/releases/tag/v1.0.0) - 2026-09-19

Commit: `66dd153f62bde67235daea34c8d81985f5573561`.

- Introduce the reusable plan, resolve, install, and scan action for Cisco Skill
  Scanner and NVIDIA SkillSpector.
- Select committed skill packages, including family drafts without `SKILL.md`,
  and preserve source bytes in bounded temporary staging.
- Resolve official stable vendors to immutable source, wheel, and dependency
  identities; supervise scanners without executing skill content.
- Normalize findings and completeness separately, bind reports to the selected
  package identity, and produce sanitized evidence.
- Add contract tests and real-engine smoke checks using synthetic fixtures.
