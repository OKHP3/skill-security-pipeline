# Skillz Shield

[![Verify Skillz Shield](https://github.com/OKHP3/skillz-shield/actions/workflows/verify.yml/badge.svg)](https://github.com/OKHP3/skillz-shield/actions/workflows/verify.yml)

**Security evidence for Agent Skills. A protective companion to Skillz Forge.**

Skillz Shield is the [OverKill Hill](https://overkillhill.com/) integration that
checks committed skill packages with [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner)
and [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector). It gives maintainers
reviewable findings and makes missing analysis visible before they rely on a skill.

Its guiding phrase comes from [The MurderBird: What the Water Kept](https://overkillhill.com/writings/murderbird/):
**“Find what doesn’t hold.”** [Skillz Forge](https://overkillhill.com/projects/skillz/)
makes reusable capabilities discoverable; Shield examines their security risks.

Visit [Skillz Shield](https://okhp3.github.io/skillz-shield/) for the public
interface, scanner identities, security evidence, and installation guidance.
The Vite, React, TypeScript, and Tailwind SPA is hosted on GitHub Pages. It reuses
Forge's typography and visual language with an inverted, dark espresso palette.

The reusable GitHub Action runs independently of both websites. The repository
is `OKHP3/skillz-shield`, formerly `skill-security-pipeline`. Scanning takes place
in GitHub Actions; the browser displays public evidence and never receives
scanner credentials or executes submitted skills.

## What gets checked

- Changed, committed skill packages and their supporting files. A change to a
  package reference, fixture, or script selects that package.
- Draft packages in declared skill families, even without a finished `SKILL.md`,
  name, description, or license. Metadata completeness is not an admission gate.
- Project support skills under `.agents/skills/` and exported skills under
  `skills/`, identified by their `SKILL.md` markers.

Application-only changes produce an empty plan and skip vendor installation and
scanning. Family administration, recognized migration locators, and unrelated
archives are outside the inventory. Removed packages need no scan. The exact
layout and exclusions are documented in [Architecture](docs/ARCHITECTURE.md).

Neither scanner executes submitted skill instructions, scripts, installers, or
dependencies. Both use static security analysis without model credentials.
NVIDIA's dependency analysis can contact OSV. This is not a skill quality,
usefulness, or maturity evaluation; NVIDIA SkillEvaluator is not included.

## Use in a skill repository

Run on a disposable Ubuntu x86_64 GitHub-hosted runner with read-only permissions.
Pin Shield to a full commit SHA, keep scan state outside the source checkout, and
do not pass secrets to the scan. This example uses the released `v1.0.2` code;
documentation on the main branch can describe changes awaiting the next release.

```yaml
name: Skillz Shield
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  skills:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Select skill packages
        id: plan
        uses: OKHP3/skillz-shield@b81aff7f323b47ae0747ff33571f3c9bc8ec60cb # v1.0.2
        with:
          mode: plan
          state: ${{ runner.temp }}/skillz-shield-state
          base: ${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.event_name == 'push' && github.event.before || '' }}
          full: ${{ github.event_name == 'workflow_dispatch' }}

      - name: Resolve current stable scanner releases
        if: steps.plan.outputs.scan == 'true'
        uses: OKHP3/skillz-shield@b81aff7f323b47ae0747ff33571f3c9bc8ec60cb # v1.0.2
        env:
          GH_TOKEN: ${{ github.token }}
        with:
          mode: resolve
          state: ${{ runner.temp }}/skillz-shield-state

      - name: Install verified scanner environments
        if: steps.plan.outputs.scan == 'true'
        uses: OKHP3/skillz-shield@b81aff7f323b47ae0747ff33571f3c9bc8ec60cb # v1.0.2
        with:
          mode: install
          state: ${{ runner.temp }}/skillz-shield-state

      - name: Scan the selected skills
        if: steps.plan.outputs.scan == 'true'
        uses: OKHP3/skillz-shield@b81aff7f323b47ae0747ff33571f3c9bc8ec60cb # v1.0.2
        with:
          mode: scan
          state: ${{ runner.temp }}/skillz-shield-state

      - name: Keep sanitized evidence
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: skillz-shield-evidence
          path: |
            ${{ runner.temp }}/skillz-shield-state/plan.json
            ${{ runner.temp }}/skillz-shield-state/pins.json
            ${{ runner.temp }}/skillz-shield-state/report.json
          if-no-files-found: ignore
          retention-days: 14
```

For automatic vendor-change rescans and weekly vulnerability-data refreshes, use
the [Skillz consumer workflow](https://github.com/OKHP3/skillz/blob/main/.github/workflows/skill-security.yml)
as the complete integration example. The action itself does not schedule jobs or
change repository protection settings. If Actions are restricted, allow Shield
and the pinned actions used by its [action definition](action.yml) and your caller.

## Read the result

| Decision | Meaning |
|---|---|
| `pass` | Both engines completed the requested static analysis with no high or critical findings. Lower-severity findings may still be present. |
| `review-required` | Both engines completed, and at least one high or critical finding needs review. |
| `incomplete` | At least one package could not be fully analyzed. Findings already obtained remain visible. |

`review-required` and `incomplete` produce a failing scan step. A failed resolution
or installation may stop before a report exists; that is not a passing scan.
Whether a failing job blocks merging is the consuming repository's decision.

Reports identify the source commit, package content digest, scanner versions and
immutable artifacts, public rule IDs, severities, and coverage. They omit raw
skill snippets and scanner diagnostics. **No result certifies that a skill is
safe, useful, mature, or ready for production.**

## How updates arrive

The Shield control code stays pinned to a reviewed commit. On each actual scan,
it resolves official stable scanner releases to immutable source commits,
SHA-256-verified wheels, and vendor dependency locks. Compatible new releases
are adopted automatically; a changed or incomplete report contract fails visibly.
There is no vendor fork or copied rule collection to synchronize.

The Skillz consumer polls hourly. A new toolchain fingerprint prompts a full
skill rescan, and a weekly refresh rechecks vulnerability data. A terminal report
is cached as **attempted, not passed**, avoiding repeated full scans every hour.
Manual runs always rescan. GitHub schedules are best effort: incorporation occurs
at the next run, not immediately when a vendor publishes. Unreleased upstream
branch edits are not installed.

## Repository guide

| Path | Purpose |
|---|---|
| [action.yml](action.yml) | Reusable action inputs, outputs, and runtime setup |
| [entrypoint.py](entrypoint.py) | Four-stage command interface: plan, resolve, install, scan |
| [skill_security/](skill_security/) | Inventory, staging, vendor resolution, report adapters, and process supervision |
| [tests/](tests/) | Contract tests and inert live-scanner smoke fixtures |
| [site/](site/) | Standalone Vite, React, TypeScript, and Tailwind public interface |
| [scripts/](scripts/) | Public evidence snapshot generation |
| [.github/workflows/verify.yml](.github/workflows/verify.yml) | Adapter verification and real-engine smoke checks |
| [Architecture](docs/ARCHITECTURE.md) | Scope rules, trust boundaries, action contract, and report flow |
| [Roadmap](docs/ROADMAP.md) | Web companion scope and follow-up opportunities |
| [Contributing](CONTRIBUTING.md) | Development and validation commands |
| [Security policy](SECURITY.md) | Private vulnerability reporting and operating boundaries |
| [Changelog](CHANGELOG.md) | Released changes and the project rename |
| [AGENTS.md](AGENTS.md) | Instructions for agents working in this repository |

## License and upstream attribution

Shield's integration code is [MIT licensed](LICENSE), copyright OKHP3. Cisco
Skill Scanner and NVIDIA SkillSpector are separate upstream projects, each under
its own Apache-2.0 license: [Cisco license](https://github.com/cisco-ai-defense/skill-scanner/blob/main/LICENSE)
and [NVIDIA license](https://github.com/NVIDIA/SkillSpector/blob/main/LICENSE).
Their dependencies retain their respective licenses. This repository does not
relicense upstream code or imply vendor endorsement.
