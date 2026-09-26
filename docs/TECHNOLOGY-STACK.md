# Technology inventory and update plan

Audit date: 2026-09-26. Baseline: `1a5cb2aa14c46506526e58fccb024772162d0cc9`,
verified against GitHub main. The checkout was clean before this work.

The [complete npm, runtime, scanner and Action comparison](technology/technology-versions.md)
includes every package/version pair in `site/package-lock.json`, including optional
platform binaries. Its [JSON companion](technology/technology-versions.json) retains
the source URL, observation time, scope and location for each entry. These are
source declarations and historical evidence, not an installed-software attestation.

## Primary technologies

| Technology | In-place declaration | Stable release checked | Adoption route |
|---|---|---|---|
| React / React DOM | 19.3.0 / 19.3.0 | 19.3.0 / 19.3.0 | Dependabot npm PR |
| TypeScript | 7.0.2 | 7.0.2 | Dependabot npm PR |
| Vite | 8.3.0 | 8.3.1 | Dependabot npm PR |
| Tailwind CSS / Vite adapter | 4.3.3 / 4.3.3 | 4.3.3 / 4.3.3 | Dependabot npm PR |
| React Vite plugin | 6.1.1 | 6.1.1 | Dependabot npm PR |
| Node type definitions | 26.6.1 | 26.6.3 | Review against Node 24 runtime APIs |
| React / React DOM types | 19.3.0 / 19.3.0 | 19.3.0 / 19.3.0 | Keep aligned with React |
| Node.js | CI 24.19.0; site minimum >=22.12.0; Replit major 20 | 26.10.0 stable; 24.21.0 latest LTS | Prefer reviewed LTS upgrades |
| npm | 11.17.0 bundled with CI Node; no independent pin | 12.1.0 | Upgrade with Node unless separately justified |
| Python | Scanner 3.13; Replit 3.12; other CI steps runner-provided | 3.14.7 | Compatibility review; scanner requires cp313 wheel |
| uv | 0.12.17 | 0.12.19 | Exact version change plus real-engine smoke |
| Cisco Skill Scanner | Historical 2.1.0 | 2.1.0 | Existing verified per-run resolver |
| NVIDIA SkillSpector | Historical 2.11.2 | 2.12.0 | Existing verified per-run resolver |

Release sources for each version are linked in the generated comparison. The npm
publisher's `latest` tag and GitHub's stable release endpoint are used; prerelease
versions are rejected. Newer is a review candidate, not proof of compatibility.

## Languages, formats, platform services and supporting tools

| Technology | Use / in-place version | Latest / update responsibility |
|---|---|---|
| JavaScript / ECMAScript | ES modules; TypeScript target and library ES2022, module ESNext; browser runtime | [ECMAScript 2026, edition 17](https://ecma-international.org/publications-and-standards/standards/ecma-262/). Compilation target is a browser compatibility choice, not an outdated package. |
| TSX / JSX | React JSX transform | Supplied by TypeScript and React tooling |
| HTML, CSS, SVG, DOM, Fetch, localStorage, Clipboard, matchMedia | Browser-native site markup, styles, icons and APIs; no separately pinned version | Living/module standards; validate supported browsers rather than inventing a single CSS or DOM version |
| JSON | Reports, evidence and configuration; npm lockfile schema 3; public evidence schema 1 | Repository schemas are contracts, not upstream packages |
| YAML | Composite Action, workflows and Dependabot schema 2 | GitHub's managed parser; no local PyYAML dependency |
| TOML / Nix configuration | `.replit`: python-3.12, nodejs-20, web; channel stable-25_05 | [NixOS 26.05](https://nixos.org/blog/announcements/2026/nixos-2605/) is upstream stable, not proof Replit supports an equivalent channel. [Replit configuration](https://docs.replit.com/references/project-setup/configuration) requires platform-specific selection. |
| Markdown / GitHub Flavored Markdown | Documentation and committed skill input | GitHub-managed rendering; no Markdown engine dependency |
| Git | Source-tree discovery/staging; CI runner-provided | [2.55.0 upstream](https://git-scm.com/); actual runner version must be recorded per run |
| Bash | Composite Action shell and workflow shell steps; runner-provided | [5.3 stable series](https://lists.nongnu.org/archive/html/bash-announce/2025-07/msg00000.html); distribution patch level is runner-managed |
| Ubuntu x86_64 | `ubuntu-latest` hosted runner | Floating image, not a version pin. Inspect each run's runner-image identity and [image manifests](https://github.com/actions/runner-images). |
| GitHub Actions / Pages / REST API / Dependabot | CI, publishing, evidence retrieval and dependency PRs | Managed services; pinned Action implementations listed in generated comparison |
| Google Fonts | Alfa Slab One, DM Sans, JetBrains Mono via Google Fonts CSS API | Hosted mutable fonts without recorded font revision; no supported numeric version pin in the current integration |
| OSV | NVIDIA vulnerability lookup; network evidence | Live vulnerability data service; existing weekly recheck policy, not a package version |
| unittest, node:test, node:assert | Dependency-free Python and Node tests | Version follows Python / Node respectively |
| Python standard library | Orchestration, subprocess supervision, hashing, HTTP, archives and concurrency | Version follows Python; no root pip requirements or project dependency manifest |
| Vendor Python environments | Vendor-owned `uv.lock`, project metadata and wheels, verified by hashes | Resolved outside checkout. Transitive installed versions are unknown without that run's environment; do not independently upgrade vendor lock entries. |
| Native build tooling | esbuild, Rolldown, Lightning CSS, Tailwind Oxide and platform packages where present in npm lock | Each exact locked entry and latest release is in the generated comparison; optional entries need not be installed on every platform |
| Mermaid | No source use, dependency, renderer, or configuration found | Not employed; no installed version to update |

No application database, server-side web framework, Docker build, Playwright,
Vitest, ESLint or Prettier dependency is declared in this repository. External
skill catalog links are references, not imported runtime dependencies. IDEs,
browsers and desktop apps named in the request are inspection tools rather than
dependencies of the delivered Action or site.

## Evidence boundaries

Local tools observed: Python **3.14.0rc1**, Node **24.11.1**, npm **11.6.2**,
Git for Windows **2.55.0.windows.5**. These differ from CI and are not proof of
production versions. In particular the local Python is a release candidate.
Replit connector authentication failed; committed declarations are verified but
the live Replit runtime, Nix revision and npm version remain unknown.

The committed site fallback records a **2026-09-20** incomplete scan. Its scanner
versions and control pin are historical and must not be rewritten to appear
current. The resolver independently selects official stable releases on actual
scan runs, records immutable commits and digests, and fails on missing compatible
artifacts. Version freshness does not establish scanner completeness or safety.

The inventory covers first-party code, all locally locked npm entries and the
declared vendor boundary. It cannot enumerate an unobserved runner image or
unretained vendor environment. For an installed SBOM, retain sanitized package
names/versions from each verified environment alongside that run's pins, without
uploading raw scanner output, package content, credentials or environment dumps.

## Update procedure

1. **Detect weekly.** `technology-freshness.yml` compares public release metadata
   without installing packages, building the site or running scanners. Manual
   dispatch is also supported. It writes Markdown to the job summary and JSON/
   Markdown artifacts outside the checkout. Exit 1 means review candidates;
   exit 2 means lookup evidence is incomplete. It is an advisory scheduled audit,
   not a required merge gate. Floating declarations and historical observations
   may keep it red until reviewed; this is not a scanner verdict. GitHub Actions
   notification preferences determine who receives failure notifications.
2. **Propose npm and Actions changes.** Existing weekly Dependabot configuration
   opens reviewable PRs, grouping minor/patch npm changes; majors remain separate.
   Dependabot preserves lockfile maintenance and pinned Action SHA updates.
   Consult [GitHub's options reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference).
   It does not cover arbitrary runtime literals, Replit channels or vendor locks.
3. **Handle runtime candidates.** Open a focused `codex/` branch for the Node LTS
   pin in `site.yml`, Replit's available Node module, and contributor instructions.
   Confirm Replit's supported module before changing it; Node 20 is below this
   site's declared minimum. Keep npm paired with the selected Node release.
   Align `@types/node` with runtime-supported APIs rather than blindly adopting
   the newest types major. For Python, keep 3.13 until Cisco provides an accepted
   wheel and the integration is intentionally adapted and tested. A 3.14 upgrade
   requires more than changing `python-version`. Update uv separately with smoke
   validation. Floating Python patches are supplied by setup-python.
4. **Validate the affected surface.** Site dependency PRs run `npm ci`, typecheck,
   Node tests and build, followed by responsive, keyboard, copy-control and missing
   evidence checks. Scanner/tool-install changes run the complete contract suite
   and Linux real-engine job after resolve/install. Keep synthetic smoke results
   separate from actual inventory findings. Do not expand consumer discovery or
   scanner CI triggers to include the SPA or this audit.
5. **Release reviewed changes.** Merge only with applicable checks satisfied,
   publish a new immutable Shield release for control changes, then coordinate
   exact consumer commit pins and any Actions allowlist. Never move old tags.
   Site-only changes publish via the existing site workflow. Dependency PRs do
   not automatically merge. For hosted services and standards, review quarterly
   and after provider notices rather than manufacturing package versions.
6. **Verify adoption.** Regenerate the snapshot after changes, inspect CI and
   deployed evidence separately, and verify Replit from its live shell once its
   connection is restored. Compatible scanner releases already use per-run
   immutable resolution; do not patch historical evidence to simulate adoption.

Run the audit with Python 3 on Windows:

```powershell
py -3 -X utf8 scripts/check_technology_versions.py --output-dir docs/technology
```

Use `--check` to return a nonzero status for review candidates. A metadata failure
always returns 2. Run offline checker tests with
`py -3 -X utf8 -m unittest discover -s scripts/tests -v`.

Activation requires merging the workflow onto the default branch. This audit
does not grant itself write permissions, merge updates or modify other repositories.
