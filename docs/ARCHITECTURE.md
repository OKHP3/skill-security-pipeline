# Skillz Shield architecture

Skillz Shield separates a pinned control layer from automatically resolved
scanner releases. The consuming repository owns its triggers and merge policy;
Shield owns package selection, vendor verification, bounded scanning, and
normalized evidence. It does not run the consuming application or publish its
GitHub Pages site. Shield's own static web interface is a separate Vite, React,
TypeScript, and Tailwind build under `site/`.

## Public website and evidence

The website reads a versioned public JSON snapshot rather than accessing Actions
artifacts with browser credentials. `scripts/build_site_evidence.py` finds
completed runs of the Skillz security workflow from the same repository's main
branch, checks artifact identity and hashes, verifies source and coverage
consistency, and publishes only allowlisted aggregate fields. Raw package text,
scanner messages, and individual finding snippets are not website inputs.

The snapshot separates three identities: the latest Shield release, the current
consumer Action pin, and the control and vendor pins used by the historical
full scan. It retains the scan's source revision and date. An unavailable refresh
keeps retained evidence explicitly stale, or shows unavailable if no valid
snapshot exists. A plan-only or cache-skipped run is not a new passing scan.

The Pages workflow builds and validates the SPA independently of the scanner's
verdict. Website-only edits do not run scanner verification. The consumer's
package-only workflow still skips application code.

## Four stages

| Mode | Reads | Writes in the external state directory | Action outputs |
|---|---|---|---|
| `plan` | Committed base/head Git trees | `plan.json` | `scan`, `packages` |
| `resolve` | Official stable vendor releases and their manifests | `pins.json` | `fingerprint`, `week` |
| `install` | Verified pins and vendor dependency locks | Isolated vendor environments, `installed.json` | None |
| `scan` | Plan, pins, installed engines, selected committed packages | `report.json` and a GitHub step summary | `complete`, `decision` |

Call the modes in that order with the same state directory. Skip the latter
three when `plan.outputs.scan` is `false`. The plan records the resolved source
commit; scanning uses that immutable commit rather than changed working files.

| Input | Contract |
|---|---|
| `mode` | Required: `plan`, `resolve`, `install`, or `scan` |
| `root` | Checked-out skill repository; defaults to `.` |
| `state` | Required dedicated directory outside the source checkout |
| `base` | Commit used to select changed packages; an empty or all-zero base selects a full inventory |
| `head` | Commit to inspect; defaults to `HEAD` |
| `full` | Set to the string `true` to select every current skill package |

The input contract is defined in [action.yml](../action.yml). `scan` returns a
nonzero exit for `review-required` or `incomplete`; earlier operational failures
can stop the workflow before a report exists.

## Package selection

Discovery reads Git trees without executing package content. A root family
declares `FAMILY.md`; its direct child directories are package candidates even
when their metadata is unfinished. Reserved application roots do not become
families merely by receiving a `FAMILY.md` file.

Markerless family support directories, such as `references/`, `reviews/`,
`archive/`, and `tests/`, are excluded. A direct `SKILL.md` makes such a directory
a package. Two existing Skillz context workspaces and recognized README-only
migration locators are excluded explicitly. [discovery.py](../skill_security/discovery.py)
is the authoritative list and its tests preserve these boundaries.

Under `.agents/skills/` and `skills/`, a `SKILL.md` marker identifies a package.
The outermost package owns nested example and fixture markers, so they are not
counted as independent skills. A supporting-file edit selects the owning package.
A rename selects the new package and records the old identity as deleted.
Deleted-only changes do not run either scanner.

This layout is designed around the Skillz catalog. A repository using a different
layout needs a reviewed discovery change; arbitrary directories are not silently
treated as skills. Uncommitted and untracked files are never part of scan input.

## Staging and scanner execution

Selected packages must use portable regular-file paths. Symlinks, submodules,
unsafe paths, oversized files, and packages exceeding resource limits cannot
produce a passing scan. Current staging limits are 10 MiB per file, 64 MiB per
package, and 2,048 files. The code also bounds path size and depth.

The stager copies committed blob bytes into a temporary directory and hashes the
original paths, modes, and content. If `SKILL.md` is absent, it adds a small
compatibility wrapper to this temporary copy and records `metadata_generated`.
The original draft files remain intact and available to both engines.

Cisco runs with lenient metadata loading and strict security policy. Only four
explicit metadata-quality warnings are filtered: invalid name, overly long
description, vague description, and missing license. The exact rule identifiers
live in [cisco.py](../skill_security/cisco.py); security findings are retained.

NVIDIA runs with `--no-llm` and `--fail-on-incomplete`. Optional model analyzers
can be disabled; required static analyzers and coverage evidence must remain
present. Declared exclusions, unsupported report contracts, failed or partial
analysis, and operational gaps remain incomplete evidence.

NVIDIA evidence includes fixed incomplete-reason codes, ledger exception/fatal
counts, allowlisted ledger reasons, and up to 64 analyzer summaries with validated
counters. Unknown vendor names, statuses, and reasons become `unknown`; paths,
messages and snippets are never copied. Diagnostic fields do not relax any gate.

The supervisor uses a restricted environment, temporary homes, a 180-second
per-engine process timeout, a 16 MiB report limit, and at most four concurrent
package workers by default. It does not execute skill code. Installed scanner
code is trusted to parse untrusted input, so disposable runners and secret-free
execution remain necessary. NVIDIA dependency analysis may contact OSV.

## Vendor identity and change detection

Consumers pin the Shield action to a full commit SHA. Resolution selects official
stable semantic-version releases from Cisco and NVIDIA, records their source
commit, and verifies the published wheel plus `uv.lock` and `pyproject.toml`
digests. Installation uses the vendor lock and checks the installed distribution
version. Required artifacts or contracts that are unavailable cause a visible
failure instead of falling back to an unverified version.

The action's fingerprint combines vendor identities with a digest of the Shield
control code. It also emits an ISO week bucket. The Skillz consumer uses these to
detect vendor/control changes and refresh vulnerability data weekly. Its hourly
schedule reuses only a terminal full-scan attempt marker, never a cached passing
verdict. A manual run bypasses that scheduled-repeat optimization. See the
[consumer workflow](https://github.com/OKHP3/skillz/blob/main/.github/workflows/skill-security.yml)
for the scheduling and cache logic; these are caller responsibilities.

## Evidence and limits

`plan.json` records selected and removed package identities and inventory size.
`pins.json` records immutable vendor and control identities. `report.json` adds
the source commit, package digests, per-engine findings and coverage, and the
aggregate decision. Raw scanner reports and logs are temporary; only bounded
public rule IDs, normalized severities, safe error codes, and structured coverage
enter the report.

Both engines must complete every selected package for `complete: true`.
Incomplete evidence takes precedence over findings in the aggregate decision.
With complete evidence, high or critical findings produce `review-required`;
otherwise the decision is `pass`. Lower-severity findings remain visible.

This measures the requested static checks at one revision with one recorded
toolchain. It does not establish runtime behavior, exhaustive vulnerability
coverage, skill quality, or a safety certification. A smoke fixture that passes
validates a bounded integration case, not the complete Skillz inventory.
