# Skill security pipeline

External GitHub Actions integration for Cisco Skill Scanner and NVIDIA SkillSpector.
Consumers pin this action to a full Git commit. Official stable vendor releases
are resolved at run time to source commits, SHA-256-verified wheels, and exact
vendor dependency locks. A newer compatible release is used automatically.
Changed JSON contracts, missing analyzers, unavailable releases, and broken
installs produce incomplete evidence; they never become a passing scan.

## Scope

Only committed skill packages are scanned. Root families declare `FAMILY.md`;
their package folders can contain unfinished drafts without `SKILL.md`.
Project support and export skills are also included. Application files, archives,
family administration, and migration locators are outside the scan inventory.
Supporting-file changes select their owning package. Removed packages require
no scan. Submitted code, installers, dependencies, and instructions are never run.

The `plan` mode uses Python and Git only. Call `resolve`, `install`, and `scan`
only when `plan` returns `scan: true`. Use `full: true` for a scheduled rescan.
State must be outside the repository checkout. Run on disposable Ubuntu x86_64
GitHub-hosted runners with read-only permissions and no secrets.

## Evidence and decisions

Both engines use static security analysis, without LLM credentials or skill
quality/maturity evaluation. Cisco uses lenient loading and strict security
policy, excluding four explicitly listed metadata-quality warnings. A missing
`SKILL.md` receives a temporary scanner compatibility wrapper; original files
remain byte-for-byte intact. This adaptation is recorded in the report.

High/critical security findings require review. Missing or incomplete analysis
fails separately. Other findings remain visible without blocking. Reports carry
the source commit, per-package content digest, both engine identities, rule IDs,
severities and coverage. They omit raw snippets, diagnostics and credentials.
No result certifies a skill safe, useful, mature, or production-ready.

NVIDIA's dependency analyzer may query OSV. No model service is used. Its static
analysis coverage and limitations are retained. GitHub-hosted processes are
credential-stripped and time-bounded, not a claim of a hermetic security sandbox.

## Updates

The consumer checks current stable releases on every actual scan and polls
hourly for new release fingerprints. An updated engine, rules, policy or locked
dependency set causes a full scan of current skills. Weekly refreshes also
recheck evolving vulnerability data. GitHub schedules are best effort, so this
is automatic incorporation at the next run, not an instantaneous vendor webhook.

The control code remains SHA-pinned and reviewable. Adapter changes are reviewed
separately from vendor releases. No vendor fork or copied detection-rule set is
maintained. Upstream unreleased main-branch edits are intentionally not installed.

## Development

`python -m unittest discover -s tests -v` exercises scoping, Git staging, report
contracts and process supervision without vendor installs. The CI smoke suite
also installs the exact resolved engines and scans synthetic draft/detection
fixtures. This repository's code is MIT; both engines remain Apache-2.0 under
their own licenses.

Sources: [Cisco Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner),
[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector).
