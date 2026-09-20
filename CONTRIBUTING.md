# Contributing to Skillz Shield

Contributions should improve skill-package security evidence, draft acceptance,
coverage reporting, or the reliability of the Cisco and NVIDIA integrations.
Start with [README.md](README.md) and [Architecture](docs/ARCHITECTURE.md). Use
[private vulnerability reporting](SECURITY.md) for exploitable weaknesses.

## Local development

The orchestration code uses Python's standard library and Git. The supported
scanner runtime is Ubuntu x86_64 with Python 3.13 and uv; GitHub Actions prepares
that runtime. Contract tests do not require either scanner or a model API key.

From a checkout of this repository:

```sh
python -m unittest discover -s tests -v
git diff --check
```

On Windows, `py -3 -X utf8 -m unittest discover -s tests -v` is the equivalent
test command. Report environment-specific skips; the Ubuntu CI run provides the
supported runner result.

For a real-engine smoke check on a disposable Linux environment with Python
3.13 and uv available, choose a fresh state directory outside the checkout:

```sh
shield_state="$(mktemp -d)"
python entrypoint.py resolve --state "$shield_state"
python entrypoint.py install --state "$shield_state"
python tests/live_smoke.py --state "$shield_state"
```

Resolution and installation access official upstream sources and package
registries. An optional read-only `GH_TOKEN` can be supplied to resolution to
avoid anonymous GitHub API limits. Do not supply credentials to scanner
processes. The smoke check creates disposable Git fixtures and never executes
their instructions. Inspect `smoke-report.json` and `pins.json` in the state
directory; do not publish raw logs or downloaded environments.

The repository's verification workflow runs contracts for pull requests and
live-engine smoke checks for trusted same-repository changes, main pushes, and
manual runs. Fork pull requests do not run the live-engine job automatically.

## Changes worth testing

For the public website, work in `site/` with Node.js 24. Run `npm ci`,
`npm run typecheck`, and `npm run build`; use `npm run dev` for a local preview.
Follow the existing Forge typography and visual components while retaining
Shield's inverted dark palette. Check mobile layouts, keyboard access, copy
feedback, source links, and explicit missing or stale evidence states.

The Pages build is separate from scanner verification. Website-only changes do
not run the real scanner smoke suite or scan application code as a skill.

- Scope changes: prove that supporting-file edits select their package, unfinished
  drafts remain eligible, and application-only changes avoid scanner work.
- Adapter changes: cover real supported JSON contracts, malformed or missing
  evidence, failed analyzers, unexpected exclusions, and retained findings.
- Staging and runner changes: preserve byte identity, path safety, credential
  stripping, deadlines, output bounds, and sanitized evidence.
- Vendor changes: verify official source identity, wheel and lock hashes, exact
  installed versions, and a real-engine smoke result.

Keep fixtures synthetic and public-safe. Do not add private skills, credentials,
customer material, live exploit destinations, or executable malicious payloads.
Use a minimal regression test that demonstrates the changed behavior.

## Pull requests and releases

Describe the problem, resulting behavior, validation, and any changed trust or
coverage boundary. Update affected documentation and the Unreleased section of
[CHANGELOG.md](CHANGELOG.md). Do not weaken a check solely to suppress an upstream
compatibility failure: incomplete evidence needs a visible explanation and fix.

Maintainers publish releases from verified commits. Release tags stay immutable,
and consumers adopt control changes by updating their full commit pin. Compatible
stable vendor releases follow the separate automatic resolution path described
in the README. Contributions to this repository are made under its [MIT license](LICENSE).
