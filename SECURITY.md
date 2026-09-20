# Security policy

## Report a vulnerability privately

Use [GitHub private vulnerability reporting for Skillz Shield](https://github.com/OKHP3/skillz-shield/security/advisories/new)
for vulnerabilities in package staging, vendor verification, report handling,
workflow permissions, or other Shield trust boundaries. Include the affected
commit, a minimal synthetic reproduction, expected and observed behavior, and
the potential impact. Do not include credentials or private skill content.

Do not post a working exploit or sensitive report in a public issue. Ordinary
integration bugs and sanitized false-positive questions can use
[Issues](https://github.com/OKHP3/skillz-shield/issues). When a defect belongs to
an upstream scanner, follow that project's security policy and identify the
exact scanner version recorded in `pins.json`.

## Supported code and fixes

Fixes target the current main branch and latest published Shield release.
Consumers should adopt the latest compatible released control commit after
reviewing its changes. Older SHA pins remain reproducible references but do not
automatically receive Shield code fixes. Scanner releases are resolved separately
at run time; this does not update the consumer's Shield pin.

## Operating boundaries

Use disposable Ubuntu x86_64 GitHub-hosted runners, read-only repository
permissions, no scan secrets, and state outside the source checkout. Do not use
`pull_request_target` to execute untrusted contribution code. A scanner parses
untrusted input and is itself part of the trusted toolchain; process limits and
credential stripping do not make the runner a hermetic sandbox.

Shield does not execute submitted package code or call a model service. NVIDIA
dependency checks may query OSV; downloads and those checks require network
access. Sanitized evidence contains repository/package identities, digests, rule
IDs, severities, and coverage, so apply the appropriate artifact access and
retention policy for the consuming repository.

A `pass` means the requested static checks completed without high or critical
findings. False negatives and false positives remain possible. Incomplete
coverage is never a passing result. See [Architecture](docs/ARCHITECTURE.md) for
the evidence contract and [README.md](README.md) for result interpretation.
