# Skillz Shield roadmap

## Initial web companion

The Vite, React, TypeScript, and Tailwind SPA gives Shield its own public interface
on GitHub Pages. It reuses Forge's typography, spacing, square-edged components,
and copper accents with the paper and espresso color roles inverted.

The site explains package-only scanning, shows verified aggregate evidence and
scanner identities, and provides an immutable Action installation example.
GitHub Actions remains the scanner runtime. The browser contains no scanner
credentials and does not accept or execute submitted skills.

Evidence publication retains the original scan date, source revision, coverage,
findings, and toolchain identities. Missing or expired artifacts, failed refreshes,
and incomplete reports remain visible. Website deployment is independent of the
scan verdict so findings are published rather than hidden by a failed scan job.

## Follow-up opportunities

- Investigate the recorded incomplete coverage and findings in the Skillz
  inventory. Neither scanner integration tests nor the website establish that
  the library has a clean security result.
- Retain more allowlisted NVIDIA analyzer reason codes and ledger-exception
  counts so full file coverage can be distinguished from completed analysis.
  Investigate representative packages before changing any completeness rule.
- Add a public, reviewed package-level triage view if aggregate results prove
  insufficient. Define redaction and disclosure rules before publishing detail.
- Support other repository layouts through an explicit discovery contract.
  Today the inventory follows the Skillz family and support-package conventions.
- Consider authenticated scan submission only as a separate, bounded service or
  GitHub workflow integration. The static public site needs no backend to explain,
  display evidence, and direct maintainers to GitHub.

Public evidence describes the checks performed at a recorded revision. It never
certifies a skill safe or useful.
