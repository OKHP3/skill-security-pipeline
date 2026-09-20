# Proposed web companion

Status: architecture recommendation, not an implemented or deployed website.

Give Skillz Shield its own Vite, TypeScript, and Tailwind SPA on GitHub Pages.
The site would explain the project and display published security evidence.
GitHub Actions would remain the scanner runtime. The static site would require
no service credentials in browser code.

## First useful release

- Explain the Forge and Shield relationship and the package-only scan boundary.
- Show the Shield action commit separately from each run's Cisco and NVIDIA
  versions, source commits, wheel hashes, and dependency-lock identities.
- Explain automatic stable vendor release adoption and the full-rescan schedule.
- Display scanned source revision, scan time, expected and completed package
  counts, findings by severity, and links to the corresponding GitHub run.
- Distinguish pass, review-required, incomplete, failed operation, skipped run,
  and stale or missing evidence. A skipped run must retain the previous scan's
  date and verdict rather than imply a new passing result.
- Provide installation examples and links to contribution and security policies.

## Evidence publication

An approved Actions publication step would produce a small, versioned public JSON
snapshot from trusted main-branch reports. It must validate the report schema,
retain provenance, and publish only explicitly public fields. Private packages,
raw scanner text, credentials, and unreviewed submitted content must not leak
into the site. GitHub artifacts expire, so the website needs its own intentional
snapshot publication contract rather than depending on temporary artifact URLs.

Keep website deployment independent of the scan verdict: incomplete coverage or
findings are results the site needs to show, not reasons to hide the latest state.

## Later, if needed

Interactive scan submission would require a separately designed authenticated
service or GitHub workflow integration with bounded untrusted input handling.
The initial public site can explain, report, and link to GitHub without adding
that service. Public evidence never certifies a skill safe or useful.
