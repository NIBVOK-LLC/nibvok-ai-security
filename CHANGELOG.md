# Changelog

All notable changes to **@nibvok-llc/nibvok-ai-security** are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/) and versions
use [Semantic Versioning](https://semver.org/).

## [0.1.2] — 2026-10-08

Documentation and honesty hardening. **No change to the runtime enforcement
path** — every allow / confirm / deny decision and the audit-chain format are
unchanged from 0.1.1.

### Changed

- **`LISTING.md` test-count wording** corrected to match the shipped suites
  ("363" → "300+"); the previous figure was stale against the actual test set.

### Documented

- **`INCIDENTS.md` #25** — a classifier that trusts *declared* features rather
  than *derived* ones (documented; not fixed, per owner).
- **`INCIDENTS.md` #26** — a wrapper that trusted a scalar (an exit code) over
  the finding the run printed; the same false-green class as #6 and #22, and the
  flip side of #25. Fixed: exit contract + wrapper mapping + briefing parser +
  controls, verified at source.

## [0.1.1] — 2026-10-05

Supply-chain and provenance hardening. **No change to the runtime enforcement
path** — every allow / confirm / deny decision and the audit-chain format are
unchanged from 0.1.0.

### Added

- **Build provenance publishing.** New `.github/workflows/package-publish.yml`
  publishes this package from GitHub Actions on a `v*` tag, using the ClawHub CLI
  and the runner's GitHub OIDC identity. Publishing from CI is what produces the
  build attestation that closes the listing's `hasProvenance: false` gap: it ties
  the published artifact to a verified builder and this tagged commit.
- **`CHANGELOG.md`** (this file) — the repo previously had none.

### Changed

- **Pinned `actions/checkout` to a commit SHA** (`11d5960a…`, `v4.4.0`) in
  `traffic-tracker.yml`, replacing the floating `@v4` tag. This closes the repo's
  own TODO and removes the last unpinned third-party action from the release
  pipeline of a security product.

### Security

- CI publishing authenticates with a **human-held repository secret**
  (`CLAWHUB_TOKEN`), never committed and never echoed to logs.

## [0.1.0] — 2026-09-21

### Added

- Initial release: runtime policy enforcement for OpenClaw agents — allow,
  confirm, or deny every tool call (classifier, audit chain, policies, hooks,
  and test suites).

[0.1.1]: https://github.com/NIBVOK-LLC/nibvok-ai-security/releases/tag/v0.1.1
[0.1.0]: https://github.com/NIBVOK-LLC/nibvok-ai-security/releases/tag/v0.1.0
