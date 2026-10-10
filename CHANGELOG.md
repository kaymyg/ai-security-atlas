# Changelog

## v0.2.0 (2026-10-10): hardening release

Driven by an external repository audit. Accuracy and safety before new features.

### Breaking changes
- **Action:** the `extra-args` input is removed. Accepting a raw string of arguments allowed word-splitting and glob surprises. Use the new explicit `only` and `exclude` inputs instead.
- **Crypto results:** RSA/ECDH/X25519/ECDSA/Ed25519 usage (PQC010–014) is now **inventory** at low/info severity instead of medium/low findings. These algorithms are safe today; they're listed for post-quantum planning and never fail a build.

### Security
- All GitHub Actions used by the Action and CI are pinned to full commit SHAs with version comments; Dependabot keeps them current.
- Action inputs are validated and passed as separate arguments (no shell interpolation). Tested with injection attempts.
- SARIF upload is skipped automatically on pull requests from forks.
- A scanner that crashes on a file no longer stops the scan, and the error report never includes file content.

### Added
- Every rule has a **kind**: `vulnerability`, `misconfiguration` or `inventory`, shown in every report format.
- **Suppression audit:** reports list silenced findings, `ignore-file` files and what each ignore pattern excluded. SARIF keeps silenced findings marked as suppressed. Excluding every file is an error (exit 2); broad patterns trigger a warning.
- **Unknown vs missing packages:** registry timeouts/rate limits are reported as "could not be checked" (SUP008), never as missing. One retry on 429/5xx; stops after three failures in a row.
- SUP007 now flags *every* Action not pinned to a SHA (official ones included) and also checks composite `action.yml` files.
- `docs/KNOWN_LIMITATIONS.md`: coverage by language and format, blind spots, appropriate use.
- Threat map: every claim cites a numbered source with type, publication date, what was verified and when.
- 19 new tests (67 total), including masking in every output format.

### Fixed
- `**/name` ignore patterns now match at the top level too.
- SUP003 (recently published package) lowered to low severity: new isn't the same as malicious.

## v0.1.0 (2026-10-10)

First release: scanner with 73 rules across five categories, text/JSON/SARIF/Markdown reports, GitHub Action, demo app and threat map.
