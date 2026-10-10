# Changelog

## Unreleased

### Added
- **Hugging Face web demo** (`huggingface/space/`): paste code or upload files and get a scan report in the browser. Input is only scanned, never executed; file names are sanitised, sizes are capped, nothing is stored, and echoed text is escaped.
- **Benchmark dataset** for Hugging Face: one row per labelled case (365 rows) with ground truth and the scanner's result. Rows use placeholders instead of key-shaped strings or invisible characters.
- `.github/workflows/huggingface.yml` publishes both on every push to `main` once an `HF_TOKEN` secret is set (`docs/HUGGINGFACE.md`), and checks the benchmark first.
- CI tests the web app with the same Gradio version the Space runs.

## v0.3.0 (2026-10-10): accuracy benchmark

### Added
- **Accuracy benchmark** (`benchmark/`): 300+ hand-labelled lines across all five categories. Every rule has cases; per-rule precision and recall are published in `benchmark/RESULTS.md`. The test suite fails on any unexplained change.
- The v0.2.0 scanner graded on the same cases is kept in `benchmark/history/` for comparison: precision 88% → 94%, recall 85% → 94%, false alarms 23 → 12, misses 31 → 13.

### Fixed (bugs the benchmark found)
- Findings in MCP configs could point at the wrong line (`"/"` matched an earlier `@scope/package` line).
- `DEBUG = True` was reported on the blank line above it.
- A `#` comment containing `]` inside a `pyproject.toml` dependency list stopped parsing, hiding the remaining dependencies.
- Git dependencies pinned to a commit SHA were flagged by SUP005, whose own fix recommends exactly that.
- Java's `RSA/ECB/OAEP…` (a naming quirk; RSA has no ECB mode) was reported as ECB.
- Importing a crypto class counted as using it.
- Emoji built with zero-width joiners (e.g. "woman technologist") were flagged in agent rules files.
- `el.innerHTML = ""` (clearing an element) was flagged as XSS.
- Code rules no longer fire on lines that are entirely comments.
- `examples/make_demo_secrets.py` (since v0.1.0) and the new benchmark runner contained literal bidi control characters instead of escapes. They're now built with `chr()`, and a new test fails if any tracked file contains invisible characters.

### Improved coverage
- SQL: `"..." + name` concatenation with mixed quotes, SQLAlchemy `text(f"...")`, JS string concatenation in `query()`.
- TLS: `ssl.CERT_NONE`, `check_hostname = False`, `_create_unverified_context()`.
- JS: `setTimeout("code")`, `insertAdjacentHTML`, `cors()` with no options; Python: Flask-CORS `CORS(app)` default.
- Public-prefixed AI provider keys, e.g. an OpenAI key behind a `VITE_` prefix (VIBE035).
- Passwords in `https`, `git`, `ssh`, `ftp` and `smtp` URLs (SEC012, renamed "Password embedded in a connection URL").
- Type-annotated secrets: `webhook_secret: str = "..."` (SEC020).
- Go `des`/`rc4` ciphers; Java's bare `Cipher.getInstance("AES")`, which defaults to ECB.
- Agent CI triggers written as `on: [issue_comment, ...]`.

### Changed
- AGT012 only reports risky `Bash(...)` permissions that use a wildcard or a bare command name.

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
