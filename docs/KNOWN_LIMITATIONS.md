# Known limitations

What `atlas` can and can't see, so you can decide how much to rely on it. Short version: **it's a fast, lightweight first layer for selected AI-era risks. It complements full static analysis (SAST), secret scanning with history, penetration testing, runtime agent controls, enterprise DLP and deepfake detection. It doesn't replace any of them.**

## How the scanner works (and why that limits it)

Every rule is a readable pattern match on one file at a time, plus JSON parsing for config files. That makes it fast, dependency-free and easy to audit, but it means:

- **No data-flow analysis.** It sees `cursor.execute(f"... {uid}")` but can't tell whether `uid` came from a user or a constant. It will miss injection that passes through helper functions, ORMs or other files.
- **No context.** A safe `eval` on a hard-coded constant inside a test may still be flagged; an unsafe one written in an unusual style may be missed.
- **A clean scan proves nothing.** It means none of these patterns matched, not that the code is secure.

There's no benchmark yet: per-rule accuracy hasn't been measured. Building a labelled test corpus is the next milestone (see [README roadmap](../README.md#roadmap)).

## Coverage by language and file type

### Insecure code patterns (`VIBE*`)

| Language / files | Rules |
|---|---|
| Python (`.py`) | VIBE001–003, VIBE010–019, VIBE050–054 |
| JavaScript / TypeScript (`.js .jsx .ts .tsx .mjs .cjs .vue .svelte`) | VIBE001–003, VIBE030–033, VIBE050–054 |
| HTML | VIBE031 only |
| Go, Java, Kotlin, C#, Ruby, PHP, Rust | **VIBE054 (security TODOs) only**: no injection, deserialisation or TLS rules yet |
| Any text file | VIBE034 (Node TLS off), VIBE035 (public-prefixed secret env vars) |
| Terraform, Kubernetes, Dockerfiles | not covered |

### Secrets (`SEC*`)

- **Scans current files only, not git history.** A key deleted in an earlier commit is still in history. Use a history-aware scanner (or GitHub's secret scanning) for that.
- **Recognised formats:** AWS access key IDs, GitHub, Anthropic, OpenAI, Google API, Stripe live, Slack and Hugging Face tokens, JWTs, database URLs with passwords, PEM private-key headers, and `0x`-prefixed 64-hex wallet keys assigned to key-like names. Anything else is only caught by the generic high-entropy assignment rule (SEC020), which needs a key-like variable name.
- **Not detected:** base64- or URL-encoded secrets, secrets split across lines or string concatenation, passwords that aren't assigned to an obviously named variable, low-entropy (guessable) passwords.
- **No live validation, by design.** Checking whether a key works means sending it to the provider. A scanner that transmits every secret it finds is a risk of its own, so `atlas` never does.
- Reports always mask secrets (first 4 characters + `…******`), in every output format, including suppressed findings and error messages. Tests enforce this.

### AI agents and MCP (`AGT*`)

Supported formats:

| Tool | Files read |
|---|---|
| MCP (any client) | Any `.json` with `mcpServers`, `servers` or `mcp.servers` (incl. `.mcp.json`, `claude_desktop_config.json`, `.vscode/mcp.json`, `.cursor/mcp.json`); JSONC comments tolerated |
| Claude Code | `.claude/settings*.json` permissions, `defaultMode`, `enableAllProjectMcpServers` |
| VS Code | `chat.tools.autoApprove` |
| OpenAI Codex CLI | `.codex/config.toml` (`approval_policy`, `sandbox_mode`) |
| CLI flags in scripts/CI | `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo`, `--permission-mode bypassPermissions` |
| GitHub Actions | Known agent actions/CLIs triggered by issue/PR comment events without an author check |
| Rules files | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `copilot-instructions.md`, `.cursor/rules/*`, `.github/instructions/*`, `.claude/agents|commands/*` |

**Not covered:** YAML-based MCP configs, Cursor/Windsurf/Gemini permission settings, agent settings stored outside the repo (user home folder), and anything about what an agent actually does at run time. A risky setting shows potential exposure, not that an agent has misbehaved, and a clean result doesn't prove an agent's effective permissions are safe.

Config formats change often. Rules match the formats as of October 2026.

### Hidden Unicode (`UNI*`)

- Tag characters (UNI001) and bidi controls (UNI002) are flagged in every text file.
- Zero-width characters (UNI003) are only flagged in code, config and agent rules files, because they have legitimate uses in normal text (e.g. emoji sequences and some scripts).
- Ordinary Arabic or Hebrew text doesn't trigger UNI002, but localisation strings that deliberately use bidi control characters do. Review them, then silence with `atlas: ignore[UNI002]`.

### Dependencies (`SUP*`)

- **Manifests read:** `requirements*.txt`/`.in`, `constraints.txt`, `pyproject.toml` (PEP 621 and Poetry), `package.json`.
- **Not read:** lock files, `Pipfile`, `setup.py`/`setup.cfg`, `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json`, Maven/Gradle files. Transitive dependencies aren't checked.
- **Typosquats (SUP001)** compare names against about 140 popular packages per ecosystem using edit distance. A legitimate package with a similar name can be flagged; typos of less popular packages are missed.
- **Online checks (`--online`)** query PyPI and npm only. A missing package (SUP002) is reported only on a definite "not found". Timeouts, rate limits and outages are reported as **unknown** (SUP008), never as missing, and after three failures in a row the scanner stops asking. A recently published package (SUP003) is a prompt to check the publisher, not evidence of malice.
- **No known-vulnerability (CVE) lookups yet.** Use `pip-audit`, `npm audit` or OSV-Scanner for that.

### Cryptography (`PQC*`)

- Results come in two kinds. **PQC001–005** (MD5/SHA-1, DES/RC4, ECB, short RSA keys, old TLS) are weaknesses today. **PQC010–014** (RSA, ECDH, X25519, ECDSA, Ed25519, secp256k1) are **inventory**: standard algorithms that are safe against current attackers, listed to plan a post-quantum migration. Inventory never fails a build.
- Only crypto visible in source and config files is found. Not found: crypto inside compiled dependencies, TLS settings on load balancers or cloud services, certificates issued elsewhere, or libraries the patterns don't know.
- Usage patterns cover Python (`cryptography`, PyCryptodome, `hashlib`, `ssl`), JS/TS (Node `crypto`, Web Crypto names, ethers/viem), Go (`crypto/*`), Java/Kotlin (JCA names), Ruby `Digest`, and nginx-style `ssl_protocols`.

## Silencing findings, and how it's audited

| Mechanism | Scope | How it's reported |
|---|---|---|
| `# atlas: ignore` / `ignore[ID]` | one line | listed by rule and line in text/JSON; kept in SARIF marked `suppressed` |
| `# atlas: ignore-file` | one file | file names listed in every report |
| `.atlasignore` / `--exclude` | paths | each pattern listed with the number of files it excluded |

Patterns that exclude more than half the files trigger a warning. Patterns that exclude *every* file make the scan exit with an error (code 2) instead of reporting a clean pass. Treat changes to `.atlasignore` and ignore comments like code changes in review.

## Appropriate use

Good fits: a quick first pass on AI-assisted code, a pre-commit or CI check for obvious mistakes, a crypto inventory to start post-quantum planning, a review of agent and MCP configs before sharing a repo.

Not appropriate as: the only security gate for production systems, a compliance certification, proof that a repo contains no secrets, or a substitute for runtime controls on what agents can do.
