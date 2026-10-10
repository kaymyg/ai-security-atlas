# Threat map

Five security problems that grew out of everyday AI use, what the established standards say about each, and what this repo's scanner can check.

**How sources are handled here.** "Evidence-driven" means a claim needs a source you can check. Standards, CVEs and CWEs below are well-established. The vendor products named in the research that started this project are listed separately under [Leads to verify](#leads-to-verify): they haven't been checked yet and shouldn't be treated as fact until they are.

| # | Problem | Scanner coverage |
|---|---|---|
| 1 | AI-generated code security debt | ✅ `VIBE*` |
| 2 | Data spillage into AI tools | ◐ `SEC*` (in code only) |
| 3 | Agentic AI, non-human identities, trust | ✅ `AGT*`, `UNI*` |
| 4 | Synthetic identity and deepfakes | ✗ out of scope for code scanning |
| 5 | Harvest now, decrypt later + AI supply chain | ✅ `PQC*`, `SUP*` |

---

## 1. AI-generated code security debt

**The problem.** Code written quickly with AI assistants ("vibe coding") ships with the same classic flaws as rushed human code (injection, disabled checks, secrets in source) plus new ones: model output executed directly, and user input mixed into system prompts.

**Established references**
- OWASP Top 10 for LLM Applications: prompt injection (LLM01) and improper output handling are the two that show up in code.
- Classic weaknesses still dominate: CWE-89 (SQL injection), CWE-78 (OS command injection), CWE-94/95 (code injection), CWE-295 (bad certificate validation), CWE-79 (XSS).

**Defensive pattern.** Keep a human review step before merge; run static checks in CI; never execute model output directly; give the model a fixed set of allowed actions instead.

**Scanner:** `VIBE001`–`VIBE054`.

## 2. Data spillage into AI tools

**The problem.** People paste code, logs and documents into chat assistants. Any secret in that material leaves the organisation. The root cause sits partly in code (secrets in source files) and partly in behaviour (what people paste).

**Established references**
- CWE-798 (hard-coded credentials), CWE-200 (exposure of sensitive information).
- Git hosting platforms run their own secret scanning and push protection; use them.

**Defensive pattern.** Get secrets out of source and into a secret manager, so there's nothing to paste. At the human end, browser-level data-loss controls warn before sensitive text reaches an AI tool.

**Scanner:** `SEC*` covers the code side. The browser side is on the [roadmap](../README.md#roadmap).

## 3. Agentic AI, non-human identities and trust

**The problem.** AI agents act with real credentials: they read files, run commands and call APIs. An over-permissioned agent turns any prompt injection into real damage. In a repository, an agent's identity is its configuration: MCP server definitions, permission allow-lists, approval settings, and instruction files.

**Established references**
- Model Context Protocol (MCP): the open protocol most coding agents use to reach tools.
- Least privilege (CWE-250 when violated) and missing authorisation (CWE-862) apply to agents as much as to people.
- MITRE ATLAS catalogues attack techniques against AI systems.
- "Trojan Source" (CVE-2021-42574): bidirectional Unicode that makes code display differently from how it runs. Invisible Unicode tag characters extend the same trick to text an AI reads.

**Defensive pattern.** Least agency (give each agent only the tools and folders it needs), keep humans approving risky actions, pin tool versions, keep tokens out of config files, and review changes to agent instruction files like code.

**Scanner:** `AGT001`–`AGT030`, `UNI001`–`UNI004`.

## 4. Synthetic identity and deepfakes

**The problem.** Cloned voices and real-time video fakes are used for fraud and fake job candidates. Single-factor face or voice checks are no longer enough on their own.

**Why it's not in the scanner.** It's about people and media, not source code. There's nothing in a repo to scan.

**Defensive pattern.** Out-of-band confirmation for high-risk requests (call back on a known number), multi-factor identity checks in hiring and payments, and liveness detection where biometric checks are used.

## 5. Harvest now, decrypt later + AI supply chain

**The problem (quantum).** Encrypted traffic recorded today can be decrypted later once a large quantum computer exists. Key exchange and public-key encryption (RSA, ECDH, DH, X25519) are the urgent part; signatures need a plan for long-lived keys.

**Established references**
- NIST post-quantum standards, finalised August 2024: FIPS 203 (ML-KEM, key encapsulation), FIPS 204 (ML-DSA, signatures), FIPS 205 (SLH-DSA, hash-based signatures).
- Hybrid key exchange such as X25519MLKEM768 is being deployed in TLS 1.3.
- Every migration framework starts with a cryptographic inventory: you can't migrate what you haven't found.

**The problem (supply chain).** AI assistants sometimes invent package names. Attackers register those names ("slopsquatting") just as they register misspellings of popular packages (typosquatting). Example from this repo's testing: `expresss` and `lodahs` both exist on npm today.

**Established references:** CWE-1357 (reliance on insufficiently trustworthy component), CWE-494 (download without integrity check), CWE-829 (untrusted functionality, e.g. unpinned GitHub Actions).

**Scanner:** `PQC000` (inventory) through `PQC014`, and `SUP001`–`SUP007`.

---

## Leads to verify

These came from the research that started this project. Each needs a primary source (vendor page, paper, standards body) before it moves into the sections above. Contributions that confirm or rule out any of them are welcome.

| Area | Lead | Status |
|---|---|---|
| 1 | Palo Alto Networks "SHIELD" framework for vibe-coded apps | unverified |
| 1 | Scanners named hackmenot, GuardVibe, vibe-shield, VibeScan | unverified |
| 2 | AI-focused DLP products from MIND, Cyera, Sentra, Netskope, Forcepoint, Palo Alto Cortex | unverified |
| 3 | IETF "Agent Identity Protocol" draft; CSA "Agent Identity Governance Framework" | unverified |
| 3 | Symmetry AIGuard, SailPoint agent identity products | unverified |
| 4 | Deepfake detection from Sumsub, iProov, Sensity; Deel's acquisition of Clarity | unverified |
| 5 | "Q-Ready" framework, PQC Planner, Crypto-Agility Readiness Score (CARS) | unverified |
| 5 | SBOM2TD agent | unverified |

To verify one: add a link to a primary source in a pull request, move the entry into the relevant section, and mark it `verified (date)`.
