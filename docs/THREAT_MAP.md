# Threat map

Five security problems that grew out of everyday AI use, what established sources say about each, and which parts this repo's scanner can check.

## How sources work here

- Every factual claim points to an entry in [Sources](#sources) by number, like **[S3]**.
- Each source records its **type**, its **publication date**, **what was actually checked**, and **when**. "Verified" means the specific claim was read on the source itself, not just that a website exists.
- Vendor products and unconfirmed claims live in [Leads to verify](#leads-to-verify) until someone checks them against a primary source.

| # | Problem | Scanner coverage |
|---|---|---|
| 1 | AI-generated code security debt | ✅ `VIBE*` |
| 2 | Data spillage into AI tools | ◐ `SEC*`: secrets in files only, not what people paste |
| 3 | Agentic AI, non-human identities, trust | ✅ `AGT*`, `UNI*`: configuration, not runtime behaviour |
| 4 | Synthetic identity and deepfakes | ✗ not a code problem |
| 5 | Harvest now, decrypt later + AI supply chain | ✅ `PQC*` (inventory + weak crypto), `SUP*` |

What the scanner can and can't detect for each area is in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

---

## 1. AI-generated code security debt

**The problem.** Code written quickly with AI assistants ("vibe coding") ships with classic flaws (injection, disabled checks, secrets in source) plus newer ones: model output executed directly, and user input mixed into the instructions given to a model.

**What established sources say**
- OWASP's Top 10 for LLM Applications (2025) lists *Prompt Injection* as LLM01 and *Improper Output Handling* as LLM05. These are the two that show up directly in application code. **[S1]**
- The classic weaknesses are catalogued by CWE: SQL injection (CWE-89), OS command injection (CWE-78), code injection (CWE-94/95), improper certificate validation (CWE-295), cross-site scripting (CWE-79). **[S2]**

**Defensive pattern.** Human review before merge; static checks in CI; never execute model output directly; map model output onto a fixed list of allowed actions.

**Scanner:** `VIBE001`–`VIBE054`.

## 2. Data spillage into AI tools

**The problem.** People paste code, logs and documents into chat assistants. Any secret in that material leaves the organisation. Part of the cause is in code (secrets in source files); part is behaviour (what people paste).

**What established sources say:** hard-coded credentials are CWE-798 and exposure of sensitive information is CWE-200. **[S2]**

**Defensive pattern.** Move secrets out of source into a secret manager, so there's nothing to paste. At the human end, browser-level data-loss controls can warn before sensitive text reaches an AI tool.

**Scanner:** `SEC*` covers the code side only. It cannot see what anyone pastes into a website.

## 3. Agentic AI, non-human identities and trust

**The problem.** AI agents act with real credentials: they read files, run commands and call APIs. An over-permissioned agent turns a prompt injection into real damage. In a repository, an agent's identity is its configuration: MCP server definitions, permission allow-lists, approval settings and instruction files.

**What established sources say**
- The Model Context Protocol is an open standard for connecting AI applications to external data sources and tools. It's the main way coding agents reach tools, which is why MCP config files matter. **[S3]**
- MITRE ATLAS is a living knowledge base of adversary tactics and techniques against AI-enabled systems, modelled on MITRE ATT&CK. **[S4]**
- Unicode "tag" characters can hide instructions that people can't see but language models still read. **[S5]** This extends an older trick: bidirectional control characters that make source code display differently from how it runs, recorded as CVE-2021-42574 (marked *disputed* by NVD, since it describes Unicode behaviour rather than one product's bug). **[S6]**
- Least privilege (CWE-250 when violated) and missing authorisation (CWE-862) apply to agents as much as to people. **[S2]**

**Defensive pattern.** Least agency (each agent gets only the tools and folders it needs), humans approve risky actions, pinned tool versions, no tokens in config files, and changes to agent instruction files reviewed like code.

**Scanner:** `AGT001`–`AGT030`, `UNI001`–`UNI004`. It checks configuration files, not what an agent actually does at run time.

## 4. Synthetic identity and deepfakes

**The problem.** Cloned voices and real-time video fakes are used for fraud and fake job candidates.

**Why it's not in the scanner.** It's about people and media, not source code; there's nothing in a repository to scan.

**Defensive pattern.** Confirm high-risk requests out of band (call back on a known number), use more than one identity check in hiring and payments, and use liveness detection where biometric checks are used.

*No sources yet beyond vendor leads. Contributions with primary sources are welcome.*

## 5. Harvest now, decrypt later + AI supply chain

**The quantum problem.** Encrypted traffic recorded today could be decrypted later once a large enough quantum computer exists. Key exchange and public-key encryption (RSA, ECDH, DH, X25519) are the urgent part. Signatures need a plan for long-lived keys.

**What established sources say**
- NIST published its first three finalised post-quantum standards on 13 August 2024: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA). **[S7]**
- Hybrid key agreement for TLS 1.3, including X25519MLKEM768, is now a published IETF standard: RFC 10024 (Proposed Standard, August 2026). **[S8]**

**Important distinction.** Using RSA or X25519 today is *not* a vulnerability: these are standard and secure against current attackers. The scanner reports them as **inventory** (the discovery step of a migration plan), separately from crypto that is broken today, like MD5 or DES.

**The supply-chain problem.** Code-generating models sometimes recommend packages that don't exist. Attackers can register those names ("slopsquatting"), just as they register misspellings of popular packages (typosquatting).

**What established sources say**
- A study of 16 code-generating models found commercial models recommended non-existent packages at least 5.2% of the time, and open-source models 21.7% of the time. **[S9]**
- GitHub's own guidance says pinning an Action to a full-length commit SHA is the only way to use it as an immutable release. **[S10]**
- From this project's own testing (not a published source): the typo names `expresss` and `lodahs` both exist on npm, which is why checking that a package *exists* isn't enough on its own.

**Scanner:** `PQC000`–`PQC014`, `SUP001`–`SUP008`.

---

## Sources

All checked on 10 October 2026. "Checked" says exactly what was confirmed on the source.

| # | Source | Type | Published | Checked |
|---|---|---|---|---|
| S1 | [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) | Community standard | 2025 edition | LLM01:2025 is Prompt Injection; LLM05:2025 is Improper Output Handling |
| S2 | [MITRE CWE](https://cwe.mitre.org/) | Standard catalogue | ongoing | CWE IDs as used in the rules (`docs/RULES.md`) |
| S3 | [Model Context Protocol](https://modelcontextprotocol.io/) | Protocol documentation | ongoing | Describes MCP as an open standard connecting AI applications to data sources and tools |
| S4 | [MITRE ATLAS fact sheet](https://atlas.mitre.org/pdf-files/MITRE_ATLAS_Fact_Sheet.pdf) | Knowledge base (non-profit) | n/d | Describes ATLAS as a living knowledge base of adversary tactics and techniques for AI-enabled systems, patterned after ATT&CK |
| S5 | [Rehberger, "ASCII Smuggler Tool: Crafting Invisible Text and Decoding Hidden Codes"](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/) | Practitioner research | 14 Jan 2024 | Unicode tag characters can hide instructions that people can't see but LLMs read |
| S6 | [NVD: CVE-2021-42574](https://nvd.nist.gov/vuln/detail/CVE-2021-42574) | Vulnerability database | 2021 | Bidi control characters can make code display differently than it is processed; marked disputed |
| S7 | [NIST: first 3 finalised post-quantum standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards) | Government standard | 13 Aug 2024 | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) |
| S8 | [IETF RFC 10024: PQ/T Hybrid Key Agreement for TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) | Internet standard | Aug 2026 | Published as RFC 10024, Proposed Standard; defines X25519MLKEM768 |
| S9 | [Spracklen et al., "We Have a Package for You!"](https://arxiv.org/abs/2406.10279) | Academic paper (preprint) | 12 Jun 2024 | 16 models tested; ≥5.2% (commercial) and 21.7% (open-source) of recommended packages didn't exist |
| S10 | [GitHub Docs: Secure use reference for Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) | Vendor documentation (platform owner) | ongoing | A full-length commit SHA is the only way to use an Action as an immutable release |

---

## Leads to verify

These came from the research that started this project. They're vendor claims or names nobody has checked yet. A lead moves into the sections above only when its specific claim is confirmed on a primary source.

| Area | Lead (as originally claimed) | Source type | Status |
|---|---|---|---|
| 1 | Palo Alto Networks "SHIELD" framework for vibe-coded apps | vendor | unverified |
| 1 | Scanners named hackmenot, GuardVibe, vibe-shield, VibeScan, and their rule counts | vendor / open source | unverified |
| 2 | AI-focused DLP features from MIND, Cyera, Sentra, Netskope, Forcepoint, Palo Alto Cortex | vendor | unverified |
| 3 | IETF "Agent Identity Protocol" draft; CSA "Agent Identity Governance Framework" | standards body | unverified |
| 3 | Symmetry AIGuard, SailPoint agent-identity products | vendor | unverified |
| 4 | Deepfake detection from Sumsub, iProov, Sensity; Deel's acquisition of Clarity; quoted accuracy figures | vendor | unverified |
| 5 | "Q-Ready" framework, PQC Planner, Crypto-Agility Readiness Score (CARS) | academic / vendor | unverified |
| 5 | SBOM2TD agent | unknown | unverified |

**To verify a lead:** open a pull request that adds the primary source to [Sources](#sources) with type, publication date, exactly what you confirmed, and today's date; then move the claim into its section with a `[S#]` reference. Vendor marketing counts as a *vendor claim*, not evidence that a product works. Independent tests or papers are better.
