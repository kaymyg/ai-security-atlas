---
title: AI Security Atlas
emoji: 🛡️
colorFrom: purple
colorTo: indigo
sdk: gradio
sdk_version: 6.30.0
python_version: "3.12"
app_file: app.py
pinned: false
license: mit
short_description: Scan code for AI-era security risks
tags:
  - security
  - ai-security
  - mcp
  - prompt-injection
  - supply-chain
  - post-quantum
---

# AI Security Atlas: scanner demo

Paste code or upload files to check them for AI-era security risks:

- **AI-generated code flaws**: model output run with `eval`/`exec`, user input in system prompts, SQL injection, disabled TLS checks…
- **Leaked secrets**: API keys, tokens, wallet keys, passwords in URLs (always masked in the report)
- **AI agent & MCP configs**: hard-coded tokens, whole-disk access, approval prompts turned off, agents anyone can prompt from CI
- **Hidden instructions**: invisible Unicode that AI models read but people can't see (decoded so you can read it)
- **Supply chain**: typosquatted and non-existent ("hallucinated") packages
- **Cryptography**: broken algorithms, plus a post-quantum migration inventory

The file name matters: it decides which rules apply (`.mcp.json`, `AGENTS.md`, `.github/workflows/ci.yml`…).

Your input is scanned in a temporary folder, never executed, and deleted straight away. Please still don't paste real secrets.

**Accuracy:** 94% precision and 94% recall on a labelled benchmark of deliberately tricky cases, which is also published as a dataset: [Sahek/ai-security-atlas-benchmark](https://huggingface.co/datasets/Sahek/ai-security-atlas-benchmark). Pattern-based checks can miss cases and flag safe code; see the [known limitations](https://github.com/kaymyg/ai-security-atlas/blob/main/docs/KNOWN_LIMITATIONS.md).

Source, CLI and GitHub Action: **[github.com/kaymyg/ai-security-atlas](https://github.com/kaymyg/ai-security-atlas)**. This Space is published automatically from that repository.
