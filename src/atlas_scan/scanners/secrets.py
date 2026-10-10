"""Secrets: keys and tokens that leak into git and get pasted into AI tools.

Problem area 2 (unconscious data spillage). If a key sits in your code, it
also ends up in every AI chat you paste that code into.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Iterable

from ..models import Finding, Rule, Severity, SourceFile
from . import Scanner

C = "secrets"


def _r(id_, title, sev, fix="Revoke the key, remove it from code, and load it from an environment variable or secret manager.") -> Rule:
    return Rule(id_, title, sev, C, fix, cwe="CWE-798")


# (rule, regex, group holding the secret)
PATTERNS: list[tuple[Rule, re.Pattern, int]] = [
    (_r("SEC001", "AWS access key ID", Severity.CRITICAL),
     re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[0-9A-Z]{16})(?![A-Z0-9])"), 1),
    (_r("SEC002", "GitHub token", Severity.CRITICAL),
     re.compile(r"\b((?:gh[pousr]_[A-Za-z0-9]{36,255})|(?:github_pat_[A-Za-z0-9_]{60,255}))\b"), 1),
    (_r("SEC003", "Anthropic API key", Severity.CRITICAL),
     re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})"), 1),
    (_r("SEC004", "OpenAI API key", Severity.CRITICAL),
     re.compile(r"\b(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,})"), 1),
    (_r("SEC005", "Google API key", Severity.HIGH),
     re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    (_r("SEC006", "Stripe live secret key", Severity.CRITICAL),
     re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"), 1),
    (_r("SEC007", "Slack token", Severity.HIGH),
     re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})"), 1),
    (_r("SEC008", "Slack incoming webhook URL", Severity.MEDIUM),
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,})"), 1),
    (_r("SEC009", "Private key block", Severity.CRITICAL,
        "Delete the key from the repo, rotate it, and store it outside source control."),
     re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 1),
    (_r("SEC010", "Hugging Face token", Severity.HIGH),
     re.compile(r"\b(hf_[A-Za-z]{34,})\b"), 1),
    (_r("SEC011", "JSON Web Token", Severity.MEDIUM,
        "Don't commit real JWTs; they often stay valid long after you forget them."),
     re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), 1),
    (_r("SEC012", "Database URL with embedded password", Severity.HIGH),
     re.compile(r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^:\s/@\"']+:([^@\s/\"']{3,})@)"), 2),
    (_r("SEC013", "Blockchain wallet private key", Severity.CRITICAL,
        "Move the key to a hardware wallet, KMS or secret manager and drain/rotate the wallet if it was ever pushed."),
     re.compile(r"(?i)(?:priv(?:ate)?_?key|secret_?key|signer|wallet_?key|pk)\s*[:=]\s*[\"']?(0x[a-fA-F0-9]{64})\b"), 1),
]

GENERIC = _r("SEC020", "Hard-coded secret in assignment", Severity.MEDIUM)
GENERIC_RE = re.compile(
    r"""(?ix)
    \b([a-z0-9_.\-]*(?:api[_\-]?key|secret|token|passw(?:or)?d|pwd|auth[_\-]?key|client[_\-]?secret|access[_\-]?key|private[_\-]?key))
    ["']?\s*[:=]>?\s*
    (["'])([^"'\s]{12,200})\2
    """
)

ENV_FILE = Rule("SEC030", "Environment file with values present in the repo", Severity.MEDIUM, C,
                "Add .env files to .gitignore and commit a .env.example with empty values instead.",
                cwe="CWE-538")

PLACEHOLDER_HINTS = (
    "example", "xxxx", "your", "changeme", "change_me", "placeholder", "dummy", "sample",
    "redacted", "<", "{", "%s", "%(", "process.env", "os.environ", "getenv", "****", "...",
    "fake", "test", "todo", "replace", "insert", "here",
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_placeholder(value: str) -> bool:
    low = value.lower()
    if any(h in low for h in PLACEHOLDER_HINTS):
        return True
    return len(set(value)) <= 3  # "aaaaaaaaaaaa", "000000000000"


def mask(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "…" + "*" * 6


class SecretScanner(Scanner):
    name = "secrets"
    category = C
    rules = [p[0] for p in PATTERNS] + [GENERIC, ENV_FILE]

    def applies(self, src: SourceFile) -> bool:
        return not src.name.endswith((".example", ".sample", ".template")) and \
            not src.name.startswith(".env.example")

    def scan(self, src: SourceFile) -> Iterable[Finding]:
        taken: set[int] = set()  # lines already reported by a specific rule
        for rule, regex, group in PATTERNS:
            for m in regex.finditer(src.text):
                secret = m.group(group)
                if rule.id != "SEC009" and looks_placeholder(secret):
                    continue
                line, col = src.line_of(m.start(group))
                taken.add(line)
                yield self._finding(rule, src, line, col, secret)

        # MCP configs get a more specific check (AGT001) in the agents scanner.
        generic_ok = not (src.suffix == ".json" and '"mcpServers"' in src.text)
        for m in (GENERIC_RE.finditer(src.text) if generic_ok else ()):
            value = m.group(3)
            line, col = src.line_of(m.start(3))
            if line in taken or looks_placeholder(value):
                continue
            if entropy(value) < 3.3:
                continue
            yield self._finding(GENERIC, src, line, col, value,
                                message=f"'{m.group(1)}' is assigned a literal that looks like a real secret")

        if self._is_live_env_file(src):
            yield Finding(rule=ENV_FILE, path=src.path, line=1,
                          snippet=f"{src.name} ({sum(1 for l in src.lines if '=' in l)} variables)")

    @staticmethod
    def _finding(rule, src, line, col, secret, message="") -> Finding:
        raw = src.snippet(line, limit=400)
        snippet = raw.replace(secret, mask(secret))
        if len(snippet) > 160:
            snippet = snippet[:159] + "…"
        return Finding(rule=rule, path=src.path, line=line, column=col, snippet=snippet,
                       message=message or rule.title, extra={"secret": mask(secret)})

    @staticmethod
    def _is_live_env_file(src: SourceFile) -> bool:
        name = src.name
        if not (name == ".env" or (name.startswith(".env.") and not name.endswith(
                (".example", ".sample", ".template", ".dist")))):
            return False
        has_value = any(
            "=" in l and l.split("=", 1)[1].strip().strip("\"'") and not l.lstrip().startswith("#")
            for l in src.lines
        )
        if not has_value:
            return False
        # If a .gitignore at the scan root already covers it, it's fine locally.
        root = src.abspath[: -len(src.path)] if src.abspath.endswith(src.path) else ""
        gi = os.path.join(root, ".gitignore") if root else ""
        if gi and os.path.isfile(gi):
            with open(gi, encoding="utf-8", errors="replace") as fh:
                rules = {l.strip() for l in fh if l.strip() and not l.startswith("#")}
            if rules & {".env", ".env*", ".env.*", "*.env", "/.env", ".env.local", name, "/" + name}:
                return False
        return True
