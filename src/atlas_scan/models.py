"""Core data types shared by every scanner.

A scanner's only job is to turn a file into a list of ``Finding`` objects.
Everything else (walking the repo, ignoring, reporting) lives elsewhere.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so we can compare: Severity.HIGH > Severity.LOW."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


# The five problem areas from the research this project grew out of.
CATEGORIES = {
    "vibe-code": "AI-generated code flaws",
    "secrets": "Secrets that could spill into AI tools or git",
    "agents": "AI agent / MCP permissions and trust",
    "supply-chain": "Hallucinated or typosquatted dependencies",
    "quantum": "Weak cryptography and post-quantum inventory",
}


# What a finding means, separate from how severe it is:
#   vulnerability     a weakness or exposure that could be used against you now
#   misconfiguration  a risky setting that widens the damage if something else goes wrong
#   inventory         an observation for planning (e.g. post-quantum migration), not a weakness by itself
KINDS = ("vulnerability", "misconfiguration", "inventory")

MISCONFIGURATION_IDS = {
    "VIBE017", "VIBE052", "VIBE053",
    "SEC030",
    "AGT002", "AGT003", "AGT004", "AGT005", "AGT010", "AGT011", "AGT012", "AGT013", "AGT014", "AGT020",
    "SUP004", "SUP005", "SUP006", "SUP007",
    "PQC005",
}
INVENTORY_IDS = {"PQC000", "PQC010", "PQC011", "PQC012", "PQC013", "PQC014", "SUP003", "SUP008"}


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    fix: str = ""
    cwe: str = ""

    @property
    def kind(self) -> str:
        if self.id in INVENTORY_IDS:
            return "inventory"
        if self.id in MISCONFIGURATION_IDS:
            return "misconfiguration"
        return "vulnerability"


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int = 1
    column: int = 1
    snippet: str = ""
    message: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict:
        data = {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": str(self.rule.severity),
            "category": self.rule.category,
            "kind": self.rule.kind,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "message": self.message or self.rule.title,
            "fix": self.rule.fix,
        }
        if self.rule.cwe:
            data["cwe"] = self.rule.cwe
        if self.extra:
            data["extra"] = self.extra
        return data


@dataclass
class SourceFile:
    """A text file loaded once and shared with all scanners."""

    path: str  # relative, forward slashes
    abspath: str
    text: str
    lines: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.lines:
            self.lines = self.text.splitlines()

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def suffix(self) -> str:
        name = self.name
        return name[name.rfind("."):].lower() if "." in name else ""

    def line_of(self, offset: int) -> tuple[int, int]:
        """Convert a character offset into (line, column), both 1-based."""
        line = self.text.count("\n", 0, offset) + 1
        col = offset - (self.text.rfind("\n", 0, offset) + 1) + 1
        return line, col

    def snippet(self, line: int, limit: int = 160) -> str:
        if 1 <= line <= len(self.lines):
            text = self.lines[line - 1].strip()
            return text if len(text) <= limit else text[: limit - 1] + "…"
        return ""


def as_dicts(findings: list[Finding]) -> list[dict]:
    return [f.to_dict() for f in findings]


__all__ = ["Severity", "Rule", "Finding", "SourceFile", "CATEGORIES", "KINDS", "as_dicts", "asdict"]
