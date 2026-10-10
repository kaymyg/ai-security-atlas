"""Scanner plug-ins.

Each scanner covers one problem area. To add your own, subclass ``Scanner``,
implement ``applies`` and ``scan``, and add it to ``default_scanners``.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..models import Finding, Rule, SourceFile


class Scanner:
    name = "base"
    category = ""
    rules: list[Rule] = []

    def applies(self, src: SourceFile) -> bool:  # pragma: no cover - overridden
        return True

    def scan(self, src: SourceFile) -> Iterable[Finding]:  # pragma: no cover - overridden
        return []

    def finish(self) -> Iterable[Finding]:
        """Called once after every file is scanned (for whole-repo checks)."""
        return []


class PatternRule:
    """A rule that fires when a regex matches inside certain file types."""

    def __init__(self, rule: Rule, pattern: str, suffixes: set[str], flags: int = 0,
                 unless: str | None = None):
        self.rule = rule
        self.regex = re.compile(pattern, flags)
        self.suffixes = suffixes
        self.unless = re.compile(unless, flags) if unless else None

    def matches(self, src: SourceFile) -> Iterable[Finding]:
        if self.suffixes and src.suffix not in self.suffixes:
            return
        for m in self.regex.finditer(src.text):
            line, col = src.line_of(m.start())
            text = src.lines[line - 1] if line <= len(src.lines) else ""
            if self.unless and self.unless.search(text):
                continue
            yield Finding(rule=self.rule, path=src.path, line=line, column=col,
                          snippet=src.snippet(line))


def default_scanners() -> list[Scanner]:
    from .agents import AgentConfigScanner, HiddenUnicodeScanner
    from .code import VibeCodeScanner
    from .crypto import QuantumCryptoScanner
    from .deps import DependencyScanner
    from .secrets import SecretScanner

    return [
        SecretScanner(),
        VibeCodeScanner(),
        AgentConfigScanner(),
        HiddenUnicodeScanner(),
        DependencyScanner(),
        QuantumCryptoScanner(),
    ]


def all_rules() -> list[Rule]:
    rules: list[Rule] = []
    for s in default_scanners():
        rules.extend(s.rules)
    return sorted(rules, key=lambda r: r.id)
