"""Runs every scanner over every file and tidies up the results."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Finding, Severity, SourceFile
from .scanners import Scanner, default_scanners
from .walker import iter_files

# "atlas: ignore" silences every rule on that line (or the next line, when the
# comment sits on a line of its own). "atlas: ignore[SEC001,VIBE004]" silences
# only those rules.
# "atlas: ignore-file" in the first five lines skips the whole file.
_FILE_IGNORE_RE = re.compile(r"atlas:\s*ignore-file", re.IGNORECASE)
_IGNORE_RE = re.compile(r"atlas:\s*ignore(?!-file)(?:\[([A-Z0-9_,\s-]+)\])?", re.IGNORECASE)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    # Audit trail: everything that was silenced, and how.
    suppressed_findings: list[Finding] = field(default_factory=list)  # inline "atlas: ignore"
    skipped_files: list[str] = field(default_factory=list)            # "atlas: ignore-file"
    exclusions: dict[str, int] = field(default_factory=dict)          # ignore pattern -> files excluded
    errors: list[dict] = field(default_factory=list)                  # a scanner crashed on a file
    warnings: list[str] = field(default_factory=list)

    @property
    def suppressed(self) -> int:
        return len(self.suppressed_findings)

    @property
    def excluded_everything(self) -> bool:
        return self.files_scanned == 0 and sum(self.exclusions.values()) > 0

    def at_or_above(self, level: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= level]

    def counts(self) -> dict[str, int]:
        out = {str(s): 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[str(f.severity)] += 1
        return out


def _suppressions(src: SourceFile) -> dict[int, set[str] | None]:
    """Map line number -> rule ids silenced there (None means all)."""
    out: dict[int, set[str] | None] = {}
    for i, line in enumerate(src.lines, start=1):
        m = _IGNORE_RE.search(line)
        if not m:
            continue
        ids = {x.strip().upper() for x in m.group(1).split(",")} if m.group(1) else None
        targets = [i]
        # A comment-only line protects the line below it.
        if line.strip().startswith(("#", "//", "/*", "*", "--", "<!--")):
            targets.append(i + 1)
        for t in targets:
            if t in out and (out[t] is None or ids is None):
                out[t] = None
            elif t in out:
                out[t] = out[t] | ids  # type: ignore[operator]
            else:
                out[t] = ids
    return out


def _is_suppressed(f: Finding, table: dict[int, set[str] | None]) -> bool:
    if f.line not in table:
        return False
    ids = table[f.line]
    return ids is None or f.rule.id.upper() in ids


def scan_path(
    root: str,
    scanners: list[Scanner] | None = None,
    min_severity: Severity = Severity.INFO,
    categories: set[str] | None = None,
    extra_ignores: list[str] | None = None,
) -> ScanResult:
    scanners = scanners if scanners is not None else default_scanners()
    if categories:
        scanners = [s for s in scanners if s.category in categories]
    result = ScanResult()
    seen: set[tuple] = set()

    for src in iter_files(root, extra_ignores, excluded=result.exclusions):
        result.files_scanned += 1
        if _FILE_IGNORE_RE.search("\n".join(src.lines[:5])):
            result.skipped_files.append(src.path)
            continue
        table = None
        for scanner in scanners:
            try:
                found = list(scanner.scan(src)) if scanner.applies(src) else []
            except Exception as exc:  # one odd file must not stop the whole scan
                # Record only the error type: the message could contain file content.
                result.errors.append({"scanner": scanner.name, "path": src.path, "error": type(exc).__name__})
                continue
            for f in found:
                if f.severity < min_severity:
                    continue
                key = (f.rule.id, f.path, f.line, f.snippet)
                if key in seen:
                    continue
                seen.add(key)
                if table is None:
                    table = _suppressions(src)
                if _is_suppressed(f, table):
                    result.suppressed_findings.append(f)
                    continue
                result.findings.append(f)

    for scanner in scanners:
        result.findings.extend(f for f in scanner.finish() if f.severity >= min_severity)

    result.findings.sort(key=lambda f: (-f.severity, f.path, f.line, f.rule.id))
    result.warnings = _warnings(result)
    return result


def _warnings(result: ScanResult) -> list[str]:
    out = []
    excluded_total = sum(result.exclusions.values())
    if result.excluded_everything:
        out.append(f"Ignore patterns excluded every file ({excluded_total}); nothing was scanned.")
    else:
        total = result.files_scanned + excluded_total
        for pattern, count in result.exclusions.items():
            if total >= 10 and count / total > 0.5:
                out.append(f"Ignore pattern '{pattern}' excludes {count} of {total} files.")
    if result.errors:
        out.append(f"{len(result.errors)} file(s) could not be fully scanned (see errors).")
    return out
