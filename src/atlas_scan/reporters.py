"""Turn a ScanResult into text, JSON, SARIF or Markdown."""

from __future__ import annotations

import json
from collections import defaultdict

from . import __version__
from .engine import ScanResult
from .models import CATEGORIES, Finding, Severity
from .scanners import all_rules

TOOL = "ai-security-atlas"
REPO_URL = "https://github.com/kaymyg/ai-security-atlas"
INVENTORY_ID = "PQC000"

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"
_KIND_LABEL = {"vulnerability": "vulnerability", "misconfiguration": "config", "inventory": "inventory"}


def _kind_counts(findings: list[Finding]) -> dict[str, int]:
    out = {k: 0 for k in ("vulnerability", "misconfiguration", "inventory")}
    for f in findings:
        out[f.rule.kind] += 1
    return out


def _split(result: ScanResult) -> tuple[list[Finding], dict]:
    inventory: dict = {}
    findings = []
    for f in result.findings:
        if f.rule.id == INVENTORY_ID:
            inventory = f.extra.get("inventory", {})
        else:
            findings.append(f)
    return findings, inventory


# ------------------------------------------------------------------- text

def to_text(result: ScanResult, color: bool = True) -> str:
    c = (lambda code, s: f"{code}{s}{_RESET}") if color else (lambda code, s: s)
    findings, inventory = _split(result)
    out: list[str] = []

    by_cat: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_cat[f.rule.category].append(f)

    for cat, label in CATEGORIES.items():
        items = by_cat.get(cat)
        if not items:
            continue
        out.append(c(_BOLD, f"\n■ {label}  ({len(items)})"))
        for f in items:
            sev = c(_COLORS[f.severity], f" {str(f.severity).upper():8} ")
            out.append(f"  {sev} {f.rule.id:8} {_KIND_LABEL[f.rule.kind]:15} {f.path}:{f.line}")
            out.append(f"           {f.message or f.rule.title}")
            if f.snippet:
                out.append(c(_DIM, f"           │ {f.snippet}"))
            if f.rule.fix:
                out.append(f"           → {f.rule.fix}")

    if inventory:
        out.append(c(_BOLD, "\n■ Cryptography inventory (post-quantum discovery)"))
        for label, paths in inventory.items():
            shown = ", ".join(paths[:4]) + (f" +{len(paths) - 4} more" if len(paths) > 4 else "")
            out.append(f"  {label:32} {len(paths):3} file(s)  {c(_DIM, shown)}")

    counts = result.counts()
    counts["info"] -= 1 if inventory else 0
    summary = "  ".join(f"{k}: {v}" for k, v in counts.items() if v)
    kinds = _kind_counts(findings)
    kind_text = ", ".join(f"{v} {k}" for k, v in kinds.items() if v)
    out.append(c(_BOLD, "\nSummary") + f"  {result.files_scanned} files scanned, "
               f"{len(findings)} finding(s)" + (f"  [{summary}]" if summary else "") +
               (f"\n         by kind: {kind_text}" if kind_text else ""))
    if kinds["inventory"]:
        out.append(c(_DIM, "         'inventory' items are planning notes (e.g. post-quantum migration), "
                           "not vulnerabilities, and never fail the build."))
    out.extend(_audit_lines(result, c))
    for w in result.warnings:
        out.append(c("\033[1;33m", f"⚠ {w}"))
    if not findings:
        out.append(c("\033[32m", "No issues found. ✓"))
    return "\n".join(out).lstrip("\n") + "\n"


def _audit_lines(result: ScanResult, c) -> list[str]:
    """Everything that was silenced, so nothing can be hidden quietly."""
    out = []
    if result.suppressed_findings:
        items = [f"{f.rule.id} {f.path}:{f.line}" for f in result.suppressed_findings]
        shown = ", ".join(items[:8]) + (f" +{len(items) - 8} more (see -f json)" if len(items) > 8 else "")
        out.append(c(_DIM, f"Silenced by 'atlas: ignore': {shown}"))
    if result.skipped_files:
        out.append(c(_DIM, f"Skipped via 'atlas: ignore-file' (review these if you didn't add them): "
                           f"{', '.join(result.skipped_files)}"))
    if result.exclusions:
        out.append(c(_DIM, "Excluded by ignore patterns: " +
                     ", ".join(f"'{p}' ({n} file(s))" for p, n in result.exclusions.items())))
    for e in result.errors:
        out.append(c("\033[1;33m", f"Error: {e['scanner']} scanner failed on {e['path']} ({e['error']})"))
    return out


# ------------------------------------------------------------------- json

def to_json(result: ScanResult) -> str:
    findings, inventory = _split(result)
    counts = result.counts()
    if inventory:
        counts["info"] -= 1
    return json.dumps({
        "tool": TOOL,
        "version": __version__,
        "files_scanned": result.files_scanned,
        "suppressed": result.suppressed,
        "suppressed_findings": [f.to_dict() for f in result.suppressed_findings],
        "skipped_files": result.skipped_files,
        "exclusions": result.exclusions,
        "errors": result.errors,
        "warnings": result.warnings,
        "counts": counts,
        "counts_by_kind": _kind_counts(findings),
        "findings": [f.to_dict() for f in findings],
        "crypto_inventory": inventory,
    }, indent=2) + "\n"


# ------------------------------------------------------------------- sarif

_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                      Severity.LOW: "3.0", Severity.INFO: "1.0"}


def to_sarif(result: ScanResult) -> str:
    findings, inventory = _split(result)
    rules = [r for r in all_rules() if r.id != INVENTORY_ID]
    index = {r.id: i for i, r in enumerate(rules)}
    sarif_rules = []
    for r in rules:
        tags = ["security", f"atlas/{r.category}", f"atlas/{r.kind}"] + ([r.cwe] if r.cwe else [])
        sarif_rules.append({
            "id": r.id,
            "name": r.title.title().replace(" ", "").replace("/", "").replace("(", "").replace(")", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": f"{r.title}. Category: {CATEGORIES.get(r.category, r.category)}. "
                                        f"Kind: {r.kind}."},
            "help": {"text": r.fix or r.title, "markdown": f"**Fix:** {r.fix}" if r.fix else r.title},
            "helpUri": f"{REPO_URL}/blob/main/docs/RULES.md#{r.id.lower()}",
            "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
            "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY[r.severity],
                           "precision": "medium"},
        })
    results = []
    for f, suppressed in [(f, False) for f in findings] + [(f, True) for f in result.suppressed_findings]:
        results.append({
            "ruleId": f.rule.id,
            "ruleIndex": index.get(f.rule.id, 0),
            "kind": "informational" if f.rule.kind == "inventory" else "fail",
            "level": "none" if f.rule.kind == "inventory" else _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message or f.rule.title}. Fix: {f.rule.fix}" if f.rule.fix
                        else (f.message or f.rule.title)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, f.line), "startColumn": max(1, f.column)},
            }}],
            "partialFingerprints": {"atlasFinding/v1": f"{f.rule.id}:{f.path}:{f.snippet}"[:200]},
            **({"suppressions": [{"kind": "inSource", "justification": "atlas: ignore comment"}]}
               if suppressed else {}),
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL, "version": __version__, "informationUri": REPO_URL,
                                "rules": sarif_rules}},
            "results": results,
            "properties": {"cryptoInventory": inventory, "skippedFiles": result.skipped_files,
                           "exclusions": result.exclusions, "warnings": result.warnings},
            "invocations": [{"executionSuccessful": not result.errors,
                             "toolExecutionNotifications": [
                                 {"level": "warning", "message": {"text": f"{e['scanner']} failed on {e['path']}: "
                                                                          f"{e['error']}"}}
                                 for e in result.errors]}],
        }],
    }
    return json.dumps(doc, indent=2) + "\n"


# ------------------------------------------------------------------- markdown

_EMOJI = {Severity.CRITICAL: "🟥", Severity.HIGH: "🔴", Severity.MEDIUM: "🟠", Severity.LOW: "🔵",
          Severity.INFO: "⚪"}


def to_markdown(result: ScanResult, limit: int = 50) -> str:
    findings, inventory = _split(result)
    lines = ["## 🛡️ AI Security Atlas scan", ""]
    if not findings:
        lines.append(f"No issues found in {result.files_scanned} files. ✅")
    else:
        counts = result.counts()
        if inventory:
            counts["info"] -= 1
        lines.append(" · ".join(f"{_EMOJI[Severity.parse(k)]} **{v}** {k}" for k, v in counts.items() if v) +
                     f" — {result.files_scanned} files scanned")
        lines += ["", "| Severity | Kind | Rule | Where | Issue |", "|---|---|---|---|---|"]
        for f in findings[:limit]:
            msg = (f.message or f.rule.title).replace("|", "\\|")
            lines.append(f"| {_EMOJI[f.severity]} {f.severity} | {f.rule.kind} | `{f.rule.id}` | "
                         f"`{f.path}:{f.line}` | {msg} |")
        if len(findings) > limit:
            lines.append(f"\n…and {len(findings) - limit} more. Download the SARIF/JSON report for the full list.")
    if result.warnings:
        lines += [""] + [f"> ⚠️ {w}" for w in result.warnings]
    audit = []
    if result.suppressed:
        audit.append(f"{result.suppressed} finding(s) silenced by `atlas: ignore` comments")
    if result.skipped_files:
        audit.append(f"{len(result.skipped_files)} file(s) skipped by `atlas: ignore-file`")
    if result.exclusions:
        audit.append(", ".join(f"`{p}` excluded {n} file(s)" for p, n in result.exclusions.items()))
    if audit:
        lines += ["", "**Suppression audit:** " + "; ".join(audit)]
    if inventory:
        lines += ["", "<details><summary>Cryptography inventory (post-quantum discovery)</summary>", "",
                  "| Algorithm family | Files |", "|---|---|"]
        lines += [f"| {k} | {len(v)} |" for k, v in inventory.items()]
        lines += ["", "</details>"]
    return "\n".join(lines) + "\n"


FORMATS = {"text": to_text, "json": to_json, "sarif": to_sarif, "markdown": to_markdown}
