"""Build the Hugging Face Space and dataset folders from this repository.

    python tools/build_hf.py build/hf     # writes build/hf/space and build/hf/dataset

The Space gets the demo app plus a copy of the scanner package. The dataset
gets one row per labelled benchmark case. Both are uploaded by
tools/publish_hf.py (run from GitHub Actions).
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from atlas_scan import __version__  # noqa: E402
from atlas_scan.models import CATEGORIES  # noqa: E402
from atlas_scan.scanners import all_rules  # noqa: E402

SPACE_FILES = ["app.py", "demo_examples.py", "README.md"]
LANGUAGES = {".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript", ".go": "go",
             ".java": "java", ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".md": "markdown",
             ".sh": "shell", ".conf": "nginx", ".pem": "pem", ".txt": "text"}
COMMENT_START = re.compile(r"(?:\s*(?:#|//|<!--))?\s*$")


def _runner():
    spec = importlib.util.spec_from_file_location("bench_run", ROOT / "benchmark" / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ----------------------------------------------------------------- space

def build_space(out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    for name in SPACE_FILES:
        shutil.copyfile(ROOT / "huggingface" / "space" / name, out / name)
    shutil.copytree(ROOT / "src" / "atlas_scan", out / "atlas_scan",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copyfile(ROOT / "LICENSE", out / "LICENSE")
    return out


# ----------------------------------------------------------------- dataset

def _language(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if name.startswith("dockerfile"):
        return "dockerfile"
    if name in (".env", ".env.example") or name.startswith(".env"):
        return "dotenv"
    if name in (".cursorrules",):
        return "text"
    suffix = name[name.rfind("."):] if "." in name else ""
    return LANGUAGES.get(suffix, "text")


def _strip_label(line: str, label_re: re.Pattern) -> tuple[str, str]:
    """Split a case line into (code without the label comment, human note)."""
    matches = list(label_re.finditer(line))
    if not matches:
        return line.rstrip(), ""
    first, last = matches[0], matches[-1]
    note = line[last.end():].strip().removesuffix("-->").strip()
    code = line[: first.start()]
    code = COMMENT_START.sub("", code)          # drop the "  # " / " // " / " <!-- " that held the label
    return code.rstrip(), note


def dataset_rows() -> list[dict]:
    run = _runner()
    rules = {r.id: r for r in all_rules()}
    with tempfile.TemporaryDirectory() as tmp:
        labels = run.prepare(Path(tmp))         # {(rendered path, line): {kind: {rule ids}}}

    # Template text by rendered path, so rows never contain generated secrets or hidden characters.
    sources: dict[str, list[str]] = {}
    sidecar_notes: dict[tuple[str, int], str] = {}
    for src in sorted(run.CASES.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(run.CASES).as_posix()
        if rel.endswith(".expect"):
            continue
        rendered = rel[: -len(".tmpl")] if rel.endswith(".tmpl") else rel
        sources[rendered] = src.read_text(encoding="utf-8").split("\n")
    for sidecar in sorted(run.CASES.rglob("*.expect")):
        target = sidecar.relative_to(run.CASES).as_posix()[: -len(".expect")]
        target = target[: -len(".tmpl")] if target.endswith(".tmpl") else target
        note, rendered_lines = "", None
        for raw in sidecar.read_text(encoding="utf-8").splitlines():
            if raw.lstrip().startswith("#"):
                note = raw.lstrip("# ").strip()
                continue
            m = run.SIDECAR_LINE.match(raw)
            if not m:
                continue
            if rendered_lines is None:
                with tempfile.TemporaryDirectory() as tmp2:
                    run.prepare(Path(tmp2))
                    rendered_lines = (Path(tmp2) / target).read_text(encoding="utf-8").splitlines()
            line_no = next(i for i, l in enumerate(rendered_lines, 1) if m.group(3) in l)
            if note:
                sidecar_notes[(target, line_no)] = note
            note = ""

    rows = []
    for (path, line_no), kinds in sorted(labels.items()):
        raw = sources[path][line_no - 1]
        code, note = _strip_label(raw, run.LABEL)
        note = note or sidecar_notes.get((path, line_no), "")
        for kind in ("expect", "miss", "safe", "noisy"):
            for rid in sorted(kinds.get(kind, ())):
                rule = rules[rid]
                rows.append({
                    "id": f"{path}:{line_no}:{rid}",
                    "rule_id": rid,
                    "rule_title": rule.title,
                    "category": rule.category,
                    "kind": rule.kind,
                    "severity": str(rule.severity),
                    "label": kind,
                    "is_unsafe": kind in ("expect", "miss"),
                    "flagged_by_atlas": kind in ("expect", "noisy"),
                    "file": path,
                    "language": _language(path),
                    "line": line_no,
                    "code": code,
                    "note": note,
                    "uses_placeholders": "{{" in code,
                    "atlas_version": __version__,
                })
    return rows


DATASET_CARD = """---
license: mit
pretty_name: AI Security Atlas Benchmark
language:
- en
task_categories:
- text-classification
tags:
- security
- code
- sast
- secrets-detection
- ai-agents
- mcp
- prompt-injection
- supply-chain
- post-quantum
- benchmark
size_categories:
- n<1K
configs:
- config_name: default
  data_files:
  - split: test
    path: data/benchmark.jsonl
---

# AI Security Atlas Benchmark

{n_rows} hand-labelled test cases for scanners that look for **AI-era security risks** in code and config files:
AI-generated code flaws, leaked secrets, risky AI-agent and MCP configurations, hidden Unicode instructions,
hallucinated or typosquatted dependencies, and weak or quantum-vulnerable cryptography.

Each row is one line of code paired with one rule, labelled with whether the line is **actually unsafe** and
whether the [ai-security-atlas](https://github.com/kaymyg/ai-security-atlas) scanner (v{version}) flags it.
The set deliberately includes **safe look-alikes** (to measure false alarms) and **known blind spots**
(to measure misses), so it's useful for testing any scanner, not just this one.

Try the scanner: [Sahek/ai-security-atlas Space](https://huggingface.co/spaces/Sahek/ai-security-atlas).

## Columns

| Column | Meaning |
|---|---|
| `rule_id`, `rule_title` | The check this case tests ([rule reference](https://github.com/kaymyg/ai-security-atlas/blob/main/docs/RULES.md)) |
| `category` | {categories} |
| `kind` | `vulnerability`, `misconfiguration` or `inventory` (a planning note, e.g. post-quantum) |
| `label` | `expect` (unsafe, caught) · `miss` (unsafe, not caught) · `safe` (safe look-alike, not flagged) · `noisy` (safe look-alike, wrongly flagged) |
| `is_unsafe` | Ground truth: `true` for `expect`/`miss` |
| `flagged_by_atlas` | What ai-security-atlas v{version} does: `true` for `expect`/`noisy` |
| `file`, `language`, `line` | Where the case lives in the [benchmark folder](https://github.com/kaymyg/ai-security-atlas/tree/main/benchmark/cases) |
| `code` | The line, with its label removed |
| `note` | Why the case is labelled the way it is, when that isn't obvious |
| `uses_placeholders` | `true` if `code` contains `{{{{PLACEHOLDERS}}}}` (see below) |

## Placeholders instead of secrets

Rows never contain real-looking secrets or invisible characters, because publishing them would trip secret
scanners and hide content from readers. Instead they hold placeholders such as `{{{{GITHUB_TOKEN}}}}`,
`{{{{RANDOM32}}}}`, `{{{{HIDDEN:text}}}}` (text encoded as invisible Unicode tag characters) or `{{{{BIDI_RLO}}}}`.
To test a scanner on these rows, fill them in with random values in the right format; `render()` in
[benchmark/run.py](https://github.com/kaymyg/ai-security-atlas/blob/main/benchmark/run.py) does exactly that.

## Composition

| Category | Rows | Unsafe | Safe look-alikes |
|---|---|---|---|
{composition}

ai-security-atlas v{version} on this set: **precision {precision}, recall {recall}**
([per-rule results](https://github.com/kaymyg/ai-security-atlas/blob/main/benchmark/RESULTS.md)).

## Limitations

- Small and hand-written: cases are realistic snippets, not code sampled from real repositories, so scores
  won't transfer exactly to any particular codebase.
- Labels are line-level and per-rule. A line can carry several rows (one per rule).
- Some rules have only a few cases; their individual numbers are rough.
- Four scanner checks can't be expressed as single lines (a repo-wide inventory summary and three live
  package-registry checks) and aren't included.

## Source

Generated from [`benchmark/cases/`](https://github.com/kaymyg/ai-security-atlas/tree/main/benchmark/cases)
by `tools/build_hf.py` and published automatically on every change. MIT licensed.
"""


def build_dataset(out: Path) -> Path:
    rows = dataset_rows()
    (out / "data").mkdir(parents=True, exist_ok=True)
    with open(out / "data" / "benchmark.jsonl", "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    comp = []
    for cat, label in CATEGORIES.items():
        sub = [r for r in rows if r["category"] == cat]
        if sub:
            unsafe = sum(r["is_unsafe"] for r in sub)
            comp.append(f"| {label} | {len(sub)} | {unsafe} | {len(sub) - unsafe} |")
    c = Counter(r["label"] for r in rows)
    tp, fp, fn = c["expect"], c["noisy"], c["miss"]
    card = DATASET_CARD.format(
        n_rows=len(rows), version=__version__, categories=", ".join(f"`{k}`" for k in CATEGORIES),
        composition="\n".join(comp), precision=f"{tp / (tp + fp):.0%}", recall=f"{tp / (tp + fn):.0%}",
    )
    (out / "README.md").write_text(card, encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    dest = Path(argv[1] if len(argv) > 1 else "build/hf").resolve()
    for sub in ("space", "dataset"):
        shutil.rmtree(dest / sub, ignore_errors=True)
    space = build_space(dest / "space")
    dataset = build_dataset(dest / "dataset")
    print(f"space   -> {space}")
    print(f"dataset -> {dataset}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
