"""Accuracy benchmark: grade the scanner against labelled examples.

    python benchmark/run.py            # print the scorecard
    python benchmark/run.py --write    # also regenerate benchmark/RESULTS.md
    python benchmark/run.py --check    # exit 1 on any regression or a stale RESULTS.md

How cases are labelled
----------------------
Put a label in a comment on the line it describes (several allowed):

    expect[VIBE013]   unsafe; the scanner must flag it        (true positive)
    safe[VIBE013]     safe look-alike; must NOT be flagged      (true negative)
    miss[VIBE013]     unsafe, but not caught yet               (known false negative)
    noisy[VIBE013]    safe, but flagged anyway                  (known false positive)

Files that can't hold comments (JSON, .env) get a sidecar file named
``<file>.expect`` with lines like ``expect[AGT003] "/"``: a label, then text
that identifies the line (the first line containing it).

Files ending in ``.tmpl`` are templates: ``{{AWS_KEY}}`` and friends are
replaced with random, key-shaped values at run time, so nothing secret-shaped
or invisible is ever stored in git. See ``PLACEHOLDERS`` below.

A finding with no label is "unexpected" and counts as a regression, so every
result has to be explained by a case.
"""

from __future__ import annotations

import argparse
import random
import re
import shutil
import string
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "src"))

from atlas_scan import __version__  # noqa: E402
from atlas_scan.engine import scan_path  # noqa: E402
from atlas_scan.models import CATEGORIES  # noqa: E402
from atlas_scan.scanners import all_rules  # noqa: E402

CASES = ROOT / "cases"
RESULTS = ROOT / "RESULTS.md"
LABEL = re.compile(r"\b(expect|safe|miss|noisy)\[([A-Z0-9, ]+)\]")
SIDECAR_LINE = re.compile(r"^\s*(expect|safe|miss|noisy)\[([A-Z0-9, ]+)\]\s+(.+?)\s*$")

# Rules that can't be graded offline from a single file. They're covered by
# unit tests instead (tests/test_deps.py, tests/test_crypto.py).
NOT_BENCHMARKED = {
    "PQC000": "repo-wide inventory summary, not a per-line finding",
    "SUP002": "needs a live registry (--online); unit-tested with a fake registry",
    "SUP003": "needs a live registry (--online); unit-tested with a fake registry",
    "SUP008": "needs a failing registry (--online); unit-tested",
}

_rng = random.Random(2026)


def _rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _hidden(text: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in text)


UPPER = string.ascii_uppercase + string.digits
PLACEHOLDERS = {
    "AWS_KEY": lambda: "AKIA" + _rand(16, UPPER),
    "GITHUB_TOKEN": lambda: "ghp_" + _rand(36),
    "GITHUB_PAT": lambda: "github_pat_" + _rand(70, string.ascii_letters + string.digits + "_"),
    "ANTHROPIC_KEY": lambda: "sk-ant-api03-" + _rand(40),
    "OPENAI_KEY": lambda: "sk-proj-" + _rand(48),
    "STRIPE_LIVE": lambda: "sk_" + "live_" + _rand(28),
    "GOOGLE_KEY": lambda: "AIza" + _rand(35),
    "HF_TOKEN": lambda: "hf_" + _rand(34, string.ascii_letters),
    "SLACK_TOKEN": lambda: "xoxb-" + _rand(12, string.digits) + "-" + _rand(24),
    "SLACK_WEBHOOK": lambda: "https://hooks.slack.com/services/T" + _rand(9, UPPER) + "/B" + _rand(9, UPPER)
                             + "/" + _rand(24),
    # Slack's documentation placeholder. GitHub push protection blocks even this, so it's built at run time.
    "SLACK_WEBHOOK_DOCS": lambda: "https://hooks.slack.com/services/" + "T" + "0" * 8 + "/B" + "0" * 8 + "/" + "X" * 24,
    "JWT": lambda: "eyJ" + _rand(20) + ".eyJ" + _rand(30) + "." + _rand(30),
    "RANDOM32": lambda: _rand(32),
    "RANDOM16": lambda: _rand(16),
    "HEX64": lambda: _rand(64, "0123456789abcdef"),
    "PEM_PRIVATE": lambda: "-----BEGIN RSA " + "PRIVATE KEY-----",
    "BIDI_RLO": lambda: chr(0x202E),  # right-to-left override
    "BIDI_LRI": lambda: chr(0x2066),  # left-to-right isolate
    "BIDI_PDI": lambda: chr(0x2069),  # pop directional isolate
    "ZWSP": lambda: chr(0x200B),      # zero-width space
    "ZWJ": lambda: chr(0x200D),       # zero-width joiner
    "VS_RUN": lambda: "".join(chr(0xE0100 + i) for i in range(8)),
}
_PLACEHOLDER = re.compile(r"\{\{(HIDDEN:([^}]*)|[A-Z0-9_]+)\}\}")


def render(text: str) -> str:
    def sub(m: re.Match) -> str:
        if m.group(2) is not None:
            return _hidden(m.group(2))
        name = m.group(1)
        if name not in PLACEHOLDERS:
            raise KeyError(f"unknown placeholder {{{{{name}}}}}")
        return PLACEHOLDERS[name]()
    return _PLACEHOLDER.sub(sub, text)


# ----------------------------------------------------------------- loading

def _drop_notes(text: str) -> str:
    """Cut human notes written after the last label on a line, so words in a
    note ("user", "secp256k1"...) can never trigger or suppress a rule.
    HTML comments keep their closing ``-->``."""
    out = []
    for line in text.split("\n"):
        last = None
        for last in LABEL.finditer(line):
            pass
        if last is not None:
            tail = " -->" if "<!--" in line[: last.start()] else ""
            line = line[: last.end()] + tail
        out.append(line)
    return "\n".join(out)

def prepare(dest: Path) -> dict[tuple[str, int], dict[str, set[str]]]:
    """Copy cases into ``dest`` (rendering templates) and return the labels:
    {(path, line): {"expect": {...}, "safe": {...}, "miss": {...}, "noisy": {...}}}"""
    labels: dict[tuple[str, int], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    sidecars: list[tuple[Path, str]] = []

    for src in sorted(CASES.rglob("*")):
        if src.is_dir():
            continue
        rel = src.relative_to(CASES).as_posix()
        if rel.endswith(".expect"):
            sidecars.append((src, rel[: -len(".expect")]))
            continue
        text = src.read_text(encoding="utf-8")
        if rel.endswith(".tmpl"):
            rel = rel[: -len(".tmpl")]
            text = render(text)
        text = _drop_notes(text)
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            for kind, ids in LABEL.findall(line):
                labels[(rel, i)][kind].update(x.strip() for x in ids.split(",") if x.strip())

    for sidecar, target in sidecars:
        target_rel = target[: -len(".tmpl")] if target.endswith(".tmpl") else target
        lines = (dest / target_rel).read_text(encoding="utf-8").splitlines()
        for raw in sidecar.read_text(encoding="utf-8").splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            m = SIDECAR_LINE.match(raw)
            if not m:
                raise ValueError(f"{sidecar.name}: can't read label line: {raw!r}")
            kind, ids, needle = m.groups()  # needle is matched literally, quotes included
            line_no = next((i for i, l in enumerate(lines, 1) if needle in l), None)
            if line_no is None:
                raise ValueError(f"{sidecar.name}: no line contains {needle!r}")
            labels[(target_rel, line_no)][kind].update(x.strip() for x in ids.split(","))
    return labels


# ----------------------------------------------------------------- grading

def grade():
    with tempfile.TemporaryDirectory(prefix="atlas-bench-") as tmp:
        labels = prepare(Path(tmp))
        result = scan_path(tmp)

    found: dict[tuple[str, int], set[str]] = defaultdict(set)
    for f in result.findings:
        if f.path != ".":  # repo-wide summaries aren't per-line
            found[(f.path, f.line)].add(f.rule.id)

    stats = defaultdict(lambda: defaultdict(int))
    problems: list[str] = []   # regressions: these fail --check
    news: list[str] = []       # good news: a known miss/noise has gone away

    for (path, line), kinds in labels.items():
        hit = found.get((path, line), set())
        where = f"{path}:{line}"
        for rid in kinds["expect"]:
            if rid in hit:
                stats[rid]["tp"] += 1
            else:
                stats[rid]["fn_regression"] += 1
                problems.append(f"MISSED  {rid} at {where} (labelled expect)")
        for rid in kinds["safe"]:
            stats[rid]["tn"] += 1
            if rid in hit:
                stats[rid]["fp_regression"] += 1
                problems.append(f"FLAGGED {rid} at {where} (labelled safe)")
        for rid in kinds["miss"]:
            if rid in hit:
                stats[rid]["tp"] += 1
                news.append(f"NOW CAUGHT {rid} at {where}: relabel miss -> expect")
            else:
                stats[rid]["known_fn"] += 1
        for rid in kinds["noisy"]:
            if rid in hit:
                stats[rid]["known_fp"] += 1
            else:
                stats[rid]["tn"] += 1
                news.append(f"NO LONGER NOISY {rid} at {where}: relabel noisy -> safe")

    for (path, line), ids in found.items():
        labelled = set().union(*labels[(path, line)].values()) if (path, line) in labels else set()
        for rid in ids - labelled:
            stats[rid]["unexpected"] += 1
            problems.append(f"UNEXPECTED {rid} at {path}:{line} (no label: add expect/noisy)")

    return stats, sorted(problems), sorted(news), len({p for p, _ in labels})


def metrics(s: dict) -> tuple[int, int, int, int, str, str]:
    tp = s["tp"]
    fp = s["known_fp"] + s["fp_regression"] + s["unexpected"]
    fn = s["known_fn"] + s["fn_regression"]
    tn = s["tn"] - s["fp_regression"]
    prec = f"{tp / (tp + fp):.0%}" if tp + fp else "–"
    rec = f"{tp / (tp + fn):.0%}" if tp + fn else "–"
    return tp, fp, fn, tn, prec, rec


def render_results(stats, n_files: int) -> str:
    rules = all_rules()
    total = defaultdict(int)
    body: list[str] = []
    for cat, label in CATEGORIES.items():
        body += [f"## {label}", "", "| Rule | TP | FP | FN | TN | Precision | Recall | Notes |",
                 "|---|---|---|---|---|---|---|---|"]
        for r in [r for r in rules if r.category == cat]:
            if r.id in NOT_BENCHMARKED:
                body.append(f"| {r.id} | | | | | | | not benchmarked: {NOT_BENCHMARKED[r.id]} |")
                continue
            s = stats.get(r.id)
            if not s:
                body.append(f"| {r.id} | | | | | | | ⚠️ no cases yet |")
                continue
            tp, fp, fn, tn, prec, rec = metrics(s)
            for k, v in zip(("tp", "fp", "fn", "tn"), (tp, fp, fn, tn)):
                total[k] += v
            note = []
            if s["known_fn"]:
                note.append(f"{s['known_fn']} known miss")
            if s["known_fp"]:
                note.append(f"{s['known_fp']} known false alarm")
            if not tn:
                note.append("no safe look-alike yet")
            body.append(f"| {r.id} | {tp} | {fp} | {fn} | {tn} | {prec} | {rec} | {', '.join(note)} |")
        body.append("")

    tp, fp, fn = total["tp"], total["fp"], total["fn"]
    overall = (f"**Overall:** {tp} caught, {fp} false alarms, {fn} missed, {total['tn']} safe look-alikes "
               f"left alone → precision {tp / max(tp + fp, 1):.0%}, recall {tp / max(tp + fn, 1):.0%}.")
    header = [
        "# Benchmark results",
        "",
        f"Scanner version {__version__}, graded against {n_files} labelled case files in `benchmark/cases/`.",
        "Generated by `python benchmark/run.py --write`; don't edit by hand.",
        "",
        overall,
        "",
        "**How to read this.** *Precision* = of the times a rule fired, how often it was right. "
        "*Recall* = of the unsafe cases, how many it caught. Both are measured only on these hand-written "
        "cases, which deliberately include tricky look-alikes and known blind spots. They show where each "
        "rule stands, not how it will do on every real codebase. Rules with few cases have rough numbers.",
        "",
        "Columns: **TP** caught correctly · **FP** false alarms · **FN** missed · **TN** safe look-alikes "
        "correctly left alone.",
        "",
    ]
    return "\n".join(header + body).rstrip() + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--write", action="store_true", help="regenerate benchmark/RESULTS.md")
    ap.add_argument("--check", action="store_true", help="fail on regressions or a stale RESULTS.md")
    args = ap.parse_args(argv)

    stats, problems, news, n_files = grade()
    report = render_results(stats, n_files)
    print(report.split("\n## ")[0].strip(), "\n")
    for p in problems:
        print("✗", p)
    for n in news:
        print("★", n)

    if args.write:
        RESULTS.write_text(report, encoding="utf-8")
        print(f"wrote {RESULTS.relative_to(ROOT.parent)}")
    if args.check:
        stale = not RESULTS.exists() or RESULTS.read_text(encoding="utf-8") != report
        if stale:
            print("✗ benchmark/RESULTS.md is stale: run `python benchmark/run.py --write`")
        if problems or news or stale:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
