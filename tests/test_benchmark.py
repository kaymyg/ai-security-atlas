"""The accuracy benchmark is part of the test suite.

Any change that makes a labelled case fail (a missed `expect`, a flagged
`safe`, an unlabelled finding) or leaves benchmark/RESULTS.md stale fails here.
"""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_runner():
    spec = importlib.util.spec_from_file_location("bench_run", ROOT / "benchmark" / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_benchmark_has_no_regressions():
    run = _load_runner()
    stats, problems, news, n_files = run.grade()
    assert not problems, "benchmark regressions:\n" + "\n".join(problems)
    assert not news, "a known miss/noise changed; relabel it:\n" + "\n".join(news)
    assert n_files > 20


def test_benchmark_results_file_is_current():
    run = _load_runner()
    stats, _, _, n_files = run.grade()
    current = (ROOT / "benchmark" / "RESULTS.md").read_text(encoding="utf-8")
    assert current == run.render_results(stats, n_files), \
        "benchmark/RESULTS.md is stale: run `python benchmark/run.py --write`"


def test_every_rule_has_cases_or_a_reason():
    run = _load_runner()
    stats, _, _, _ = run.grade()
    from atlas_scan.scanners import all_rules
    uncovered = [r.id for r in all_rules() if r.id not in stats and r.id not in run.NOT_BENCHMARKED]
    assert not uncovered, f"rules with no benchmark cases: {uncovered}"


def test_notes_after_labels_cannot_affect_scanning():
    run = _load_runner()
    out = run._drop_notes("x = 1  # safe[SEC020] mentions user and secp256k1\n<!-- expect[AGT030] note -->")
    assert out == "x = 1  # safe[SEC020]\n<!-- expect[AGT030] -->"


def test_templates_render_without_leftover_placeholders():
    run = _load_runner()
    for tmpl in (ROOT / "benchmark" / "cases").rglob("*.tmpl"):
        assert "{{" not in run.render(tmpl.read_text(encoding="utf-8")), tmpl
