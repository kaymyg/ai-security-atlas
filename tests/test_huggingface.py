"""Tests for the Hugging Face Space and dataset builds (no network, no real token)."""

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("hf")
    build = _load("build_hf", "tools/build_hf.py")
    build.main(["build_hf", str(out)])
    return out


def test_space_folder_is_complete(built):
    space = built / "space"
    for name in ("app.py", "demo_examples.py", "README.md", "LICENSE", "atlas_scan/__init__.py",
                 "atlas_scan/scanners/agents.py"):
        assert (space / name).is_file(), name
    assert not list(space.rglob("__pycache__"))
    readme = (space / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("---\n") and "sdk: gradio" in readme and "app_file: app.py" in readme


def test_dataset_matches_the_benchmark(built):
    rows = [json.loads(l) for l in (built / "dataset/data/benchmark.jsonl").read_text(encoding="utf-8").splitlines()]
    run = _load("bench_run", "benchmark/run.py")
    stats, problems, _, _ = run.grade()
    assert not problems
    expected = sum(s["tp"] + s["known_fp"] + s["known_fn"] + s["tn"] for s in stats.values())
    assert len(rows) == expected
    assert {r["label"] for r in rows} == {"expect", "safe", "miss", "noisy"}
    for r in rows:
        assert r["is_unsafe"] == (r["label"] in ("expect", "miss"))
        assert r["flagged_by_atlas"] == (r["label"] in ("expect", "noisy"))


def test_dataset_rows_hide_labels_secrets_and_invisible_characters(built):
    text = (built / "dataset/data/benchmark.jsonl").read_text(encoding="utf-8")
    for r in map(json.loads, text.splitlines()):
        assert not any(tag in r["code"] for tag in ("expect[", "safe[", "miss[", "noisy[")), r["id"]
    assert not any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 or ord(c) >= 0xE0000 for c in text)
    # Run the scanner's own secret detection over the published rows. The only hits allowed are the
    # known public look-alikes the benchmark labels "noisy" (jwt.io's sample JWT, a docs DB URL).
    from atlas_scan.models import SourceFile
    from atlas_scan.scanners.secrets import SecretScanner
    hits = {f.rule.id for f in SecretScanner().scan(SourceFile("benchmark.jsonl", "benchmark.jsonl", text))}
    assert hits <= {"SEC011", "SEC012"}, hits


def test_dataset_card_has_a_valid_config(built):
    card = (built / "dataset/README.md").read_text(encoding="utf-8")
    header = card.split("---")[1]
    assert "path: data/benchmark.jsonl" in header and "split: test" in header
    assert "{" not in card.split("## Placeholders")[0].replace("{{", "").replace("`{", "")  # template filled


def test_publish_needs_a_token(monkeypatch, built):
    publish = _load("publish_hf", "tools/publish_hf.py")
    monkeypatch.delenv("HF_TOKEN", raising=False)
    assert publish.main(["publish_hf", str(built)]) == 1


def test_publish_creates_and_mirrors_both_repos(monkeypatch, built):
    calls = []

    class FakeApi:
        def __init__(self, token):
            calls.append(("init", token))

        def whoami(self):
            return {"name": "Sahek"}

        def create_repo(self, repo_id, **kw):
            calls.append(("create", repo_id, kw.get("repo_type"), kw.get("exist_ok")))

        def upload_folder(self, **kw):
            calls.append(("upload", kw["repo_id"], kw["repo_type"], kw["delete_patterns"],
                          Path(kw["folder_path"]).name))

    monkeypatch.setitem(sys.modules, "huggingface_hub", types.SimpleNamespace(HfApi=FakeApi))
    monkeypatch.setenv("HF_TOKEN", "test-token")
    publish = _load("publish_hf", "tools/publish_hf.py")
    assert publish.main(["publish_hf", str(built)]) == 0
    assert ("create", "Sahek/ai-security-atlas", "space", True) in calls
    assert ("create", "Sahek/ai-security-atlas-benchmark", "dataset", True) in calls
    assert ("upload", "Sahek/ai-security-atlas", "space", "*", "space") in calls
    assert ("upload", "Sahek/ai-security-atlas-benchmark", "dataset", "*", "dataset") in calls


# ----------------------------------------------------------------- the web app (needs gradio)

@pytest.fixture(scope="module")
def app():
    pytest.importorskip("gradio")
    sys.path.insert(0, str(ROOT / "huggingface" / "space"))
    return _load("space_app", "huggingface/space/app.py")


@pytest.mark.parametrize("name,ok", [
    ("app.py", "app.py"), (".github/workflows/ci.yml", ".github/workflows/ci.yml"), ("./x.py", "x.py"),
    ("../etc/passwd", None), ("/etc/passwd", None), ("a/../../x", None), ("C:\\x\\y", None), ("", None),
    ("a\x00b", None),
])
def test_app_rejects_unsafe_file_names(app, name, ok):
    assert app.safe_relpath(name) == ok


def test_app_escapes_user_text(app):
    assert app.md("[x](https://evil)<img>") == r"\[x\]\(https://evil\)\<img\>"
    assert app.code_span("a`b") == "`a'b`"


def test_app_examples_all_produce_findings(app):
    from demo_examples import EXAMPLES
    for filename, code in EXAMPLES:
        report = app.scan_paste(filename, code, False, "low")
        assert report.startswith("### ") and "finding(s)" in report, filename


def test_app_limits(app):
    assert app.scan_paste("a.py", "x" * (app.MAX_PASTE_CHARS + 1), False, "low").startswith("⚠️")
    assert app.scan_paste("../a.py", "x", False, "low").startswith("⚠️")
    assert app.scan_uploads(None, False, "low").startswith("⚠️")
