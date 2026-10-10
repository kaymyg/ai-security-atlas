import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_rules_doc_is_up_to_date():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "tools" / "gen_rules_doc.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    current = (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8")
    assert current == gen.render(), "docs/RULES.md is stale: run `python tools/gen_rules_doc.py`"
