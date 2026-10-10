import random
import string

import pytest

from atlas_scan.engine import scan_path


@pytest.fixture
def scan(tmp_path):
    """Write files into a temp folder, scan it, and return the findings.

    Usage: findings = scan({"app.py": "...", "sub/x.js": "..."})
    """

    calls = {"n": 0}

    def _scan(files, **kwargs):
        calls["n"] += 1
        root = tmp_path / f"repo{calls['n']}"  # fresh folder per call
        root.mkdir()
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return scan_path(str(root), **kwargs).findings

    return _scan


def ids(findings):
    return sorted({f.rule.id for f in findings})


def fake(n, alphabet=string.ascii_letters + string.digits, seed=7):
    """Random key-like text, built at run time so no secret shapes live in git."""
    rng = random.Random(seed + n)
    return "".join(rng.choice(alphabet) for _ in range(n))
