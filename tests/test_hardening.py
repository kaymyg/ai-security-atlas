"""Tests for the v0.2.0 hardening work (see the repository audit)."""

import io
import json
import urllib.error

import pytest

from atlas_scan.cli import main
from atlas_scan.engine import scan_path
from atlas_scan.models import Finding, Rule, Severity
from atlas_scan.reporters import FORMATS
from atlas_scan.scanners import Scanner, default_scanners
from atlas_scan.scanners.deps import Registry, http_json
from atlas_scan.walker import is_ignored

from conftest import fake, ids


def write(root, files):
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


# --------------------------------------------------------------- finding kinds

def test_every_rule_has_a_kind():
    from atlas_scan.scanners import all_rules
    assert {r.kind for r in all_rules()} == {"vulnerability", "misconfiguration", "inventory"}


def test_quantum_usage_is_inventory_not_vulnerability(scan):
    findings = scan({"a.py": "padding.OAEP(mgf=m, algorithm=a, label=None)\nX25519PrivateKey.generate()\n"})
    assert {f.rule.kind for f in findings} == {"inventory"}
    assert all(f.severity <= Severity.LOW for f in findings)


def test_inventory_never_fails_the_build(tmp_path, capsys):
    write(tmp_path, {"a.py": "rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"})
    assert main(["scan", str(tmp_path), "--fail-on", "info", "--min-severity", "info"]) == 0
    write(tmp_path, {"b.py": "hashlib.md5(x)\n"})  # broken today: a real vulnerability
    assert main(["scan", str(tmp_path), "--fail-on", "info"]) == 1


def test_json_counts_by_kind(tmp_path, capsys):
    write(tmp_path, {"a.py": "pickle.loads(x)\napp.run(debug=True)\n"})
    main(["scan", str(tmp_path), "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["counts_by_kind"] == {"vulnerability": 1, "misconfiguration": 1, "inventory": 0}
    assert {f["kind"] for f in data["findings"]} == {"vulnerability", "misconfiguration"}


# --------------------------------------------------------------- masking

@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_secrets_never_appear_in_any_format(fmt, tmp_path):
    visible = "ghp_" + fake(36)
    silenced = "sk-ant-api03-" + fake(40)
    write(tmp_path, {"a.py": f'TOKEN = "{visible}"\nKEY = "{silenced}"  # atlas: ignore\n',
                     ".mcp.json": json.dumps({"mcpServers": {"x": {"command": "node",
                                                                    "env": {"API_TOKEN": fake(30)}}}})})
    result = scan_path(str(tmp_path))
    assert result.findings and result.suppressed_findings
    report = FORMATS[fmt](result) if fmt != "text" else FORMATS[fmt](result, color=False)
    assert visible not in report
    assert silenced not in report
    assert fake(30) not in report


# --------------------------------------------------------------- error paths

class Exploding(Scanner):
    name = "exploding"
    category = "vibe-code"

    def applies(self, src):
        return True

    def scan(self, src):
        raise ValueError(f"boom while reading {src.text}")  # message contains file content


def test_a_crashing_scanner_does_not_stop_the_scan_or_leak_content(tmp_path):
    secret = "ghp_" + fake(36)
    write(tmp_path, {"a.py": f'T = "{secret}"\n'})
    result = scan_path(str(tmp_path), scanners=[Exploding()] + default_scanners())
    assert "SEC002" in ids(result.findings)  # other scanners still ran
    assert result.errors == [{"scanner": "exploding", "path": "a.py", "error": "ValueError"}]
    assert result.warnings
    for fmt, render in FORMATS.items():
        out = render(result) if fmt != "text" else render(result, color=False)
        assert secret not in out
    sarif = json.loads(FORMATS["sarif"](result))
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False


# --------------------------------------------------------------- suppression audit

def test_suppressed_findings_are_reported(tmp_path, capsys):
    write(tmp_path, {"a.py": "requests.get(u, verify=False)  # atlas: ignore\n"})
    assert main(["scan", str(tmp_path), "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []
    assert [f["rule_id"] for f in data["suppressed_findings"]] == ["VIBE016"]

    main(["scan", str(tmp_path), "--no-color"])
    assert "Silenced by 'atlas: ignore': VIBE016 a.py:1" in capsys.readouterr().out

    sarif_out = tmp_path / "r.sarif"
    main(["scan", str(tmp_path), "-f", "sarif", "-o", str(sarif_out)])
    results = json.loads(sarif_out.read_text())["runs"][0]["results"]
    assert results[0]["suppressions"][0]["kind"] == "inSource"


def test_exclusions_are_counted_and_shown(tmp_path, capsys):
    write(tmp_path, {"src/app.py": "print(1)\n", "fixtures/a.py": "pickle.loads(x)\n",
                     "fixtures/b.py": "pickle.loads(x)\n", ".atlasignore": "fixtures\n"})
    main(["scan", str(tmp_path), "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["exclusions"] == {"fixtures": 2}
    assert data["findings"] == []


def test_excluding_everything_is_an_error_not_a_clean_pass(tmp_path, capsys):
    write(tmp_path, {"a.py": "pickle.loads(x)\n"})
    assert main(["scan", str(tmp_path), "--exclude", "*"]) == 2
    assert "excluded every file" in capsys.readouterr().err


def test_broad_pattern_warning(tmp_path):
    write(tmp_path, {f"gen/f{i}.py": "x = 1\n" for i in range(12)} | {"main.py": "x = 1\n"})
    result = scan_path(str(tmp_path), extra_ignores=["gen"])
    assert any("'gen' excludes 12 of 13" in w for w in result.warnings)


def test_double_star_pattern_matches_top_level():
    assert is_ignored(".mcp.json", ["**/.mcp.json"])
    assert is_ignored("a/b/.mcp.json", ["**/.mcp.json"])
    assert not is_ignored("mcp.json", ["**/.mcp.json"])


# --------------------------------------------------------------- registry states

def _http_error(code, headers=None):
    return urllib.error.HTTPError("https://x", code, "err", headers or {}, io.BytesIO(b""))


def test_rate_limit_is_retried_then_succeeds(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise _http_error(429, {"Retry-After": "1"})
        return io.BytesIO(b'{"ok": true}')

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    slept = []
    assert http_json("https://x", sleep=slept.append) == {"ok": True}
    assert slept == [1.0]


def test_persistent_rate_limit_is_unknown_not_missing(monkeypatch):
    def always_429(req, timeout):
        raise _http_error(429)

    monkeypatch.setattr("urllib.request.urlopen", always_429)
    with pytest.raises(urllib.error.HTTPError):
        http_json("https://x", sleep=lambda s: None)
    reg = Registry(fetch=lambda url: http_json(url, sleep=lambda s: None))
    assert reg.lookup("pypi", "flask") is None  # unknown


def test_404_means_missing(monkeypatch):
    def not_found(req, timeout):
        raise _http_error(404)

    monkeypatch.setattr("urllib.request.urlopen", not_found)
    assert Registry().lookup("npm", "nope") == (False, None)


def test_circuit_breaker_stops_asking_when_offline():
    calls = []

    def offline(url):
        calls.append(url)
        raise OSError("no network")

    reg = Registry(fetch=offline)
    for name in ["a", "b", "c", "d", "e", "f"]:
        assert reg.lookup("pypi", name) is None
    assert len(calls) == Registry.MAX_FAILURES


# --------------------------------------------------------------- CLI argument safety

def test_double_dash_separates_path(tmp_path):
    write(tmp_path, {"-weird.py": "print(1)\n"})
    assert main(["scan", "--fail-on", "high", "--", str(tmp_path)]) == 0
