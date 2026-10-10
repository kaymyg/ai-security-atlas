import json
import string

from atlas_scan.engine import ScanResult
from atlas_scan.reporters import to_json, to_sarif
from atlas_scan.scanners.secrets import entropy, looks_placeholder, mask

from conftest import fake, ids

UPPER = string.ascii_uppercase + string.digits


def test_provider_keys_are_found(scan):
    code = "\n".join([
        f'aws = "{"AKIA" + fake(16, UPPER)}"',
        f'gh = "{"ghp_" + fake(36)}"',
        f'anthropic = "{"sk-ant-api03-" + fake(40)}"',
        f'openai = "{"sk-proj-" + fake(48)}"',
        f'stripe = "{"sk_" + "live_" + fake(28)}"',
        f'google = "{"AIza" + fake(35)}"',
        f'hf = "{"hf_" + fake(34, string.ascii_letters)}"',
        f'db = "postgres://admin:{fake(14)}@db:5432/prod"',
        f'WALLET_PRIVATE_KEY = "0x{fake(64, "0123456789abcdef")}"',
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----",  # split so the repo never holds a key header
    ])
    found = ids(scan({"settings.py": code}))
    for rule in ["SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC009", "SEC010", "SEC012",
                 "SEC013"]:
        assert rule in found, rule


def test_anthropic_key_is_not_also_reported_as_openai(scan):
    findings = scan({"a.py": f'k = "{"sk-ant-api03-" + fake(40)}"'})
    assert ids(findings) == ["SEC003"]


def test_placeholders_are_ignored(scan):
    code = "\n".join([
        'OPENAI_API_KEY = "sk-your-openai-key-goes-here-xxxxxxxxxxxx"',
        'api_key = "<YOUR_API_KEY>"',
        'password = os.environ["DB_PASSWORD"]',
        'token = "${GITHUB_TOKEN}"',
        'secret = "changeme-changeme-changeme"',
        'url = f"postgres://{user}:{password}@{host}/db"',
        'url = "mysql://root:%s@localhost/app" % pw',
    ])
    assert scan({"config.py": code}) == []


def test_generic_secret_needs_high_entropy(scan):
    low = 'client_secret = "aaaabbbbaaaabbbb"'
    high = f'client_secret = "{fake(32)}"'
    assert scan({"a.py": low}) == []
    assert ids(scan({"b.py": high})) == ["SEC020"]


def test_secrets_are_masked_in_every_report(scan):
    key = "ghp_" + fake(36)
    findings = scan({"a.py": f'TOKEN = "{key}"'})
    result = ScanResult(findings=findings, files_scanned=1)
    assert key not in to_json(result)
    assert key not in to_sarif(result)
    assert key not in findings[0].snippet
    assert json.loads(to_json(result))["findings"][0]["extra"]["secret"].startswith("ghp_")


def test_env_file_flagged_unless_gitignored(scan):
    env = f"API_KEY={fake(30)}\n"
    assert "SEC030" in ids(scan({".env": env}))
    assert "SEC030" not in ids(scan({".env": env, ".gitignore": ".env\n"}))


def test_example_env_files_are_skipped(scan):
    assert scan({".env.example": "OPENAI_API_KEY=\nDEBUG=true\n"}) == []


def test_helpers():
    assert entropy("aaaa") == 0
    assert entropy(fake(32)) > 4
    assert looks_placeholder("your-key-here")
    assert not looks_placeholder(fake(20))
    assert mask("abcdefghijkl") == "abcd…******"
