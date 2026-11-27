import json
from datetime import datetime, timedelta, timezone

from atlas_scan.engine import scan_path
from atlas_scan.scanners.deps import DependencyScanner, Registry, distance, squat_target

from conftest import ids


def test_distance():
    assert distance("requests", "requests") == 0
    assert distance("reqeusts", "requests") == 1  # swapped letters count as one edit
    assert distance("expresss", "express") == 1
    assert distance("abc", "xyzxyzxyz") > 2


def test_squat_target():
    popular = {"requests", "express", "python-dateutil"}
    assert squat_target("reqeusts", popular) == "requests"
    assert squat_target("requests", popular) is None
    assert squat_target("python-dateutl", popular) == "python-dateutil"
    assert squat_target("numpy", popular) is None


def test_typosquats_in_manifests(scan):
    findings = scan({
        "requirements.txt": "reqeusts==2.31.0\nnumpy==2.0.0\n",
        "package.json": json.dumps({"dependencies": {"lodahs": "^4.0.0", "react": "^18.0.0"}}),
    })
    squats = {f.extra["package"] for f in findings if f.rule.id == "SUP001"}
    assert squats == {"reqeusts", "lodahs"}


def test_pypi_name_normalisation_is_not_a_squat(scan):
    assert scan({"requirements.txt": "python_dotenv==1.0.0\nPyYAML==6.0\n"}) == []


def test_unpinned_and_url_dependencies(scan):
    found = ids(scan({
        "requirements.txt": "flask\ngit+https://github.com/a/b.git\n",
        "package.json": json.dumps({"dependencies": {"axios": "*", "x": "github:a/x"}}),
    }))
    assert found == ["SUP004", "SUP005"]


def test_pyproject_only_reads_dependency_lists(scan):
    text = (
        '[project]\nname = "x"\nauthors = [{ name = "someone" }]\nkeywords = ["security"]\n'
        'dependencies = [\n  "reqeusts>=2",\n  "rich>=13",\n]\n'
        '[project.optional-dependencies]\ndev = ["pytest"]\n'
    )
    findings = scan({"pyproject.toml": text})
    assert {(f.rule.id, f.extra.get("package")) for f in findings} == {("SUP001", "reqeusts"), ("SUP004", None)}


def test_pipe_to_shell_and_action_pinning(scan):
    wf = ("steps:\n  - uses: actions/checkout@v4\n  - uses: someone/tool@v1\n"
          "  - uses: someone/pinned@0123456789abcdef0123456789abcdef01234567\n"
          "  - run: curl -sSL https://x.dev/i.sh | bash\n")
    findings = scan({".github/workflows/ci.yml": wf})
    assert ids(findings) == ["SUP006", "SUP007"]
    # actions/checkout@v4 and someone/tool@v1 are both movable tags; the SHA pin is fine.
    assert sum(f.rule.id == "SUP007" for f in findings) == 2


def test_online_check_finds_missing_and_new_packages(tmp_path):
    now = datetime(2026, 10, 10, tzinfo=timezone.utc)
    registry = {
        "https://pypi.org/pypi/flask/json": {"releases": {"3.0": [{"upload_time_iso_8601": "2010-04-06T00:00:00Z"}]}},
        "https://pypi.org/pypi/brand-new-ai-helper/json": {
            "releases": {"0.1": [{"upload_time_iso_8601": (now - timedelta(days=3)).isoformat()}]}},
    }
    (tmp_path / "requirements.txt").write_text(
        "flask==3.0\nbrand-new-ai-helper==0.1\nmade-up-package-xyz==1.0\n")
    scanner = DependencyScanner(online=True, registry=Registry(fetch=registry.get), now=lambda: now)
    findings = scan_path(str(tmp_path), scanners=[scanner]).findings
    got = {(f.rule.id, f.extra.get("package")) for f in findings}
    assert ("SUP002", "made-up-package-xyz") in got
    assert ("SUP003", "brand-new-ai-helper") in got
    assert not any(p == "flask" for _, p in got)


def test_online_check_survives_network_errors(tmp_path):
    def broken(url):
        raise OSError("offline")

    (tmp_path / "requirements.txt").write_text("flask==3.0\nrich==13.0\n")
    scanner = DependencyScanner(online=True, registry=Registry(fetch=broken))
    findings = scan_path(str(tmp_path), scanners=[scanner]).findings
    # Unknown is reported as unknown, never as "missing".
    assert [f.rule.id for f in findings] == ["SUP008"]
    assert findings[0].extra["packages"] == ["pypi:flask", "pypi:rich"]
    assert findings[0].rule.kind == "inventory"


def test_registry_rejects_names_that_could_rewrite_the_url():
    """REGRESSION: names were only partly escaped, so a crafted manifest entry
    such as "evil/../requests" or ".." could resolve to a different registry
    URL and be reported as an existing package, hiding a fake dependency."""
    seen = []

    def fetch(url):
        seen.append(url)
        return {"releases": {}, "time": {}}  # any URL "exists"

    reg = Registry(fetch=fetch)
    for eco, name in [("npm", ".."), ("npm", "."), ("npm", "a/../lodash"),
                      ("pypi", "evil/../requests"), ("pypi", "x?y"), ("pypi", "")]:
        assert reg.lookup(eco, name) == (False, None), (eco, name)
    assert seen == [], "invalid names must never reach the network"

    assert reg.lookup("npm", "@types/node")[0] is True
    assert seen[-1] == "https://registry.npmjs.org/@types%2Fnode"
    assert reg.lookup("pypi", "requests")[0] is True
    assert seen[-1] == "https://pypi.org/pypi/requests/json"


def test_crafted_package_json_name_is_reported_missing(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"..": "1.0.0"}}')
    scanner = DependencyScanner(online=True, registry=Registry(fetch=lambda url: {"time": {}}))
    findings = scan_path(str(tmp_path), scanners=[scanner]).findings
    assert ("SUP002", "..") in {(f.rule.id, f.extra.get("package")) for f in findings}
