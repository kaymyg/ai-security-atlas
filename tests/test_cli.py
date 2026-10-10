import json

from atlas_scan.cli import main

from conftest import ids


def write(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def test_exit_codes(tmp_path, capsys):
    write(tmp_path, {"a.py": "requests.get(u, verify=False)\n"})
    assert main(["scan", str(tmp_path)]) == 1                       # high finding, default --fail-on high
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 0
    assert main(["scan", str(tmp_path), "--fail-on", "never"]) == 0
    assert main(["scan", str(tmp_path / "missing")]) == 2


def test_clean_folder_passes(tmp_path, capsys):
    write(tmp_path, {"a.py": "print('hello')\n"})
    assert main(["scan", str(tmp_path)]) == 0
    assert "No issues found" in capsys.readouterr().out


def test_json_and_sarif_output(tmp_path, capsys):
    write(tmp_path, {"a.py": "pickle.loads(x)\nhashlib.sha1(x)\n"})
    main(["scan", str(tmp_path), "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert {f["rule_id"] for f in data["findings"]} == {"VIBE014", "PQC001"}
    assert data["crypto_inventory"]["MD5/SHA-1"] == ["a.py"]

    out = tmp_path / "r.sarif"
    main(["scan", str(tmp_path), "-f", "sarif", "-o", str(out)])
    sarif = json.loads(out.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_inline_ignore(scan):
    code = ("requests.get(u, verify=False)  # atlas: ignore\n"
            "# atlas: ignore[VIBE014]\n"
            "pickle.loads(x)\n"
            "yaml.load(f)  # atlas: ignore[VIBE014]\n")
    assert ids(scan({"a.py": code})) == ["VIBE015"]


def test_ignore_file_and_atlasignore(tmp_path, capsys):
    write(tmp_path, {
        "gen.py": "# atlas: ignore-file\npickle.loads(x)\n",
        "fixtures/bad.py": "pickle.loads(x)\n",
        ".atlasignore": "fixtures\n",
    })
    assert main(["scan", str(tmp_path), "-f", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []
    assert data["skipped_files"] == ["gen.py"]


def test_only_filter(tmp_path, capsys):
    write(tmp_path, {"a.py": "pickle.loads(x)\nhashlib.md5(x)\n"})
    main(["scan", str(tmp_path), "--only", "quantum", "-f", "json"])
    assert {f["category"] for f in json.loads(capsys.readouterr().out)["findings"]} == {"quantum"}
    assert main(["scan", str(tmp_path), "--only", "nope"]) == 2


def test_rules_command(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "SEC001" in out and "AGT001" in out and "PQC010" in out
