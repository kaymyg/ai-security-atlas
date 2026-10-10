# How it works

A guided tour of the code, written for someone learning. Read the files in this order and the whole tool makes sense in about an hour.

## The big picture

```
atlas scan .
   │
   ▼
cli.py ──► engine.scan_path()
              │
              ├─ walker.iter_files()      which files? (skips node_modules, binaries, .atlasignore)
              │
              ├─ for each file, for each scanner:
              │     scanner.applies(file)  is this file relevant to me?
              │     scanner.scan(file)     return a list of Findings
              │
              ├─ drop findings silenced by "atlas: ignore" comments
              ├─ scanner.finish()          whole-repo results (the crypto inventory)
              ▼
          ScanResult ──► reporters.py ──► text / JSON / SARIF / Markdown
```

One idea holds it together: **a scanner turns a file into a list of `Finding`s.** Scanners don't read the disk, print anything or know about each other. That makes each one small and easy to test.

## 1. `models.py`: the vocabulary

- `Severity`: an ordered enum, so `Severity.HIGH > Severity.LOW` works.
- `Rule`: what a check is (id, title, severity, category, fix, CWE).
- `Finding`: one hit (which rule, which file, which line, a snippet).
- `SourceFile`: a file loaded once and shared with every scanner. `line_of(offset)` turns a regex match position into a line and column.

## 2. `walker.py`: choosing files

`os.walk` over the folder, pruning junk folders *before* descending (much faster than filtering afterwards). A file counts as binary if its first 8 KB contain a zero byte; that simple test is surprisingly reliable.

## 3. `scanners/`: the checks

| File | Technique worth learning |
|---|---|
| `code.py` | `PatternRule`: a regex plus file types plus an `unless` regex for safe variants (`yaml.load(..., Loader=SafeLoader)` is fine) |
| `secrets.py` | Shannon **entropy**: random keys look "busier" than words. `entropy("password123")` ≈ 3.3, a real key ≈ 4.5+. Also *masking* so reports never leak what they find |
| `deps.py` | **Edit distance** (Damerau-Levenshtein) for typosquats; parsing three manifest formats; an injectable `fetch` function so tests never touch the network |
| `agents.py` | Parsing JSON configs as data instead of regex; decoding invisible Unicode tag characters (`chr(ord(c) - 0xE0000)`) |
| `crypto.py` | `finish()`: collecting state across files to build an inventory |

## 4. `engine.py`: suppressions

`atlas: ignore` comments are read per file into a table of `line → rule ids`. A comment on its own line protects the next line. `atlas: ignore-file` skips the file but the file is still named in the report, because a silent skip would be a perfect hiding place for malicious code.

## 5. `reporters.py`: output formats

**SARIF** is the standard JSON format for static-analysis results. GitHub reads it to show findings in the Security tab, so supporting it gives this tool a professional UI for free.

## Add your own rule (10 minutes)

Say you want to flag Python's `tempfile.mktemp()` (it has a race condition).

1. Open `src/atlas_scan/scanners/code.py` and add to `_rules`:

   ```python
   R(Rule("VIBE020", "Insecure temporary file (mktemp)", Severity.MEDIUM, C,
          "Use tempfile.mkstemp() or NamedTemporaryFile().", "CWE-377"),
     r"\btempfile\.mktemp\s*\(", PY),
   ```

2. Add a test in `tests/test_code.py`:

   ```python
   def test_mktemp(scan):
       assert "VIBE020" in ids(scan({"a.py": "p = tempfile.mktemp()\n"}))
       assert scan({"b.py": "fd, p = tempfile.mkstemp()\n"}) == []
   ```

3. Regenerate the rules doc and run the tests:

   ```bash
   python tools/gen_rules_doc.py
   pytest -q
   ```

Always test the safe version too. A rule that fires on safe code teaches people to ignore the tool.

## Dogfooding

CI scans this repo with its own GitHub Action. The first run found a real bug: the `pyproject.toml` parser treated `authors` and `keywords` lists as dependencies. That's the value of running your tool on yourself.
