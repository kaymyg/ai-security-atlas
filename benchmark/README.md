# Accuracy benchmark

A folder of small, hand-labelled examples that the scanner is graded against. It answers "how good is each rule?" with numbers instead of guesses, and stops accuracy from quietly getting worse.

```bash
python benchmark/run.py            # print the scorecard and any problems
python benchmark/run.py --write    # regenerate RESULTS.md after an intended change
python benchmark/run.py --check    # what CI runs: fails on any regression
```

Results: **[RESULTS.md](RESULTS.md)**. The v0.2.0 scanner graded on the same cases: [history/v0.2.0-baseline.md](history/v0.2.0-baseline.md).

## Labels

Each case line carries a label in a comment. The label says what's **true** about the code, then whether the scanner currently gets it right:

| Label | The code is… | The scanner… | Counts as |
|---|---|---|---|
| `expect[RULE]` | unsafe | flags it | caught (true positive) |
| `miss[RULE]` | unsafe | doesn't flag it yet | missed (known false negative) |
| `safe[RULE]` | a safe look-alike | leaves it alone | true negative |
| `noisy[RULE]` | a safe look-alike | flags it anyway | false alarm (known false positive) |

**Decide the truth first.** Write `expect` or `safe` based only on whether the code is actually unsafe. Run the benchmark. Then switch a label to `miss` or `noisy` only after reading the case and agreeing the scanner is wrong. Never change `safe` to `expect` (or the reverse) just to make a number look better.

`--check` fails when:
- an `expect` case is missed, or a `safe` case is flagged (a regression),
- a `miss`/`noisy` case starts behaving (good news, but relabel it so the improvement is recorded),
- the scanner reports anything on a line with no label (every result must be explained),
- `RESULTS.md` is out of date.

## Adding a case

1. Pick the right folder under `cases/` and add a line to an existing file, or a new file.
2. Put the label in a comment on the same line: `db.execute(f"... {uid}")  # expect[VIBE013]`. Several are fine: `# expect[PQC004,PQC012]`.
3. Anything you write *after* the last label is a note for humans; the runner removes it before scanning. (It once made a "miss" look like a catch because the note contained the very keyword the rule looks for.)
4. Files that can't hold comments (JSON, `.env`, PEM) get a sidecar file `<name>.expect`:
   ```
   expect[AGT003] "/"
   safe[AGT002] "fs-project"
   ```
   The label applies to the first line containing that text, matched literally.
5. Never commit real-looking secrets or invisible characters. Name the file `something.tmpl` and use placeholders such as `{{GITHUB_TOKEN}}`, `{{RANDOM32}}`, `{{HIDDEN:text}}` or `{{BIDI_RLO}}`; the runner fills them in at run time. The full list is `PLACEHOLDERS` in `run.py`. This applies to documentation placeholders too: GitHub's push protection blocked Slack's own example webhook URL.
6. Run `python benchmark/run.py --write` and commit the updated `RESULTS.md`.

## What the numbers do and don't mean

- They're measured on cases written to be tricky, including known blind spots, so they're not a prediction for any particular codebase.
- A rule with two or three cases has rough numbers. More cases make them meaningful.
- Four rules can't be graded offline from a single file (the repo-wide inventory summary and the three online registry checks); they're covered by unit tests instead and listed as "not benchmarked".
