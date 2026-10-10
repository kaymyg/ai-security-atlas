# Contributing

Thanks for helping. Two kinds of contribution are especially useful:

1. **New or better rules.** Read [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md#add-your-own-rule-10-minutes). Every rule needs a test that it fires on bad code *and* stays quiet on the safe version.
2. **Verifying the threat map.** Pick an entry under [Leads to verify](docs/THREAT_MAP.md#leads-to-verify), find a primary source, and open a PR.

## Setup

```bash
git clone https://github.com/kaymyg/ai-security-atlas
cd ai-security-atlas
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Before you open a pull request

- `pytest -q` passes.
- If you changed rules: `python tools/gen_rules_doc.py`.
- `atlas scan .` is still clean.
- Never commit a real-looking secret, even a fake one. Build test keys at run time (see `tests/conftest.py::fake`).
