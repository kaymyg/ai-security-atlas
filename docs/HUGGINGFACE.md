# Publishing to Hugging Face

Two things are published automatically from this repository:

| What | Where | Built from |
|---|---|---|
| **Web demo** (Space): paste code or upload files, get a scan report | [huggingface.co/spaces/Sahek/ai-security-atlas](https://huggingface.co/spaces/Sahek/ai-security-atlas) | `huggingface/space/` + the scanner in `src/` |
| **Benchmark dataset**: every labelled case as one row | [huggingface.co/datasets/Sahek/ai-security-atlas-benchmark](https://huggingface.co/datasets/Sahek/ai-security-atlas-benchmark) | `benchmark/cases/` |

The workflow `.github/workflows/huggingface.yml` rebuilds and uploads both on every push to `main`. It creates them the first time, so you never need to create them by hand. Until a token is set up it simply skips, without failing CI.

## One-time setup (about 3 minutes)

**1. Create a Hugging Face token**

On huggingface.co: your profile picture → **Settings → Access Tokens → Create new token**. Choose the **Write** token type (or a fine-grained token with write access to repositories in your own account), name it something like `github-ai-security-atlas`, and create it. Copy the token; Hugging Face only shows it once.

**2. Give it to GitHub as a secret**

On github.com/kaymyg/ai-security-atlas: **Settings → Secrets and variables → Actions → New repository secret**.

- Name: `HF_TOKEN`
- Secret: paste the token

GitHub encrypts it; nobody, including you, can read it back. The workflow passes it only to the final upload step, and only runs on pushes to `main` (never on pull requests from other people's forks).

**3. Run it**

Go to the **Actions** tab → **Publish to Hugging Face** → **Run workflow**. (Or just push any change to `main`.) The first Space build takes a few minutes; after that, each push updates both within a couple of minutes.

## Keep the token safe

- Never paste it into chat, code, issues or commit messages. Only into the GitHub secret box.
- If it ever leaks, delete it on Hugging Face (Settings → Access Tokens) and create a new one, then update the GitHub secret.

## Building locally

```bash
python tools/build_hf.py build/hf        # build/hf/space and build/hf/dataset
cd build/hf/space && pip install gradio==6.30.0 && python app.py   # try the demo at http://127.0.0.1:7860
```

Publishing by hand: `HF_TOKEN=... python tools/publish_hf.py build/hf`. Different repository names can be set with `HF_SPACE_ID` and `HF_DATASET_ID`.
