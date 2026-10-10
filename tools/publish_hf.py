"""Upload the folders made by tools/build_hf.py to Hugging Face.

    HF_TOKEN=... python tools/publish_hf.py build/hf

Creates the Space and the dataset on the first run, then mirrors each folder
in one commit: files deleted here are deleted there too. Runs from GitHub
Actions (.github/workflows/huggingface.yml); see docs/HUGGINGFACE.md.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

SPACE_ID = os.environ.get("HF_SPACE_ID", "Sahek/ai-security-atlas")
DATASET_ID = os.environ.get("HF_DATASET_ID", "Sahek/ai-security-atlas-benchmark")


def main(argv: list[str]) -> int:
    build = Path(argv[1] if len(argv) > 1 else "build/hf")
    token = os.environ.get("HF_TOKEN", "").strip()
    if not token:
        print("HF_TOKEN is not set; nothing published. See docs/HUGGINGFACE.md.", file=sys.stderr)
        return 1
    for sub in ("space", "dataset"):
        if not (build / sub / "README.md").is_file():
            print(f"{build / sub} is missing; run tools/build_hf.py first.", file=sys.stderr)
            return 1

    from huggingface_hub import HfApi

    api = HfApi(token=token)
    who = api.whoami()["name"]
    print(f"Publishing as {who}")
    sha = os.environ.get("GITHUB_SHA", "local")[:7]
    message = f"Sync from github.com/kaymyg/ai-security-atlas@{sha}"

    api.create_repo(SPACE_ID, repo_type="space", space_sdk="gradio", exist_ok=True)
    api.upload_folder(repo_id=SPACE_ID, repo_type="space", folder_path=str(build / "space"),
                      commit_message=message, delete_patterns="*")
    print(f"Space   https://huggingface.co/spaces/{SPACE_ID}")

    api.create_repo(DATASET_ID, repo_type="dataset", exist_ok=True)
    api.upload_folder(repo_id=DATASET_ID, repo_type="dataset", folder_path=str(build / "dataset"),
                      commit_message=message, delete_patterns="*")
    print(f"Dataset https://huggingface.co/datasets/{DATASET_ID}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
