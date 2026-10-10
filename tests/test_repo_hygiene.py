"""Checks on this repository itself.

The self-scan skips the deliberately insecure folders (examples/, tests/,
benchmark/cases/), which once let real bidi control characters sit unnoticed in
an example script. This test has no exclusions: no tracked text file may
contain invisible or direction-changing characters. Demos must build them with
chr() at run time instead.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Zero-width joiners are allowed only inside emoji (e.g. in prose).
FORBIDDEN = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200B, 0x200C, 0x2060, 0xFEFF}


def tracked_files():
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:  # not a git checkout (e.g. an sdist): check everything
        return [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    return [ROOT / f for f in out.stdout.splitlines()]


def test_no_invisible_characters_in_the_repo():
    offenders = []
    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            bad = [c for c in line if ord(c) in FORBIDDEN or 0xE0000 <= ord(c) <= 0xE01EF]
            if bad:
                codes = ", ".join(sorted({f"U+{ord(c):04X}" for c in bad}))
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} ({codes})")
    assert not offenders, "invisible characters found; use chr() instead:\n" + "\n".join(offenders)
