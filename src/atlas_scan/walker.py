"""Find the files worth scanning.

Skips build output, dependency folders, binaries and very large files, and
honours an optional ``.atlasignore`` file (one glob pattern per line).
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Iterator

from .models import SourceFile

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt", ".svelte-kit", "target", "vendor", ".terraform", "coverage",
    ".idea", ".gradle", "site-packages",
}

SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
    ".tar", ".7z", ".rar", ".jar", ".class", ".so", ".dll", ".dylib", ".exe", ".bin",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".wav",
    ".pyc", ".lock", ".min.js", ".map", ".svg", ".sqlite", ".db",
}

# Lock files are huge and machine-written; scan the manifest instead.
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock"}

MAX_BYTES = 1_000_000


def load_ignore_patterns(root: Path) -> list[str]:
    ignore = root / ".atlasignore"
    if not ignore.is_file():
        return []
    patterns = []
    for raw in ignore.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            patterns.append(line.rstrip("/"))
    return patterns


def is_ignored(rel: str, patterns: list[str]) -> bool:
    return matching_pattern(rel, patterns) is not None


def matching_pattern(rel: str, patterns: list[str]) -> str | None:
    """Return the first pattern that excludes ``rel``, or None."""
    for original in patterns:
        if _matches(rel, original) or (original.startswith("**/") and _matches(rel, original[3:])):
            return original
    return None


def _matches(rel: str, pat: str) -> bool:
    if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
        return True
    # a bare name like "fixtures" matches that folder anywhere
    return "/" not in pat and any(fnmatch.fnmatch(part, pat) for part in rel.split("/"))


def _looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def iter_files(root: str | os.PathLike, extra_ignores: list[str] | None = None,
               excluded: dict[str, int] | None = None) -> Iterator[SourceFile]:
    """Yield scannable files. If ``excluded`` is given, it's filled with
    {ignore pattern: number of files it excluded} so reports can show it."""
    root_path = Path(root).resolve()
    patterns = load_ignore_patterns(root_path) + list(extra_ignores or [])
    tally = excluded if excluded is not None else {}

    if root_path.is_file():
        candidates = [(root_path, root_path.name)]
    else:
        candidates = _walk(root_path, patterns, tally)

    for abspath, rel in candidates:
        name = abspath.name
        lower = name.lower()
        if name in SKIP_NAMES or any(lower.endswith(s) for s in SKIP_SUFFIXES):
            continue
        try:
            if abspath.stat().st_size > MAX_BYTES:
                continue
            raw = abspath.read_bytes()
        except OSError:
            continue
        if _looks_binary(raw[:8192]):
            continue
        text = raw.decode("utf-8", errors="replace")
        yield SourceFile(path=rel, abspath=str(abspath), text=text)


def _count_files(folder: Path) -> int:
    total = 0
    for _, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        total += len(filenames)
    return total


def _walk(root: Path, patterns: list[str], tally: dict[str, int]) -> Iterator[tuple[Path, str]]:
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if d in SKIP_DIRS:
                continue
            pat = matching_pattern(rel, patterns)
            if pat is not None:
                tally[pat] = tally.get(pat, 0) + _count_files(Path(dirpath) / d)
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            rel = f"{rel_dir}/{f}" if rel_dir else f
            pat = matching_pattern(rel, patterns)
            if pat is not None:
                tally[pat] = tally.get(pat, 0) + 1
                continue
            yield Path(dirpath) / f, rel
