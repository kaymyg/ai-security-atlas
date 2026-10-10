"""AI supply chain: hallucinated, typosquatted and loosely sourced dependencies.

Problem area 5 (second half). AI assistants sometimes invent package names
that sound right but don't exist. Attackers register those names
("slopsquatting") and wait. Typosquats work the same way with spelling
mistakes.

Offline checks run always. ``--online`` also asks PyPI/npm whether each
package exists and how old it is.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

from ..data import POPULAR_NPM, POPULAR_PYPI
from ..models import Finding, Rule, Severity, SourceFile
from . import Scanner

C = "supply-chain"

TYPOSQUAT = Rule("SUP001", "Possible typosquat of a popular package", Severity.HIGH, C,
                 "Check the spelling. If you meant the popular package, fix the name before installing.", "CWE-1357")
MISSING = Rule("SUP002", "Package does not exist on the registry (possible AI hallucination)", Severity.HIGH, C,
               "Don't install it. The name was probably invented by an AI; an attacker could register it.",
               "CWE-1357")
NEW_PKG = Rule("SUP003", "Very new package (published in the last 30 days)", Severity.MEDIUM, C,
               "New packages with AI-plausible names are a common slopsquatting trap. Verify the publisher.",
               "CWE-1357")
UNPINNED = Rule("SUP004", "Dependency with no version constraint", Severity.LOW, C,
                "Pin a version (and use a lock file) so a hijacked release can't slip in silently.", "CWE-1104")
URL_DEP = Rule("SUP005", "Dependency installed straight from a URL or git", Severity.MEDIUM, C,
               "Prefer a published, pinned release. If you must use git, pin to a commit SHA.", "CWE-494")
PIPE_SH = Rule("SUP006", "Remote script piped straight into a shell", Severity.MEDIUM, C,
               "Download, verify a checksum or signature, then run.", "CWE-494")
ACTION_PIN = Rule("SUP007", "Third-party GitHub Action not pinned to a commit SHA", Severity.LOW, C,
                  "Pin to the full 40-character commit SHA (tags can be moved by an attacker).", "CWE-829")

NEW_PACKAGE_DAYS = 30


def normalise_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein distance, giving up early once it exceeds ``limit``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def squat_target(name: str, popular: set[str]) -> Optional[str]:
    if name in popular:
        return None
    bare = re.sub(r"[-_.]", "", name)
    for p in popular:
        if bare == re.sub(r"[-_.]", "", p):
            return p  # "python_dotenv" vs "python-dotenv" is fine on PyPI, but npm treats them as different
        if len(p) < 5:
            continue
        d = distance(name, p, 2)
        if d == 1 or (d == 2 and len(p) >= 9):
            return p
    return None


# ---------------------------------------------------------------- parsers

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirements(src: SourceFile) -> Iterable[tuple[str, str, int]]:
    for i, raw in enumerate(src.lines, 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-r", "-c", "--", "-e .")):
            continue
        if re.search(r"(?:git\+|https?://|file:)", line):
            yield "__url__", line, i
            continue
        m = REQ_LINE.match(line)
        if m:
            yield m.group(1), m.group(3).split(";")[0].strip(), i


def parse_pyproject(src: SourceFile) -> Iterable[tuple[str, str, int]]:
    in_list = False
    section = ""
    for i, raw in enumerate(src.lines, 1):
        line = raw.strip()
        if line.startswith("["):
            section = line
            in_list = False
            continue
        is_dep_list = (
            (section == "[project]" and re.match(r"^dependencies\s*=\s*\[", line))
            or (("optional-dependencies" in section or "dependency-groups" in section)
                and re.match(r"^[\w-]+\s*=\s*\[", line))
        )
        if is_dep_list:
            in_list = True
            line = line.split("[", 1)[1]
        if in_list:
            for item in re.findall(r"[\"']([^\"']+)[\"']", line):
                if re.search(r"(?:git\+|https?://|@\s*file:)", item):
                    yield "__url__", item, i
                    continue
                m = REQ_LINE.match(item)
                if m:
                    yield m.group(1), m.group(3).split(";")[0].strip(), i
            if "]" in line:
                in_list = False
        elif "tool.poetry" in section and "dependencies" in section:
            m = re.match(r"^([A-Za-z0-9][\w.\-]*)\s*=\s*(.+)$", line)
            if m and m.group(1).lower() != "python":
                spec = m.group(2).strip()
                if "git" in spec or "url" in spec:
                    yield "__url__", line, i
                else:
                    yield m.group(1), "" if spec.strip("\"'") == "*" else spec, i


def parse_package_json(src: SourceFile) -> Iterable[tuple[str, str, int]]:
    try:
        data = json.loads(src.text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(key) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            line = _find_line(src, f'"{name}"')
            spec = str(spec)
            if re.match(r"^(?:git\+|git:|https?://|github:|gitlab:|bitbucket:|file:)", spec) or \
                    re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", spec):
                yield "__url__", f"{name}: {spec}", line
            else:
                yield name, "" if spec in ("*", "latest", "") else spec, line


def _find_line(src: SourceFile, needle: str) -> int:
    for i, l in enumerate(src.lines, 1):
        if needle in l:
            return i
    return 1


# ---------------------------------------------------------------- registry

Fetcher = Callable[[str], Optional[dict]]


def http_json(url: str) -> Optional[dict]:
    """Return parsed JSON, None for 404, or raise for other failures."""
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ai-security-atlas"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


class Registry:
    def __init__(self, fetch: Fetcher = http_json) -> None:
        self.fetch = fetch
        self.cache: dict[tuple[str, str], tuple[bool, Optional[datetime]] | None] = {}

    def lookup(self, eco: str, name: str) -> tuple[bool, Optional[datetime]] | None:
        """(exists, first_published) or None when the registry can't be reached."""
        key = (eco, name)
        if key in self.cache:
            return self.cache[key]
        try:
            if eco == "pypi":
                data = self.fetch(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
                result = (False, None) if data is None else (True, _pypi_created(data))
            else:
                data = self.fetch(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
                created = (data or {}).get("time", {}).get("created") if data else None
                result = (False, None) if data is None else (True, _iso(created))
        except Exception:
            result = None
        self.cache[key] = result
        return result


def _iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _pypi_created(data: dict) -> Optional[datetime]:
    times = [_iso(f.get("upload_time_iso_8601")) for files in (data.get("releases") or {}).values()
             for f in files]
    times = [t for t in times if t]
    return min(times) if times else None


# ---------------------------------------------------------------- scanner

class DependencyScanner(Scanner):
    name = "supply-chain"
    category = C
    rules = [TYPOSQUAT, MISSING, NEW_PKG, UNPINNED, URL_DEP, PIPE_SH, ACTION_PIN]

    def __init__(self, online: bool = False, registry: Registry | None = None,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.online = online
        self.registry = registry or Registry()
        self.now = now

    def applies(self, src: SourceFile) -> bool:
        return True

    def scan(self, src: SourceFile) -> Iterable[Finding]:
        name = src.name.lower()
        if re.match(r"^requirements.*\.(txt|in)$", name) or name == "constraints.txt":
            yield from self._check(src, "pypi", parse_requirements(src))
        elif name == "pyproject.toml":
            yield from self._check(src, "pypi", parse_pyproject(src))
        elif name == "package.json":
            yield from self._check(src, "npm", parse_package_json(src))

        if name.endswith((".sh", ".bash", ".zsh", ".yml", ".yaml", ".md", ".ps1")) or \
                name in ("dockerfile", "makefile", "package.json") or name.startswith("dockerfile"):
            for m in re.finditer(r"(?:curl|wget)\b[^\n|]*https?://[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", src.text):
                line, col = src.line_of(m.start())
                yield Finding(PIPE_SH, src.path, line, col, src.snippet(line))

        if "/.github/workflows/" in "/" + src.path and name.endswith((".yml", ".yaml")):
            for m in re.finditer(r"uses:\s*[\"']?([\w.-]+)/([\w./-]+)@([\w.\-/]+)", src.text):
                owner, ref = m.group(1), m.group(3)
                if owner in ("actions", "github") or re.fullmatch(r"[0-9a-f]{40}", ref):
                    continue
                line, col = src.line_of(m.start())
                yield Finding(ACTION_PIN, src.path, line, col, src.snippet(line))

    def _check(self, src: SourceFile, eco: str, deps: Iterable[tuple[str, str, int]]) -> Iterable[Finding]:
        popular = POPULAR_PYPI if eco == "pypi" else POPULAR_NPM
        for raw_name, spec, line in deps:
            if raw_name == "__url__":
                yield Finding(URL_DEP, src.path, line, 1, src.snippet(line))
                continue
            name = normalise_py(raw_name) if eco == "pypi" else raw_name.lower()
            target = squat_target(name, popular)
            if target and not (eco == "pypi" and normalise_py(target) == name):
                yield Finding(TYPOSQUAT, src.path, line, 1, src.snippet(line),
                              message=f"'{raw_name}' looks like a misspelling of '{target}'",
                              extra={"package": raw_name, "similar_to": target})
            if not spec:
                yield Finding(UNPINNED, src.path, line, 1, src.snippet(line),
                              message=f"'{raw_name}' has no version constraint")
            if self.online:
                yield from self._online(src, eco, raw_name, name, line)

    def _online(self, src, eco, raw_name, name, line) -> Iterable[Finding]:
        info = self.registry.lookup(eco, name)
        if info is None:
            return
        exists, created = info
        if not exists:
            yield Finding(MISSING, src.path, line, 1, src.snippet(line),
                          message=f"'{raw_name}' was not found on {'PyPI' if eco == 'pypi' else 'npm'}",
                          extra={"package": raw_name, "ecosystem": eco})
        elif created and (self.now() - created).days < NEW_PACKAGE_DAYS:
            yield Finding(NEW_PKG, src.path, line, 1, src.snippet(line),
                          message=f"'{raw_name}' was first published {created.date().isoformat()}",
                          extra={"package": raw_name, "first_published": created.isoformat()})
