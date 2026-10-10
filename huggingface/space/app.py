"""AI Security Atlas: web demo for Hugging Face Spaces.

Paste code or upload files and get the same report as `atlas scan`.
Everything submitted is treated as data: it's written to a temporary folder,
scanned (never executed), and deleted straight after.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))                       # on the Space: bundled atlas_scan/
_repo_src = HERE.parent.parent / "src"
if (_repo_src / "atlas_scan").is_dir():              # running from a git checkout
    sys.path.insert(0, str(_repo_src))

import gradio as gr  # noqa: E402

from atlas_scan import __version__  # noqa: E402
from atlas_scan.engine import ScanResult, scan_path  # noqa: E402
from atlas_scan.models import CATEGORIES, Finding, Severity  # noqa: E402
from atlas_scan.scanners import default_scanners  # noqa: E402
from atlas_scan.scanners.deps import DependencyScanner  # noqa: E402

REPO = "https://github.com/kaymyg/ai-security-atlas"
MAX_PASTE_CHARS = 200_000
MAX_FILES = 20
MAX_FILE_BYTES = 1_000_000
SEVERITY_ICON = {Severity.CRITICAL: "🟥", Severity.HIGH: "🔴", Severity.MEDIUM: "🟠", Severity.LOW: "🔵",
                 Severity.INFO: "⚪"}


# ----------------------------------------------------------------- input safety

def safe_relpath(name: str) -> str | None:
    """Turn a user-supplied file name into a safe relative path, or None.

    Folders are allowed because some rules depend on them
    (".github/workflows/ci.yml", ".claude/settings.json"), but absolute paths
    and ".." are rejected so nothing can be written outside the temp folder.
    """
    name = (name or "").strip().replace("\\", "/")
    if not name or len(name) > 200 or "\x00" in name:
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts) or re.match(r"^[A-Za-z]:", name):
        return None
    return str(path)


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")


def md(text: str) -> str:
    """Escape user-derived text so it can't add links, HTML or formatting."""
    return _MD_SPECIAL.sub(r"\\\1", text or "")


def code_span(text: str) -> str:
    text = (text or "").replace("`", "'").replace("\n", " ")
    return f"`{text}`" if text.strip() else ""


# ----------------------------------------------------------------- scanning

def _scan_dir(root: str, online: bool) -> ScanResult:
    scanners = default_scanners()
    if online:
        scanners = [DependencyScanner(online=True) if isinstance(s, DependencyScanner) else s for s in scanners]
    return scan_path(root, scanners=scanners)


def render(result: ScanResult, min_severity: str) -> str:
    floor = Severity.parse(min_severity)
    inventory: dict = {}
    findings: list[Finding] = []
    for f in result.findings:
        if f.rule.id == "PQC000":
            inventory = f.extra.get("inventory", {})
        elif f.severity >= floor:
            findings.append(f)

    out = []
    if not findings:
        out.append(f"### ✅ No findings in {result.files_scanned} file(s)")
        out.append("That means none of the patterns matched, not that the code is proven secure.")
    else:
        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = " · ".join(f"{SEVERITY_ICON[s]} {n} {s}" for s, n in sorted(counts.items(), reverse=True))
        out.append(f"### {len(findings)} finding(s) in {result.files_scanned} file(s)")
        out.append(summary)

    for cat, label in CATEGORIES.items():
        items = [f for f in findings if f.rule.category == cat]
        if not items:
            continue
        out.append(f"\n#### {label}")
        for f in items:
            kind = {"misconfiguration": "config"}.get(f.rule.kind, f.rule.kind)
            out.append(f"**{SEVERITY_ICON[f.severity]} {f.severity} · {f.rule.id} · {kind}** — "
                       f"{code_span(f'{f.path}:{f.line}')}  ")
            out.append(f"{md(f.message or f.rule.title)}  ")
            if f.snippet:
                out.append(f"{code_span(f.snippet)}  ")
            if f.rule.fix:
                out.append(f"→ {md(f.rule.fix)}")
            out.append("")

    if inventory:
        out.append("\n#### Cryptography inventory (post-quantum planning, not vulnerabilities)")
        for label, paths in inventory.items():
            out.append(f"- {md(label)}: {', '.join(code_span(p) for p in paths)}")

    if result.suppressed_findings or result.skipped_files:
        out.append(f"\n_Silenced by `atlas: ignore` comments: {len(result.suppressed_findings)} finding(s); "
                   f"files skipped by `atlas: ignore-file`: {len(result.skipped_files)}._")
    for w in result.warnings:
        out.append(f"\n> ⚠️ {md(w)}")
    out.append(f"\n<sub>ai-security-atlas {__version__} · pattern-based checks: they can miss cases and "
               f"flag safe code. [Rules, limitations and benchmark]({REPO}).</sub>")
    return "\n".join(out)


def scan_paste(filename: str, code: str, online: bool, min_severity: str) -> str:
    rel = safe_relpath(filename)
    if rel is None:
        return "⚠️ Please enter a file name such as `app.py`, `.mcp.json` or `.github/workflows/ci.yml` " \
               "(no absolute paths or `..`)."
    if not (code or "").strip():
        return "⚠️ Paste some code or a config file first."
    if len(code) > MAX_PASTE_CHARS:
        return f"⚠️ That's {len(code):,} characters; the limit is {MAX_PASTE_CHARS:,}. Scan a smaller part."
    with tempfile.TemporaryDirectory(prefix="atlas-") as tmp:
        target = Path(tmp) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code, encoding="utf-8")
        return render(_scan_dir(tmp, online), min_severity)


def scan_uploads(files: list[str] | None, online: bool, min_severity: str) -> str:
    if not files:
        return "⚠️ Upload at least one file."
    if len(files) > MAX_FILES:
        return f"⚠️ Upload at most {MAX_FILES} files at a time."
    skipped = []
    with tempfile.TemporaryDirectory(prefix="atlas-") as tmp:
        used: set[str] = set()
        for src in files:
            src_path = Path(src)
            name = safe_relpath(src_path.name) or "upload.txt"
            if src_path.stat().st_size > MAX_FILE_BYTES:
                skipped.append(src_path.name)
                continue
            base, n = name, 1
            while name in used:                    # two uploads with the same name
                n += 1
                name = f"{n}_{base}"
            used.add(name)
            shutil.copyfile(src_path, Path(tmp) / name)
        report = render(_scan_dir(tmp, online), min_severity)
    if skipped:
        report = f"⚠️ Skipped (over 1 MB): {', '.join(code_span(s) for s in skipped)}\n\n" + report
    return report


from demo_examples import EXAMPLES  # noqa: E402  (insecure on purpose, kept separate)

LANGUAGES = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
             ".ts": "typescript", ".tsx": "typescript", ".json": "json", ".yml": "yaml", ".yaml": "yaml",
             ".md": "markdown", ".sh": "shell", ".html": "html", ".sql": "sql", ".c": "c", ".cpp": "cpp"}


def language_for(filename: str):
    name = (filename or "").strip().lower()
    if name.rsplit("/", 1)[-1].startswith("dockerfile"):
        return "dockerfile"
    suffix = name[name.rfind("."):] if "." in name else ""
    return LANGUAGES.get(suffix)


# ----------------------------------------------------------------- page

INTRO = f"""
# 🛡️ AI Security Atlas

One scan for AI-era risks in code: **AI-generated code flaws**, **leaked secrets**, **risky AI agent & MCP configs**,
**hidden instructions in invisible Unicode**, **hallucinated or typosquatted packages**, and **weak cryptography**
with a post-quantum inventory.

Open source: [{REPO.split('github.com/')[1]}]({REPO}) · run it locally with `pip install` and `atlas scan .`,
or in CI as a GitHub Action.
"""

PRIVACY = """
<sub>🔒 Your input is scanned in a temporary folder and deleted immediately; nothing is stored or executed.
Even so, **don't paste real secrets**. If you already have, rotate them. Reports always mask secrets.</sub>
"""


def build() -> gr.Blocks:
    with gr.Blocks(title="AI Security Atlas") as demo:
        gr.Markdown(INTRO)
        with gr.Row():
            online = gr.Checkbox(label="Check PyPI / npm for packages that don't exist (slower)", value=False)
            min_sev = gr.Dropdown(["info", "low", "medium", "high", "critical"], value="low",
                                  label="Show findings from this level up")
        with gr.Tab("Paste code"):
            filename = gr.Textbox(label="File name (it decides which rules apply)", value="app.py",
                                  placeholder="app.py, server.js, .mcp.json, AGENTS.md, .github/workflows/ci.yml")
            code = gr.Code(label="Code or config", language="python", lines=14, max_lines=40)
            paste_btn = gr.Button("Scan", variant="primary")
            gr.Examples(EXAMPLES, inputs=[filename, code], label="Try an example")
        with gr.Tab("Upload files"):
            files = gr.File(label=f"Up to {MAX_FILES} files, 1 MB each", file_count="multiple", type="filepath")
            upload_btn = gr.Button("Scan files", variant="primary")
        report = gr.Markdown(sanitize_html=True)
        gr.Markdown(PRIVACY)

        filename.change(lambda n: gr.Code(language=language_for(n)), inputs=filename, outputs=code,
                        api_visibility="private")
        paste_btn.click(scan_paste, inputs=[filename, code, online, min_sev], outputs=report)
        upload_btn.click(scan_uploads, inputs=[files, online, min_sev], outputs=report)
    return demo


demo = build()

if __name__ == "__main__":
    demo.launch(theme=gr.themes.Soft(), max_file_size="1mb")
