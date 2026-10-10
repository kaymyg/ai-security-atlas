"""AI agents, MCP servers and the files that steer them.

Problem area 3 (agentic AI and non-human identity). In a repo, an agent's
"identity" is its config: which tools it can call, which credentials it
holds, and whether a human approves what it does. This scanner applies the
"least agency" and "human in the loop" ideas to those configs.

It also checks agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules…)
and every other file for invisible Unicode, which can hide instructions from
humans while the AI still reads them.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from ..models import Finding, Rule, Severity, SourceFile
from . import Scanner
from .secrets import entropy, looks_placeholder, mask

C = "agents"

MCP_SECRET = Rule("AGT001", "Credential hard-coded in an MCP server config", Severity.HIGH, C,
                  "Reference an environment variable (e.g. \"${GITHUB_TOKEN}\") instead of pasting the value, and "
                  "give the token the smallest scope that works.", "CWE-798")
MCP_UNPINNED = Rule("AGT002", "MCP server launched from an unpinned package", Severity.MEDIUM, C,
                    "Pin an exact version (npx -y pkg@1.2.3, uvx pkg==1.2.3) so a malicious update can't run "
                    "with your agent's permissions.", "CWE-1104")
MCP_BROAD_FS = Rule("AGT003", "MCP server given access to the whole disk or home folder", Severity.HIGH, C,
                    "Point it at the one project folder it needs.", "CWE-250")
MCP_HTTP = Rule("AGT004", "Remote MCP server over unencrypted HTTP", Severity.MEDIUM, C,
                "Use https:// for any MCP server that isn't on localhost.", "CWE-319")
MCP_DOCKER = Rule("AGT005", "MCP server container runs privileged or with the Docker socket", Severity.HIGH, C,
                  "Drop --privileged and don't mount /var/run/docker.sock or / into agent containers.", "CWE-250")

BYPASS = Rule("AGT010", "AI agent approval prompts disabled", Severity.HIGH, C,
              "Keep a human in the loop: remove bypass/auto-approve modes from shared configs.", "CWE-862")
WILD_SHELL = Rule("AGT011", "AI agent pre-approved to run any shell command", Severity.HIGH, C,
                  "Allow only the specific commands the agent needs, e.g. Bash(npm test:*).", "CWE-250")
RISKY_ALLOW = Rule("AGT012", "AI agent pre-approved for a risky command", Severity.MEDIUM, C,
                   "Require approval for destructive, network or deploy commands.", "CWE-250")
AUTO_MCP = Rule("AGT013", "All project MCP servers trusted automatically", Severity.MEDIUM, C,
                "Approve MCP servers one by one; a cloned repo could add its own.", "CWE-829")
CLI_BYPASS = Rule("AGT014", "AI agent run with approvals disabled in a script or CI", Severity.MEDIUM, C,
                  "Run unattended agents in a sandbox with read-only tokens, or restrict their tools.", "CWE-862")
CI_UNTRUSTED = Rule("AGT020", "AI agent in CI triggered by untrusted input", Severity.MEDIUM, C,
                    "Issue/PR text is attacker-controlled prompt input. Limit the trigger to trusted authors "
                    "(author_association) and give the job read-only permissions.", "CWE-77")
POISON = Rule("AGT030", "Suspicious instruction in an AI agent rules file", Severity.HIGH, C,
              "Read the file carefully. Rules files are executed by the agent like code; treat changes to them "
              "like code review.", "CWE-77")

HIDDEN_TAGS = Rule("UNI001", "Invisible Unicode tag characters (hidden AI instructions)", Severity.CRITICAL, C,
                   "Delete the hidden characters. They smuggle text that AI models read but humans can't see.",
                   "CWE-1007")
BIDI = Rule("UNI002", "Bidirectional control characters (Trojan Source)", Severity.HIGH, C,
            "Remove the bidi controls; they make code display differently from how it runs.", "CWE-1007")
ZERO_WIDTH = Rule("UNI003", "Zero-width characters in code or agent instructions", Severity.MEDIUM, C,
                  "Remove them; they can hide text or make identifiers look identical.", "CWE-1007")
VARSEL = Rule("UNI004", "Unusual variation-selector characters (possible hidden payload)", Severity.HIGH, C,
              "Remove them; long runs of variation selectors can encode hidden data.", "CWE-1007")

RULES_FILES = re.compile(
    r"(?:^|/)(?:\.cursorrules|\.windsurfrules|\.clinerules|AGENTS\.md|CLAUDE\.md|GEMINI\.md|"
    r"copilot-instructions\.md|\.cursor/rules/[^/]+|\.github/instructions/[^/]+|\.claude/(?:agents|commands)/[^/]+)$",
    re.I,
)

SECRET_KEY = re.compile(r"(?i)token|secret|key|passw|pwd|auth|credential|bearer|cookie")
BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "C:\\", "C:/", "/home", "/Users", "/root"}
RISKY_CMDS = ("rm", "sudo", "curl", "wget", "ssh", "scp", "chmod", "chown", "dd", "mkfs", "git push",
              "npm publish", "docker", "kubectl", "terraform", "aws", "gcloud", "az", "eval", "python -c",
              "node -e")
AGENT_IN_CI = re.compile(
    r"anthropics/claude-code-action|openai/codex-action|run-gemini-cli|aider\b|\bclaude\s+(?:-p|--print)\b|"
    r"\bcodex\s+exec\b|\bgemini\s+-p\b|copilot-swe-agent"
)
_TRIGGER_NAMES = r"(issue_comment|issues|pull_request_target|pull_request_review_comment|discussion_comment)"
UNTRUSTED_TRIGGERS = re.compile(
    rf"^[ \t]*(?:-[ \t]*)?{_TRIGGER_NAMES}[ \t]*:?[ \t]*(?:#.*)?$"      # block form:  on:\n  issues:
    rf"|^[ \t]*on[ \t]*:[ \t]*\[[^\]\n]*\b{_TRIGGER_NAMES}\b"           # list form:   on: [issues, push]
    rf"|^[ \t]*on[ \t]*:[ \t]*{_TRIGGER_NAMES}[ \t]*(?:#.*)?$",          # single:      on: issues
    re.M,
)
POISON_PATTERNS = re.compile(
    r"(?i)ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+(?:instructions|rules)|"
    r"(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show)\s+(?:this\s+)?(?:to\s+)?the\s+user|"
    r"without\s+(?:telling|asking|informing)\s+the\s+user|"
    r"(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh|exfiltrat|"
    r"(?:send|post|upload)\s+[^\n]{0,60}(?:env|secrets?|keys?|tokens?|credentials)[^\n]{0,60}https?://|"
    r"[A-Za-z0-9+/]{200,}={0,2}"
)


def _walk(obj: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def _line(src: SourceFile, needle: str) -> int:
    """Line of a JSON value: prefer the exact quoted string ("/" must not match
    "@scope/pkg"), then fall back to a plain substring."""
    if needle:
        quoted = json.dumps(needle)
        for candidate in (quoted, needle):
            for i, l in enumerate(src.lines, 1):
                if candidate in l:
                    return i
    return 1


class AgentConfigScanner(Scanner):
    name = "agents"
    category = C
    rules = [MCP_SECRET, MCP_UNPINNED, MCP_BROAD_FS, MCP_HTTP, MCP_DOCKER, BYPASS, WILD_SHELL, RISKY_ALLOW,
             AUTO_MCP, CLI_BYPASS, CI_UNTRUSTED, POISON]

    def applies(self, src: SourceFile) -> bool:
        return True

    def scan(self, src: SourceFile) -> Iterable[Finding]:
        name = src.name.lower()
        if src.suffix in (".json", ".jsonc") or name.endswith("mcp.json"):
            data = self._load_json(src)
            if isinstance(data, dict):
                servers = data.get("mcpServers") or data.get("servers")
                if servers is None and isinstance(data.get("mcp"), dict):
                    servers = data["mcp"].get("servers")
                if isinstance(servers, dict):
                    yield from self._mcp(src, servers)
                if "/.claude/" in "/" + src.path or name.startswith("settings"):
                    yield from self._claude_settings(src, data)
                yield from self._vscode(src, data)
        if name == "config.toml" and ".codex" in src.path:
            yield from self._codex(src)
        if name.endswith((".sh", ".bash", ".yml", ".yaml", ".ps1", ".toml")) or name in (
                "makefile", "dockerfile", "package.json", "justfile"):
            for m in re.finditer(r"--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|"
                                 r"(?<![\w-])--yolo\b|--permission-mode[ =]bypassPermissions", src.text):
                line, col = src.line_of(m.start())
                yield Finding(CLI_BYPASS, src.path, line, col, src.snippet(line))
        if "/.github/workflows/" in "/" + src.path and src.suffix in (".yml", ".yaml"):
            yield from self._ci(src)
        if RULES_FILES.search(src.path):
            for m in POISON_PATTERNS.finditer(src.text):
                line, col = src.line_of(m.start())
                yield Finding(POISON, src.path, line, col, src.snippet(line))
            # Instructions hidden in invisible tag characters get the same check.
            for m in _TAGS.finditer(src.text):
                hidden_text = decode_tags(m.group(0))
                hit = POISON_PATTERNS.search(hidden_text)
                if hit:
                    line, col = src.line_of(m.start())
                    yield Finding(POISON, src.path, line, col, _visible(src.lines[line - 1]),
                                  message=f"Hidden instruction: \"{hit.group(0)}\"")

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _load_json(src: SourceFile) -> Any:
        text = src.text
        try:
            return json.loads(text)
        except ValueError:
            # tolerate // comments and trailing commas (VS Code style JSONC)
            stripped = re.sub(r"(?m)^\s*//.*$", "", text)
            stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
            try:
                return json.loads(stripped)
            except ValueError:
                return None

    def _mcp(self, src: SourceFile, servers: dict) -> Iterable[Finding]:
        for sname, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command", ""))
            args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int))]
            line = _line(src, f'"{sname}"')

            for path, value in _walk({"env": cfg.get("env", {}), "headers": cfg.get("headers", {})}):
                key = path.rsplit(".", 1)[-1]
                if not isinstance(value, str) or not SECRET_KEY.search(key):
                    continue
                v = value.replace("Bearer ", "").strip()
                if len(v) < 12 or looks_placeholder(v) or v.startswith(("$", "%")) or entropy(v) < 3.0:
                    continue
                yield Finding(MCP_SECRET, src.path, _line(src, value), 1,
                              src.snippet(_line(src, value)).replace(v, mask(v)),
                              message=f"MCP server '{sname}' has a literal value for {key}",
                              extra={"server": sname})
            for a in args:  # tokens passed on the command line
                if re.match(r"^(?:ghp_|github_pat_|sk-|xox|AKIA)", a) and not looks_placeholder(a):
                    yield Finding(MCP_SECRET, src.path, _line(src, a), 1, f'"{mask(a)}"',
                                  message=f"MCP server '{sname}' gets a credential as an argument")

            launcher = cmd.rsplit("/", 1)[-1]
            if launcher in ("npx", "bunx", "pnpx", "uvx", "pipx") or (launcher in ("pnpm", "yarn") and "dlx" in args):
                pkg = next((a for a in args if not a.startswith("-") and a not in ("dlx", "run")), "")
                if pkg:
                    pinned = ("==" in pkg) if launcher in ("uvx", "pipx") else bool(
                        re.search(r".@\d", pkg))
                    if not pinned or pkg.endswith("@latest"):
                        yield Finding(MCP_UNPINNED, src.path, line, 1, src.snippet(_line(src, pkg)),
                                      message=f"MCP server '{sname}' runs '{pkg}' without a pinned version")

            if launcher == "docker":
                joined = " ".join(args)
                if "--privileged" in joined or "docker.sock" in joined or re.search(r"(?:-v|--volume)\s+/:", joined):
                    yield Finding(MCP_DOCKER, src.path, line, 1, src.snippet(line),
                                  message=f"MCP server '{sname}' container has host-level access")

            if any("filesystem" in x or "file-system" in x for x in [cmd, sname, *args]):
                for a in args:
                    if a.rstrip("/\\") in {p.rstrip("/\\") for p in BROAD_PATHS} or \
                            re.fullmatch(r"/(?:home|Users)/[^/]+/?|C:\\Users\\[^\\]+\\?", a):
                        yield Finding(MCP_BROAD_FS, src.path, _line(src, a), 1, src.snippet(_line(src, a)),
                                      message=f"MCP server '{sname}' can read/write '{a}'")

            url = str(cfg.get("url", "") or cfg.get("serverUrl", ""))
            if url.startswith("http://") and not re.match(r"http://(?:localhost|127\.|0\.0\.0\.0|\[::1\])", url):
                yield Finding(MCP_HTTP, src.path, _line(src, url), 1, src.snippet(_line(src, url)))

    def _claude_settings(self, src: SourceFile, data: dict) -> Iterable[Finding]:
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        if perms.get("defaultMode") == "bypassPermissions" or data.get("dangerouslySkipPermissions") is True:
            yield Finding(BYPASS, src.path, _line(src, "bypassPermissions") if "bypassPermissions" in src.text
                          else _line(src, "dangerouslySkipPermissions"), 1,
                          src.snippet(_line(src, "bypassPermissions")))
        for rule in perms.get("allow", []) or []:
            if not isinstance(rule, str):
                continue
            r = rule.strip()
            ln = _line(src, r)
            if r in ("Bash", "Bash(*)", "Bash(**)", "Bash(:*)"):
                yield Finding(WILD_SHELL, src.path, ln, 1, src.snippet(ln))
                continue
            m = re.match(r"Bash\((.+)\)$", r)
            if m:
                inner = m.group(1).strip()
                # Only a wildcard rule ("curl:*", "rm *") hands over the whole command;
                # a fully spelled-out command is a narrow, reviewed permission.
                wildcard = "*" in inner or inner in RISKY_CMDS
                if wildcard and any(inner == c or inner.startswith((c + ":", c + " ")) for c in RISKY_CMDS):
                    yield Finding(RISKY_ALLOW, src.path, ln, 1, src.snippet(ln),
                                  message=f"Pre-approved: {r}")
        if data.get("enableAllProjectMcpServers") is True:
            yield Finding(AUTO_MCP, src.path, _line(src, "enableAllProjectMcpServers"), 1,
                          src.snippet(_line(src, "enableAllProjectMcpServers")))

    def _vscode(self, src: SourceFile, data: dict) -> Iterable[Finding]:
        if data.get("chat.tools.autoApprove") is True or data.get("chat.tools.global.autoApprove") is True:
            ln = _line(src, "autoApprove")
            yield Finding(BYPASS, src.path, ln, 1, src.snippet(ln),
                          message="VS Code agent mode auto-approves every tool call")

    def _codex(self, src: SourceFile) -> Iterable[Finding]:
        for m in re.finditer(r"(?m)^\s*(approval_policy\s*=\s*[\"']never[\"']|"
                             r"sandbox_mode\s*=\s*[\"']danger-full-access[\"'])", src.text):
            line, col = src.line_of(m.start(1))
            yield Finding(BYPASS, src.path, line, col, src.snippet(line))

    def _ci(self, src: SourceFile) -> Iterable[Finding]:
        agent = AGENT_IN_CI.search(src.text)
        trig = UNTRUSTED_TRIGGERS.search(src.text)
        if agent and trig:
            guarded = re.search(r"author_association|github\.actor\s*==|contains\(\s*fromJSON", src.text)
            if not guarded:
                line, col = src.line_of(agent.start())
                yield Finding(CI_UNTRUSTED, src.path, line, col, src.snippet(line),
                              message=f"AI agent runs on '{next(g for g in trig.groups() if g)}' events "
                                      f"with no author check")


# --------------------------------------------------------------------- unicode

_TAGS = re.compile("[\U000E0000-\U000E007F]+")
_BIDI = re.compile("[\u202A-\u202E\u2066-\u2069]")
_ZW = re.compile("[\u200B\u200C\u2060\u180E]|(?<!^)\uFEFF")
_ZWJ = re.compile("\u200D")
_VS_SUPP = re.compile("[\U000E0100-\U000E01EF]{2,}")
CODEISH = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt", ".c", ".cc",
           ".cpp", ".h", ".cs", ".rb", ".php", ".swift", ".sh", ".json", ".yml", ".yaml", ".toml", ".sol",
           ".tf", ".mdc"}


def decode_tags(run: str) -> str:
    return "".join(chr(ord(ch) - 0xE0000) if 0xE0020 <= ord(ch) <= 0xE007E else "" for ch in run)


class HiddenUnicodeScanner(Scanner):
    name = "hidden-unicode"
    category = C
    rules = [HIDDEN_TAGS, BIDI, ZERO_WIDTH, VARSEL]

    def applies(self, src: SourceFile) -> bool:
        return True

    def scan(self, src: SourceFile) -> Iterable[Finding]:
        text = src.text
        if text.isascii():
            return
        is_rules = bool(RULES_FILES.search(src.path))

        for m in _TAGS.finditer(text):
            line, col = src.line_of(m.start())
            hidden = decode_tags(m.group(0))
            yield Finding(HIDDEN_TAGS, src.path, line, col, _visible(src.lines[line - 1]),
                          message=f"Hidden text: \"{hidden[:200]}\"" if hidden else HIDDEN_TAGS.title,
                          extra={"hidden_text": hidden})
        for rx, rule in ((_BIDI, BIDI), (_VS_SUPP, VARSEL)):
            yield from self._per_line(src, rx, rule)
        if is_rules or src.suffix in CODEISH:
            yield from self._per_line(src, _ZW, ZERO_WIDTH)
        if is_rules:
            # ZWJ is how multi-part emoji are built (woman + ZWJ + laptop); only flag it elsewhere.
            done: set[int] = set()
            for m in _ZWJ.finditer(text):
                prev = text[m.start() - 1] if m.start() else ""
                nxt = text[m.end()] if m.end() < len(text) else ""
                if _is_emoji(prev) and _is_emoji(nxt):
                    continue
                line, col = src.line_of(m.start())
                if line not in done:
                    done.add(line)
                    yield Finding(ZERO_WIDTH, src.path, line, col, _visible(src.lines[line - 1]))

    @staticmethod
    def _per_line(src: SourceFile, rx: re.Pattern, rule: Rule) -> Iterable[Finding]:
        done: set[int] = set()
        for m in rx.finditer(src.text):
            line, col = src.line_of(m.start())
            if line in done:
                continue
            done.add(line)
            yield Finding(rule, src.path, line, col, _visible(src.lines[line - 1]))


def _is_emoji(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    return cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or cp == 0xFE0F


def _visible(line: str) -> str:
    """Show invisible characters as <U+XXXX> so the report is readable."""
    out = []
    for ch in line.strip():
        cp = ord(ch)
        if cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E) or 0x202A <= cp <= 0x202E or \
                0x2066 <= cp <= 0x2069:
            out.append(f"<U+{cp:04X}>")
        elif 0xE0000 <= cp <= 0xE01EF:
            if not out or not out[-1].startswith("<hidden"):
                out.append("<hidden>")
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= 160 else s[:159] + "…"
