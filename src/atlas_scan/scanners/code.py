# atlas: ignore-file  (this file defines the rules, so it contains the patterns it looks for)
"""Vibe-code flaws: insecure patterns AI coding assistants commonly produce.

Problem area 1. These are deliberately simple, explainable regex rules. They
are a safety net for AI-generated code, not a replacement for a full SAST tool.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..models import Finding, Rule, Severity, SourceFile
from . import PatternRule, Scanner

C = "vibe-code"
PY = {".py"}
JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
CODE = PY | JS | {".go", ".java", ".rb", ".php", ".rs", ".kt", ".cs"}
ALL: set[str] = set()  # empty = every text file

LLM_WORDS = r"(?:completion|choices|\.content|llm|gpt|claude|model_output|ai_response|generated|response\.text)"

R = PatternRule
_rules: list[PatternRule] = [
    # ---- AI-specific ----
    R(Rule("VIBE001", "LLM output is executed as code", Severity.CRITICAL, C,
           "Never eval/exec model output. Parse it into a fixed set of allowed actions instead.", "CWE-94"),
      rf"(?<![.\w])(?:eval|exec)\s*\([^\n]*{LLM_WORDS}", PY | JS, re.I),
    R(Rule("VIBE002", "Untrusted input placed in an LLM system prompt", Severity.MEDIUM, C,
           "Keep the system prompt constant. Put user text in a separate user message and treat it as data.",
           "CWE-77"),
      r"(?i)(?:system_?prompt|system_?message|system_?instructions)\s*[:=]\s*(?:f[\"'`]|`[^`\n]*\$\{|[^\n]*\+\s*\w|[^\n]*\.format\()"
      r"[^\n]*(?:request|user|input|query|body|params|message)",
      PY | JS),
    R(VIBE003 := Rule("VIBE003", "LLM output passed to a shell command", Severity.CRITICAL, C,
                      "Map model output onto an allow-list of commands; never run it directly.", "CWE-78"),
      rf"(?:subprocess\.\w+|os\.system|os\.popen)\s*\([^\n]*{LLM_WORDS}", PY, re.I),
    R(VIBE003, rf"(?<![.\w])(?:exec|execSync|spawn|spawnSync)\s*\([^\n]*{LLM_WORDS}", JS, re.I),

    # ---- Python ----
    R(Rule("VIBE010", "eval()/exec() on dynamic input", Severity.HIGH, C,
           "Use ast.literal_eval for data, or a dispatch table for actions.", "CWE-95"),
      r"(?<![.\w])(?:eval|exec)\s*\((?!\s*[\"'][^\"']*[\"']\s*\))", PY,
      unless=rf"(?i){LLM_WORDS}"),
    R(Rule("VIBE011", "subprocess with shell=True", Severity.HIGH, C,
           "Pass a list of arguments and drop shell=True.", "CWE-78"),
      r"shell\s*=\s*True", PY),
    R(Rule("VIBE012", "os.system/os.popen with a built string", Severity.HIGH, C,
           "Use subprocess.run([...]) with an argument list.", "CWE-78"),
      r"os\.(?:system|popen)\s*\(\s*(?:f[\"']|[^)\n]*(?:\+|%|\.format\())", PY),
    R(Rule("VIBE013", "SQL query built with string formatting", Severity.HIGH, C,
           "Use parameterised queries: cursor.execute(\"... WHERE id = %s\", (id,)).", "CWE-89"),
      r"\.execute(?:many)?\s*\(\s*(?:f[\"']|[\"'][^\"'\n]*[\"']\s*(?:%|\+|\.format))", PY),
    R(Rule("VIBE014", "Unsafe deserialisation (pickle)", Severity.MEDIUM, C,
           "Don't unpickle data you didn't create. Use JSON for anything from outside.", "CWE-502"),
      r"\b(?:pickle|cPickle|dill|joblib)\.loads?\s*\(", PY),
    R(Rule("VIBE015", "yaml.load without a safe loader", Severity.MEDIUM, C,
           "Use yaml.safe_load().", "CWE-502"),
      r"\byaml\.load\s*\(", PY, unless=r"Safe|BaseLoader|safe_load"),
    R(Rule("VIBE016", "TLS certificate verification disabled", Severity.HIGH, C,
           "Remove verify=False. Point at a CA bundle if you use a private CA.", "CWE-295"),
      r"verify\s*=\s*False", PY),
    R(Rule("VIBE017", "Debug mode enabled in web app", Severity.MEDIUM, C,
           "Read debug from an env var and keep it off in production.", "CWE-489"),
      r"\.run\([^)\n]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b", PY, re.M),
    R(Rule("VIBE018", "File path built from request data", Severity.HIGH, C,
           "Resolve the path and check it stays inside an allowed folder (or use werkzeug.secure_filename).",
           "CWE-22"),
      r"open\s*\([^)\n]*request\.(?:args|form|files|values|json|GET|POST|query_params)", PY),
    R(Rule("VIBE019", "Outbound request to a user-supplied URL", Severity.MEDIUM, C,
           "Allow-list hosts before fetching user-supplied URLs.", "CWE-918"),
      r"(?:requests|httpx|urllib\.request)\.\w+\s*\([^)\n]*request\.(?:args|form|json|values|GET|POST|query_params)",
      PY),

    # ---- JavaScript / TypeScript ----
    R(Rule("VIBE030", "eval() or new Function()", Severity.HIGH, C,
           "Avoid eval; use JSON.parse for data or a lookup table for behaviour.", "CWE-95"),
      r"(?<![.\w])eval\s*\(|\bnew\s+Function\s*\(", JS, unless=rf"(?i){LLM_WORDS}"),
    R(Rule("VIBE031", "Raw HTML injection (XSS risk)", Severity.MEDIUM, C,
           "Render text, or sanitise with DOMPurify before injecting HTML.", "CWE-79"),
      r"dangerouslySetInnerHTML|\.(?:inner|outer)HTML\s*=(?!=)|document\.write\s*\(|v-html\s*=",
      JS | {".html"}, unless=r"(?i)DOMPurify|sanitize"),
    R(Rule("VIBE032", "child_process command built from a string", Severity.HIGH, C,
           "Use execFile/spawn with an argument array.", "CWE-78"),
      r"\bexec(?:Sync)?\s*\(\s*(?:`[^`\n]*\$\{|[^)\n]*\+\s*\w)", JS),
    R(Rule("VIBE033", "SQL built with a template literal", Severity.HIGH, C,
           "Use placeholders ($1, ?) or your ORM's tagged template helper.", "CWE-89"),
      r"\.(?:query|execute|raw)\s*\(\s*`[^`]*\$\{|\$(?:queryRaw|executeRaw)Unsafe\s*\(", JS),
    R(Rule("VIBE034", "TLS certificate verification disabled", Severity.HIGH, C,
           "Remove rejectUnauthorized:false / NODE_TLS_REJECT_UNAUTHORIZED=0.", "CWE-295"),
      r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0", ALL),
    R(Rule("VIBE035", "Server secret exposed to the browser bundle", Severity.HIGH, C,
           "Variables with NEXT_PUBLIC_/VITE_/REACT_APP_/EXPO_PUBLIC_ are shipped to every visitor. Keep secrets "
           "server-side.", "CWE-200"),
      r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_\w*(?:SECRET|SERVICE_ROLE|PRIVATE|ADMIN_KEY|DB_PASS)\w*",
      ALL),

    # ---- Cross-language ----
    R(Rule("VIBE050", "Insecure random used for a secret value", Severity.MEDIUM, C,
           "Use secrets.token_urlsafe() (Python) or crypto.randomUUID()/getRandomValues() (JS).", "CWE-330"),
      r"(?i)\b\w*(?:token|secret|password|passwd|otp|nonce|salt|api_?key|session_?id)\w*\s*[:=][^\n]*"
      r"(?:\brandom\.(?:random|randint|choice|choices|getrandbits)\b|Math\.random\s*\()", PY | JS),
    R(Rule("VIBE051", "JWT signature check disabled or 'none' algorithm", Severity.HIGH, C,
           "Always verify signatures and pin the expected algorithm.", "CWE-347"),
      r"(?i)verify_signature[\"']?\s*:\s*False|verify\s*=\s*False[^\n]*jwt|algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']",
      PY | JS),
    R(Rule("VIBE052", "CORS allows any origin", Severity.MEDIUM, C,
           "List the exact origins that may call your API.", "CWE-942"),
      r"(?i)Access-Control-Allow-Origin[\"']?\s*[,:]\s*[\"']\*[\"']|origins?\s*[:=]\s*\[?\s*[\"']\*[\"']|"
      r"allow_origins\s*=\s*\[\s*[\"']\*[\"']",
      PY | JS),
    R(Rule("VIBE053", "CSRF protection disabled", Severity.MEDIUM, C,
           "Keep CSRF protection on for any cookie-authenticated endpoint.", "CWE-352"),
      r"@csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*:\s*false", PY | JS),
    R(Rule("VIBE054", "Unfinished security TODO left in code", Severity.LOW, C,
           "AI assistants often leave the hard part as a TODO. Finish it or track it before shipping.",
           "CWE-1188"),
      r"(?i)(?:#|//|/\*)\s*(?:TODO|FIXME|XXX|HACK)\b[^\n]*\b(?:auth\w*|permission|access control|"
      r"sanitiz\w*|validat\w*|rate.?limit|security|csrf|escape|encrypt\w*)",
      CODE),
]


class VibeCodeScanner(Scanner):
    name = "vibe-code"
    category = C
    rules = list({r.rule.id: r.rule for r in _rules}.values())

    def applies(self, src: SourceFile) -> bool:
        return True

    def scan(self, src: SourceFile) -> Iterable[Finding]:
        for rule in _rules:
            yield from rule.matches(src)
