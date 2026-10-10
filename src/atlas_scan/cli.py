"""Command line interface: ``atlas scan .``"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .engine import scan_path
from .models import CATEGORIES, Severity
from .reporters import FORMATS, to_text
from .scanners import all_rules, default_scanners
from .scanners.deps import DependencyScanner

SEVERITIES = [s.name.lower() for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="atlas",
        description="Scan a codebase for AI-era security risks: vibe-code flaws, leaked secrets, risky AI-agent "
                    "configs, hallucinated packages and quantum-weak crypto.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a folder or file")
    s.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: current folder)")
    s.add_argument("-f", "--format", choices=sorted(FORMATS), default="text", help="report format")
    s.add_argument("-o", "--output", help="write the report to this file instead of the screen")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low",
                   help="hide findings below this level (default: low)")
    s.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high",
                   help="exit with code 1 if any finding is at or above this level (default: high)")
    s.add_argument("--only", help=f"comma-separated categories to run: {', '.join(CATEGORIES)}")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this glob (repeatable); also reads .atlasignore")
    s.add_argument("--online", action="store_true",
                   help="ask PyPI/npm whether each dependency exists and how new it is")
    s.add_argument("--no-color", action="store_true", help="plain text output")
    s.add_argument("--inventory", action="store_true",
                   help="always include the crypto inventory, even with --min-severity above info")

    sub.add_parser("rules", help="list every rule")
    return p


def cmd_rules() -> int:
    current = None
    for r in sorted(all_rules(), key=lambda r: (list(CATEGORIES).index(r.category), r.id)):
        if r.category != current:
            current = r.category
            print(f"\n{CATEGORIES[current]}")
        print(f"  {r.id:8} {str(r.severity):9} {r.title}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if not os.path.exists(args.path):
        print(f"atlas: path not found: {args.path}", file=sys.stderr)
        return 2

    categories = None
    if args.only:
        categories = {c.strip() for c in args.only.split(",") if c.strip()}
        unknown = categories - set(CATEGORIES)
        if unknown:
            print(f"atlas: unknown category: {', '.join(sorted(unknown))}. "
                  f"Choose from: {', '.join(CATEGORIES)}", file=sys.stderr)
            return 2

    scanners = default_scanners()
    if args.online:
        scanners = [DependencyScanner(online=True) if isinstance(s, DependencyScanner) else s for s in scanners]

    min_sev = Severity.parse(args.min_severity)
    result = scan_path(args.path, scanners=scanners, min_severity=Severity.INFO, categories=categories,
                       extra_ignores=args.exclude)
    keep_inventory = args.inventory or args.format != "text" or min_sev <= Severity.LOW
    result.findings = [f for f in result.findings
                       if f.severity >= min_sev or (f.rule.id == "PQC000" and keep_inventory)]

    if args.format == "text":
        color = not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        report = to_text(result, color=color)
    else:
        report = FORMATS[args.format](result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"atlas: wrote {args.format} report to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(report)

    if result.excluded_everything:
        print("atlas: ignore patterns excluded every file, so nothing was scanned. "
              "Check .atlasignore and --exclude.", file=sys.stderr)
        return 2
    if args.fail_on == "never":
        return 0
    threshold = Severity.parse(args.fail_on)
    # Inventory items are planning notes, never a reason to fail a build.
    blocking = [f for f in result.findings if f.severity >= threshold and f.rule.kind != "inventory"]
    return 1 if blocking else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "rules":
            return cmd_rules()
        if args.command == "scan":
            return cmd_scan(args)
    except BrokenPipeError:  # e.g. `atlas rules | head`
        sys.stderr.close()
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
