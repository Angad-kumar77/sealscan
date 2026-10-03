"""Command-line interface for sealscan."""
import argparse
import os
import sys
from pathlib import Path

from sealscan import __version__
from sealscan.config import CONFIG_FILENAME, ConfigError, load_config
from sealscan.models import CATEGORIES, SEVERITY_ORDER
from sealscan.reporters import render_json, render_sarif, render_text
from sealscan.rules import all_rules
from sealscan.scanner import ScanOptions, scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sealscan",
        description="Local-only scanner for secrets, insecure code and license risks. "
                    "Scan before you ship. No network calls, no telemetry.",
    )
    p.add_argument("path", nargs="?", default=".",
                   help="directory or file to scan (default: .)")
    p.add_argument("--version", action="version", version="sealscan " + __version__)
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text",
                   help="output format (default: text)")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER),
                   help="hide findings below this level (default: low)")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                   help="exit 1 if a finding is at or above this level (default: high)")
    p.add_argument("--only", metavar="LIST",
                   help="comma-separated categories to run: " + ",".join(CATEGORIES))
    p.add_argument("--disable", action="append", default=[], metavar="RULE_ID",
                   help="disable a rule (repeatable, or comma-separated)")
    p.add_argument("--config", metavar="FILE",
                   help="config file (default: %s in the scanned directory)" % CONFIG_FILENAME)
    p.add_argument("--no-gitignore", action="store_true",
                   help="also scan files that .gitignore excludes")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--list-rules", action="store_true", help="list all rules and exit")
    return p


def _csv(values):
    out = []
    for v in values:
        out.extend(x.strip() for x in v.split(",") if x.strip())
    return out


def _setup_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if os.name == "nt":
        os.system("")  # sealscan:ignore  (enables ANSI colors in the Windows console)


def _default_config(target: Path):
    base = target if target.is_dir() else target.parent
    return base / CONFIG_FILENAME


def main(argv=None) -> int:
    _setup_stdio()
    args = build_parser().parse_args(argv)

    catalog = {r.id: r for r in all_rules()}
    if args.list_rules:
        for r in sorted(catalog.values(), key=lambda r: (r.category, r.id)):
            print("%-30s %-9s %-14s %s" % (r.id, r.severity, r.category, r.title))
        return 0

    target = Path(args.path)
    if not target.exists():
        print("sealscan: error: path not found: %s" % args.path, file=sys.stderr)
        return 2

    try:
        cfg_path = Path(args.config) if args.config else _default_config(target)
        cfg = load_config(cfg_path)
    except ConfigError as exc:
        print("sealscan: config error: %s" % exc, file=sys.stderr)
        return 2

    categories = set(CATEGORIES)
    if args.only:
        categories = set(_csv([args.only]))
        bad = categories - set(CATEGORIES)
        if bad:
            print("sealscan: error: unknown category: %s" % ", ".join(sorted(bad)), file=sys.stderr)
            return 2

    disabled = set(cfg.get("disable_rules", [])) | set(_csv(args.disable))
    unknown = disabled - set(catalog)
    if unknown:
        print("sealscan: error: unknown rule id: %s (see --list-rules)"
              % ", ".join(sorted(unknown)), file=sys.stderr)
        return 2

    min_severity = args.min_severity or cfg.get("min_severity", "low")
    fail_on = args.fail_on or cfg.get("fail_on", "high")
    opts = ScanOptions(
        min_severity=min_severity,
        use_gitignore=not args.no_gitignore,
        extra_ignores=list(cfg.get("ignore", [])),
        disabled_rules=disabled,
        categories=categories,
    )

    try:
        result = scan(args.path, opts)
    except FileNotFoundError as exc:
        print("sealscan: error: %s" % exc, file=sys.stderr)
        return 2

    if args.format == "json":
        report = render_json(result)
    elif args.format == "sarif":
        report = render_sarif(result)
    else:
        color = (sys.stdout.isatty() and not args.no_color
                 and not os.environ.get("NO_COLOR") and not args.output)
        report = render_text(result, color=color)

    try:
        if args.output:
            Path(args.output).write_text(report + "\n", encoding="utf-8")
            print("sealscan: report written to %s (%d findings)" % (args.output, len(result.findings)))
        else:
            print(report)
            sys.stdout.flush()
    except BrokenPipeError:
        # e.g. `sealscan . | head`: stop quietly instead of printing a traceback
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass

    limit = SEVERITY_ORDER[fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= limit for f in result.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
