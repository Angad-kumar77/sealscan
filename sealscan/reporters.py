"""Output formats: text, JSON and SARIF 2.1.0."""
import json
from collections import Counter

from sealscan import __version__
from sealscan.models import SEVERITY_ORDER, ScanResult
from sealscan.rules import all_rules

COLORS = {"critical": "\033[1;31m", "high": "\033[31m",
          "medium": "\033[33m", "low": "\033[36m"}
RESET = "\033[0m"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def render_text(result: ScanResult, color: bool = False) -> str:
    lines = []
    for f in result.findings:
        tag = "[%s]" % f.severity.upper()
        if color:
            tag = COLORS[f.severity] + tag + RESET
        lines.append("%s %s  %s:%d" % (tag, f.rule_id, f.path, f.line))
        if f.message:
            lines.append("    " + f.message)
        lines.append("    > " + f.snippet)
    if lines:
        lines.append("")
    if not result.findings:
        lines.append("sealscan: scanned %d files, no issues found." % result.files_scanned)
    else:
        counts = Counter(f.severity for f in result.findings)
        parts = ["%s: %d" % (s, counts[s]) for s in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)
                 if counts[s]]
        lines.append("sealscan: scanned %d files, %d issues (%s)"
                     % (result.files_scanned, len(result.findings), ", ".join(parts)))
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": {"name": "sealscan", "version": __version__},
        "files_scanned": result.files_scanned,
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


def render_sarif(result: ScanResult) -> str:
    rules = [{
        "id": r.id,
        "name": r.id,
        "shortDescription": {"text": r.title},
        "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
        "properties": {"category": r.category},
    } for r in all_rules()]
    results = [{
        "ruleId": f.rule_id,
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": "%s (%s)" % (f.message or f.title, f.snippet)},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.path},
            "region": {"startLine": f.line},
        }}],
    } for f in result.findings]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "sealscan", "version": __version__, "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
