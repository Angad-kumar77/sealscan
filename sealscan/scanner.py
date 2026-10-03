"""Core scanning engine. Standard library only, fully offline."""
import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from math import log2
from pathlib import Path
from typing import Iterator, List, Optional, Set

from sealscan import rules as R
from sealscan.ignore import IgnoreRules
from sealscan.models import CATEGORIES, SEVERITY_ORDER, Finding, Rule, ScanResult

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".idea", ".vscode", "site-packages",
}
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".tar", ".gz",
    ".bz2", ".7z", ".exe", ".dll", ".so", ".dylib", ".pyc", ".class", ".jar",
    ".woff", ".woff2", ".ttf", ".mp3", ".mp4", ".mov", ".lock", ".min.js",
}
MANIFESTS = {"package.json", "composer.json", "pyproject.toml", "setup.py",
             "setup.cfg", "cargo.toml"}
MAX_FILE_SIZE = 1_000_000
MAX_LINE_LENGTH = 2000
IGNORE_MARKER = "sealscan:ignore"
COMMENT_PREFIXES = ("#", "//", "/*", "*")
MIN_ENTROPY = 2.5

LICENSE_KV = re.compile(
    r"""(?i)\blicen[sc]e\s*[=:]\s*(?:\{\s*text\s*=\s*)?["']([^"']+)["']""")


@dataclass
class ScanOptions:
    min_severity: str = "low"
    use_gitignore: bool = True
    extra_ignores: List[str] = field(default_factory=list)
    disabled_rules: Set[str] = field(default_factory=set)
    categories: Set[str] = field(default_factory=lambda: set(CATEGORIES))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _redact(value: str) -> str:
    value = value.strip()
    return value if len(value) <= 8 else value[:4] + "*" * 6 + value[-2:]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * log2(c / n) for c in Counter(text).values())


def _looks_real(value: str) -> bool:
    low = value.lower()
    if value.startswith(("$", "%", "{", "<", "@")):
        return False
    if any(hint in low for hint in R.PLACEHOLDER_HINTS):
        return False
    return _entropy(value) >= MIN_ENTROPY


def _finding(rule: Rule, rel: str, line: int, snippet: str, message: str = "") -> Finding:
    return Finding(rule.category, rule.id, rule.title, rule.severity,
                   rel, line, snippet, message or rule.message)


def _match_secret(rule: Rule, line: str) -> Optional[str]:
    for m in rule.pattern.finditer(line):
        value = m.group(1) if m.groups() else m.group(0)
        if rule.generic and not _looks_real(value):
            continue
        return value
    return None


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:2048]:
        return None
    return data.decode("utf-8", errors="ignore")


def _sensitive_file_rule(name: str, ext: str) -> Optional[Rule]:
    env_rule, key_rule = R.SENSITIVE_FILE_RULES
    if name == ".env" or (name.startswith(".env.") and not name.endswith(R.ENV_EXAMPLE_SUFFIXES)):
        return env_rule
    if name in R.SENSITIVE_NAMES or ext in R.SENSITIVE_EXTS:
        return key_rule
    return None


# --------------------------------------------------------------------------
# per-file scanning
# --------------------------------------------------------------------------
def _scan_lines(text: str, rel: str, ext: str, opts: ScanOptions) -> List[Finding]:
    cats = opts.categories
    secret_rules = R.SECRET_RULES if "secret" in cats else ()
    vuln_rules = ([r for r in R.VULN_RULES if r.exts is None or ext in r.exts]
                  if "vulnerability" in cats else [])
    want_license = "license" in cats
    findings: List[Finding] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in raw:
            continue
        line = raw[:MAX_LINE_LENGTH]
        stripped = line.strip()
        if not stripped:
            continue

        hit_secret = False
        for rule in secret_rules:
            if rule.generic and hit_secret:
                continue
            value = _match_secret(rule, line)
            if value is not None:
                findings.append(_finding(rule, rel, lineno, _redact(value)))
                hit_secret = True

        if vuln_rules and not stripped.startswith(COMMENT_PREFIXES):
            for rule in vuln_rules:
                if rule.pattern.search(line):
                    findings.append(_finding(rule, rel, lineno, stripped[:120]))

        if want_license and "SPDX-License-Identifier" in line:
            m = R.SPDX_HEADER.search(line)
            if m:
                expr = m.group(1).replace("*/", "").strip()
                for rule in R.classify_spdx(expr):
                    findings.append(_finding(rule, rel, lineno, expr))
    return findings


def _scan_manifest(name: str, text: str, rel: str) -> List[Finding]:
    findings: List[Finding] = []
    if name in ("package.json", "composer.json"):
        try:
            data = json.loads(text)
        except ValueError:
            return findings
        lic = data.get("license") if isinstance(data, dict) else None
        exprs = [lic] if isinstance(lic, str) else (
            [x for x in lic if isinstance(x, str)] if isinstance(lic, list) else [])
        for expr in exprs:
            for rule in R.classify_spdx(expr):
                findings.append(_finding(rule, rel, 1, expr,
                                         "Project declares this license"))
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in LICENSE_KV.finditer(line):
            for rule in R.classify_spdx(m.group(1)):
                findings.append(_finding(rule, rel, lineno, m.group(1),
                                         "Project declares this license"))
        if "License ::" in line:
            rule = R.classify_text(line)
            if rule:
                findings.append(_finding(rule, rel, lineno, line.strip()[:120],
                                         "Project declares this license"))
    return findings


def scan_file(path: Path, base: Path, opts: ScanOptions) -> List[Finding]:
    try:
        rel = path.relative_to(base).as_posix()
    except ValueError:
        rel = path.name
    name = path.name.lower()
    ext = path.suffix.lower()
    cats = opts.categories
    findings: List[Finding] = []

    if "secret" in cats:
        rule = _sensitive_file_rule(name, ext)
        if rule:
            findings.append(_finding(rule, rel, 1, path.name))

    text = _read_text(path)
    if text is None:
        return findings

    if name.startswith(R.LICENSE_FILENAMES):
        if "license" in cats:
            rule = R.classify_text(text)
            if rule:
                findings.append(_finding(rule, rel, 1, "license file"))
        return findings

    findings.extend(_scan_lines(text, rel, ext, opts))
    if "license" in cats and name in MANIFESTS:
        findings.extend(_scan_manifest(name, text, rel))
    return findings


# --------------------------------------------------------------------------
# directory walking
# --------------------------------------------------------------------------
def _find_git_root(start: Path) -> Optional[Path]:
    for p in [start, *start.parents]:
        if (p / ".git").exists():
            return p
    return None


def _ancestor_matchers(root: Path) -> List[IgnoreRules]:
    """.gitignore files from the git root down to the parent of `root`."""
    git_root = _find_git_root(root)
    if git_root is None or git_root == root:
        return []
    matchers = []
    current = git_root
    for part in root.relative_to(git_root).parts:
        m = IgnoreRules.from_file(str(current), ".gitignore")
        if m:
            matchers.append(m)
        current = current / part
    return matchers


def _is_ignored(path: str, is_dir: bool, stack: List[IgnoreRules],
                cfg: Optional[IgnoreRules]) -> bool:
    if cfg is not None and cfg.match(path, is_dir):
        return True
    result = None
    for matcher in stack:
        r = matcher.match(path, is_dir)
        if r is not None:
            result = r
    return bool(result)


def _walk(directory: str, stack: List[IgnoreRules], cfg: Optional[IgnoreRules],
          opts: ScanOptions) -> Iterator[Path]:
    try:
        with os.scandir(directory) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return

    local = []
    if opts.use_gitignore:
        g = IgnoreRules.from_file(directory, ".gitignore")
        if g:
            local.append(g)
    s = IgnoreRules.from_file(directory, ".sealscanignore")
    if s:
        local.append(s)
    stack = stack + local

    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        name = entry.name
        if is_dir:
            if name in SKIP_DIRS or name.endswith(".egg-info"):
                continue
        elif os.path.splitext(name)[1].lower() in SKIP_EXTS or name.lower().endswith(".min.js"):
            continue
        if _is_ignored(entry.path, is_dir, stack, cfg):
            continue
        if is_dir:
            yield from _walk(entry.path, stack, cfg, opts)
        else:
            yield Path(entry.path)


def _iter_files(root: Path, opts: ScanOptions) -> Iterator[Path]:
    stack = _ancestor_matchers(root) if opts.use_gitignore else []
    cfg = IgnoreRules(str(root), opts.extra_ignores) if opts.extra_ignores else None
    yield from _walk(str(root), stack, cfg, opts)


def scan(target: str, options: Optional[ScanOptions] = None) -> ScanResult:
    opts = options or ScanOptions()
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError("Path not found: " + str(target))

    if root.is_file():
        files, base = [root], root.parent
    else:
        files, base = _iter_files(root, opts), root

    floor = SEVERITY_ORDER[opts.min_severity]
    findings: List[Finding] = []
    count = 0
    for f in files:
        count += 1
        for finding in scan_file(f, base, opts):
            if finding.rule_id in opts.disabled_rules:
                continue
            if SEVERITY_ORDER[finding.severity] < floor:
                continue
            findings.append(finding)

    findings.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.path, x.line, x.rule_id))
    return ScanResult(findings, count)
