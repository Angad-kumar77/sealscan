"""Shared data types."""
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CATEGORIES = ("secret", "vulnerability", "license")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    message: str = ""
    pattern: Optional[Any] = None   # compiled regex used for matching
    spdx: Optional[Any] = None      # compiled regex for SPDX ids (license rules)
    exts: Optional[frozenset] = None  # restrict to these file extensions
    generic: bool = False           # generic rules get value checks and yield to specific ones


@dataclass
class Finding:
    category: str
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    snippet: str
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    findings: List[Finding]
    files_scanned: int
