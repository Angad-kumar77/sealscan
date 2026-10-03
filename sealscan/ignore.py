"""Minimal .gitignore-style matcher (standard library only)."""
import os
import re
from typing import List, Optional, Tuple


def _glob_to_regex(pat: str) -> str:
    i, n, out = 0, len(pat), []
    while i < n:
        c = pat[i]
        if c == "*":
            if pat.startswith("**", i):
                j = i + 2
                at_start = i == 0 or pat[i - 1] == "/"
                if at_start and j < n and pat[j] == "/":
                    out.append("(?:.*/)?")
                    i = j + 1
                    continue
                out.append(".*")
                i = j
                continue
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 2)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                cls = pat[i + 1:j]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append("[" + cls.replace("\\", "\\\\") + "]")
                i = j + 1
        elif c == "\\" and i + 1 < n:
            out.append(re.escape(pat[i + 1]))
            i += 2
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


class IgnoreRules:
    """Rules from one ignore file, relative to the directory that holds it."""

    def __init__(self, base: str, lines: List[str]):
        self.base = base
        self.rules: List[Tuple] = []
        for raw in lines:
            self._add(raw)

    def _add(self, raw: str) -> None:
        line = raw.rstrip("\r\n")
        if not line or line.startswith("#"):
            return
        line = re.sub(r"(?<!\\)\s+$", "", line)
        if not line:
            return
        negate = False
        if line.startswith("!"):
            negate = True
            line = line[1:]
        elif line.startswith("\\!") or line.startswith("\\#"):
            line = line[1:]
        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")
        if not line:
            return
        anchored = line.startswith("/") or "/" in line
        line = line.lstrip("/")
        body = _glob_to_regex(line)
        prefix = "^" if anchored else "^(?:.*/)?"
        self.rules.append((re.compile(prefix + body + "$"), negate, dir_only))

    def match(self, path: str, is_dir: bool) -> Optional[bool]:
        """True = ignored, False = re-included, None = no rule matched."""
        rel = os.path.relpath(path, self.base).replace(os.sep, "/")
        result = None
        for regex, negate, dir_only in self.rules:
            if dir_only and not is_dir:
                continue
            if regex.match(rel):
                result = not negate
        return result

    @classmethod
    def from_file(cls, base: str, filename: str) -> Optional["IgnoreRules"]:
        path = os.path.join(base, filename)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return cls(base, f.read().splitlines())
        except OSError:
            return None
