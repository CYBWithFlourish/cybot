from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"sk-or-v1-[A-Za-z0-9]+"),
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"xai-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{10,}"),
    re.compile(r"ghp_[A-Za-z0-9]{10,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{10,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{6,}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password|apikey)\s*[=:]\s*\S+"),
    re.compile(r"https://api\.shodan\.io/\S+"),
    re.compile(r"https://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_\-]+"),
    re.compile(r"(?i)x-apikey['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9]+"),
]


def redact(text: str) -> str:
    if not text:
        return ""
    out = str(text)
    for pattern in _PATTERNS:
        out = pattern.sub("[redacted]", out)
    return out
