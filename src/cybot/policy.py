from __future__ import annotations

import re
from dataclasses import dataclass

from cybot.tools import ToolSpec, builtin_specs

INTENSITY = {"passive": 0, "light": 1, "standard": 2}

# Fail closed. A match on the tool name or description blocks the tool even
# if a user allow-list names it.
_DENY = re.compile(
    r"nuclei|ffuf|sqlmap|metasploit|msfvenom|hydra|hashcat|xsstrike|wfuzz|"
    r"dirsearch|arjun|gospider|exploit|payload|\brce\b|webshell|"
    r"reverse[\s_-]?shell|\bbrute|\bfuzz|credential|password|default[\s_-]?cred|"
    r"\bxss\b|\bsqli\b|\blfi\b|\brfi\b|\bnse\b|origin[\s_-]?bypass|\bpoc\b|"
    r"\bnmap\b",
    re.I,
)


@dataclass(frozen=True)
class ExternalTool:
    name: str
    description: str
    server_name: str
    mode: str
    server: dict


def rank(intensity: str) -> int:
    if intensity not in INTENSITY:
        raise ValueError(f"Unknown intensity {intensity}")
    return INTENSITY[intensity]


def vet_external(name: str, description: str, allow: list[str]) -> tuple[bool, str]:
    if name not in allow:
        return False, "not in this server's allow list (default deny)"
    if _DENY.search(f"{name} {description}"):
        return False, "blocked by the denylist (exploit, fuzzer, credential, or scanner class)"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
        return False, "tool name has unexpected characters"
    return True, "allow list match"


def select_builtin(
    intensity: str,
    *,
    secrets: set[str],
    binaries: set[str],
    phase: str,
    roles: set[str] | None = None,
) -> list[ToolSpec]:
    chosen: list[ToolSpec] = []
    ceiling = rank(intensity)
    granted = roles or set()
    for spec in builtin_specs():
        if spec.phase != phase:
            continue
        if rank(spec.intensity) > ceiling:
            continue
        if spec.needs_secret and spec.needs_secret not in secrets:
            continue
        if spec.needs_binary and spec.needs_binary not in binaries:
            continue
        if spec.needs_role and spec.needs_role not in granted:
            continue
        chosen.append(spec)
    return chosen


def external_specs(tools: list[ExternalTool], intensity: str, phase: str) -> list[ToolSpec]:
    ceiling = rank(intensity)
    specs: list[ToolSpec] = []
    for tool in tools:
        mode = tool.mode if tool.mode in INTENSITY else "standard"
        if rank(mode) > ceiling:
            continue
        # Attached servers are discover-phase only when passive, probe-phase when they touch a host.
        tool_phase = "discover" if mode == "passive" else "probe"
        if tool_phase != phase:
            continue
        ok, _reason = vet_external(tool.name, tool.description, [tool.name])
        if not ok:
            continue
        specs.append(
            ToolSpec(
                name=f"mcp:{tool.server_name}:{tool.name}",
                title=tool.name,
                description=tool.description,
                intensity=mode,
                phase=tool_phase,
                external=True,
                server_name=tool.server_name,
                remote_name=tool.name,
            )
        )
    return specs
