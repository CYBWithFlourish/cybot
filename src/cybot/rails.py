"""Hard gates for every scan. A tool runs only after all of these pass."""

from __future__ import annotations

import time
from dataclasses import dataclass

from cybot.scope import Scope, check_scope

MODES = ("passive", "soft-active", "active-test")
MODE_RANK = {"passive": 0, "soft-active": 1, "active-test": 2}

# These tokens are refused in every mode, including active-test.
BANNED_TOKENS = (
    "sudo",
    "--os-shell",
    "--os-cmd",
    "--os-pwn",
    "--os-smbrelay",
    "--file-read",
    "--file-write",
    "--file-dest",
    "--dump",
    "--dump-all",
    "--sql-shell",
    "--reg-read",
    "--priv-esc",
    "--script",
    "--privileged",
    "--blind",
)

# Nmap scan-type flags. They are not global bans: curl uses -sS for
# silent plus show-errors. On nmap they need active-test and an attestation.
NMAP_RAW_FLAGS = frozenset({"-sS", "-sU", "-sA", "-sW", "-sN", "-sF", "-sX", "-sM"})

# Tools that send more than a single homepage or a fixed port connect.
INTRUSIVE_TOOLS = frozenset(
    {"katana", "nuclei", "ffuf", "gobuster", "dalfox", "sqlmap"}
)


@dataclass(frozen=True)
class Permit:
    allowed: bool
    reason: str
    host: str = ""
    mode: str = "passive"


@dataclass
class ScanBudget:
    max_requests: int = 40
    max_seconds: float = 120

    def __post_init__(self) -> None:
        self.remaining = self.max_requests
        self.deadline = time.monotonic() + self.max_seconds

    def allow(self) -> bool:
        return self.remaining > 0 and time.monotonic() <= self.deadline

    def take(self) -> bool:
        if not self.allow():
            return False
        self.remaining -= 1
        return True


def mode_rank(mode: str) -> int:
    if mode not in MODE_RANK:
        raise ValueError(f"Unknown scan mode {mode}.")
    return MODE_RANK[mode]


def derive_mode(mode: str, intensity: str) -> str:
    chosen = (mode or "").strip()
    if chosen:
        if chosen not in MODES:
            raise ValueError("Mode must be passive, soft-active, or active-test.")
        return chosen
    if intensity == "passive":
        return "passive"
    if intensity in {"light", "standard"}:
        return "soft-active"
    raise ValueError("Intensity must be passive, light, or standard.")


def attestation_ok(text: str) -> bool:
    cleaned = " ".join((text or "").split())
    if len(cleaned) < 40:
        return False
    return "authoriz" in cleaned.lower()


def tool_mode(name: str) -> str:
    if name in INTRUSIVE_TOOLS:
        return "active-test"
    if name in {"httpx", "whatweb", "wafw00f", "naabu", "nmap"}:
        return "soft-active"
    return "passive"


def tool_allowed(name: str, mode: str) -> bool:
    return mode_rank(tool_mode(name)) <= mode_rank(mode)


def argv_is_safe(argv: list[str], mode: str) -> tuple[bool, str]:
    if not argv:
        return False, "Empty command."
    binary = argv[0].rsplit("/", 1)[-1]
    if binary == "sudo" or any(part == "sudo" for part in argv):
        return False, "sudo is refused."
    for part in argv[1:]:
        if part in BANNED_TOKENS or any(part.startswith(token + "=") for token in BANNED_TOKENS):
            return False, f"{part} is refused in every mode."
    if binary == "nmap" and any(part in NMAP_RAW_FLAGS for part in argv[1:]):
        if mode_rank(mode) < mode_rank("active-test"):
            flagged = next(part for part in argv[1:] if part in NMAP_RAW_FLAGS)
            return False, f"nmap {flagged} requires active-test mode and an attestation."
    if not tool_allowed(binary, mode):
        return False, f"{binary} requires {tool_mode(binary)} mode."
    return True, "Argument list is within the locked set."


def permit_scan(
    scope: Scope,
    target: str,
    *,
    mode: str,
    active_approved: bool,
    attestation: str = "",
    budget_ok: bool = True,
    rate_ok: bool = True,
    allow_demo: bool = False,
) -> Permit:
    if mode not in MODES:
        return Permit(False, "Mode must be passive, soft-active, or active-test.")
    if not rate_ok:
        return Permit(False, "Rate limit reached. This check was not sent.", mode=mode)
    if not budget_ok:
        return Permit(False, "Scan budget is exhausted. This check was not sent.", mode=mode)
    if mode != "passive" and not active_approved:
        return Permit(False, "Soft-active and active-test are opt-in. Approve the check first.", mode=mode)
    if mode == "active-test" and not attestation_ok(attestation):
        return Permit(
            False,
            "Active-test needs an attestation of at least 40 characters that states you are authorized.",
            mode=mode,
        )
    decision = check_scope(scope, target, allow_demo=allow_demo and mode == "active-test")
    if not decision.allowed:
        return Permit(False, decision.reason, host=decision.host, mode=mode)
    if decision.host == "127.0.0.1" and not allow_demo:
        return Permit(False, "The local demo is off for this run.", host=decision.host, mode=mode)
    return Permit(True, decision.reason, host=decision.host, mode=mode)
