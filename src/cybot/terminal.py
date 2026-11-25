"""Allowlisted command runner.

Every host, URL, and IP is checked against the scope gate before the process
starts. Active-test waits for confirmation. Output is capped and timed out.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

from cybot.rails import BANNED_TOKENS, ScanBudget, attestation_ok, mode_rank
from cybot.scope import Scope, check_scope, ip_is_public

ALLOWLIST = frozenset(
    {
        "curl",
        "httpx",
        "gobuster",
        "ffuf",
        "dig",
        "whois",
        "nslookup",
        "host",
        "nmap",
        "openssl",
        "whatweb",
        "wafw00f",
        "jq",
        "grep",
        "sed",
    }
)

MIN_MODE = {
    "dig": "passive",
    "whois": "passive",
    "nslookup": "passive",
    "host": "passive",
    "jq": "passive",
    "grep": "passive",
    "sed": "passive",
    "curl": "soft-active",
    "httpx": "soft-active",
    "nmap": "soft-active",
    "openssl": "soft-active",
    "whatweb": "soft-active",
    "wafw00f": "soft-active",
    "ffuf": "active-test",
    "gobuster": "active-test",
}

INTRUSIVE_FLAGS = frozenset({"-A", "-sV", "-sC", "-p-", "--script", "--data", "--data-raw", "--data-binary", "-d"})
WRITE_FLAGS = frozenset({"-o", "--output", "--output-dir", "-w", "--wordlist"})
OUTPUT_CAP = 4000
DEFAULT_TIMEOUT = 15
MAX_STEPS = 6

_URL_HOST = re.compile(r"https?://([^/\s:@]+)", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_FILE = re.compile(r"(?i)\.(txt|json|xml|lst|log|md|csv|out|html|pdf)$")
_SHELL = re.compile(r"[;&|`$<>]|\$\(")


def parse_command(command: str) -> tuple[list[str] | None, str]:
    text = (command or "").strip()
    if not text:
        return None, "Command is empty."
    if _SHELL.search(text):
        return None, "Pipes, redirects, and command separators are refused."
    try:
        argv = shlex.split(text)
    except ValueError:
        return None, "Command could not be parsed."
    if not argv:
        return None, "Command is empty."
    binary = Path(argv[0]).name
    if binary not in ALLOWLIST:
        return None, f"{binary} is not an allowlisted command."
    argv[0] = binary
    return argv, ""


def extract_targets(argv: list[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        host = value.strip().strip("[]").rstrip(".").lower()
        if host.startswith("*."):
            host = host[2:]
        if ":" in host and host.count(":") == 1 and not host.startswith("http"):
            host = host.split(":", 1)[0]
        if not host or host in seen:
            return
        seen.add(host)
        found.append(host)

    for token in argv[1:]:
        for match in _URL_HOST.findall(token):
            add(match)
        for match in _IPV4.findall(token):
            add(match)
        bare = token.strip("'\"")
        if _DOMAIN.fullmatch(bare) and not _FILE.search(bare):
            add(bare)
        if bare.lower().startswith("host:"):
            add(bare.split(":", 1)[1])
    return found


def _paths_ok(argv: list[str], workdir: Path) -> str:
    root = workdir.resolve()
    previous = ""
    for token in argv[1:]:
        if previous in WRITE_FLAGS or token.startswith("/") or token.startswith("./") or token.startswith("../"):
            if "://" in token:
                previous = token
                continue
            path = Path(token)
            if not path.is_absolute():
                path = root / path
            try:
                path.resolve().relative_to(root)
            except ValueError:
                return f"{token} is outside the run work directory."
        previous = token
    return ""


def prepare_command(
    command: str,
    scope: Scope,
    *,
    mode: str,
    workdir: Path,
    attestation: str = "",
    allow_demo: bool = False,
    budget_ok: bool = True,
    rate_ok: bool = True,
) -> dict:
    argv, error = parse_command(command)
    if argv is None:
        return {"ok": False, "reason": error, "argv": [], "targets": []}
    binary = argv[0]
    if any(part == "sudo" or part in BANNED_TOKENS for part in argv):
        return {"ok": False, "reason": "That flag is refused in every mode.", "argv": argv, "targets": []}
    path_error = _paths_ok(argv, workdir)
    if path_error:
        return {"ok": False, "reason": path_error, "argv": argv, "targets": []}
    intrusive = binary in {"ffuf", "gobuster"} or any(part in INTRUSIVE_FLAGS for part in argv)
    needed = "active-test" if intrusive else MIN_MODE[binary]
    if mode_rank(needed) > mode_rank(mode):
        return {
            "ok": False,
            "reason": f"{binary} needs {needed} mode.",
            "argv": argv,
            "targets": extract_targets(argv),
        }
    if needed == "active-test" and not attestation_ok(attestation):
        return {
            "ok": False,
            "reason": "Active-test needs an attestation of at least 40 characters that states you are authorized.",
            "argv": argv,
            "targets": extract_targets(argv),
        }
    if not budget_ok:
        return {"ok": False, "reason": "Scan budget is exhausted.", "argv": argv, "targets": []}
    if not rate_ok:
        return {"ok": False, "reason": "Rate limit reached.", "argv": argv, "targets": []}
    targets = extract_targets(argv)
    for target in targets:
        if _looks_private(target) and not (allow_demo and target == "127.0.0.1"):
            return {
                "ok": False,
                "reason": f"{target} is a private, loopback, or metadata address.",
                "argv": argv,
                "targets": targets,
            }
        decision = check_scope(scope, target, allow_demo=allow_demo and target == "127.0.0.1")
        if not decision.allowed:
            return {"ok": False, "reason": decision.reason, "argv": argv, "targets": targets}
    return {"ok": True, "reason": "Command is inside the rails.", "argv": argv, "targets": targets}


def _looks_private(target: str) -> bool:
    if not _IPV4.fullmatch(target):
        return False
    return not ip_is_public(target)


def run_prepared(
    prepared: dict,
    *,
    workdir: Path,
    timeout: float = DEFAULT_TIMEOUT,
    runner=None,
) -> dict:
    if not prepared.get("ok"):
        return {"status": "refused", "output": prepared.get("reason") or "Refused.", "argv": prepared.get("argv") or []}
    argv = prepared["argv"]
    workdir.mkdir(parents=True, exist_ok=True)

    def _default(args, limit, folder):
        return subprocess.run(
            args,
            cwd=str(folder),
            capture_output=True,
            text=True,
            timeout=limit,
            shell=False,
            check=False,
        )

    try:
        completed = (runner or _default)(argv, timeout, workdir)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "output": f"Stopped after {timeout:.0f}s.", "argv": argv}
    if isinstance(completed, subprocess.CompletedProcess):
        text = (completed.stdout or "") + (completed.stderr or "")
        status = "ok" if completed.returncode == 0 else "exit"
    else:
        text = str(completed)
        status = "ok"
    if len(text) > OUTPUT_CAP:
        text = text[:OUTPUT_CAP] + "\n[output capped]"
    return {"status": status, "output": text.strip() or "no output", "argv": argv}


def submit_command(
    store,
    run: dict,
    scope: Scope,
    command: str,
    *,
    workdir: Path,
    confirmed: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    budget: ScanBudget | None = None,
    rate_ok: bool = True,
    allow_demo: bool = False,
    runner=None,
) -> dict:
    mode = run.get("mode") or "passive"
    budget_ok = True if budget is None else budget.allow()
    prepared = prepare_command(
        command,
        scope,
        mode=mode,
        workdir=workdir,
        attestation=run.get("attestation") or "",
        allow_demo=allow_demo,
        budget_ok=budget_ok,
        rate_ok=rate_ok,
    )
    targets = ", ".join(prepared.get("targets") or []) or run.get("target") or ""
    if not prepared["ok"]:
        store.audit("terminal", targets[:253], "refused", prepared["reason"], run.get("id"))
        store.add_terminal(run["id"], command, "refused", prepared["reason"])
        return {"status": "refused", "output": prepared["reason"], "command": command}
    if mode == "active-test" and not confirmed:
        store.audit("terminal", targets[:253], "pending", "Waiting for confirmation.", run.get("id"))
        store.add_terminal(run["id"], command, "pending", "Confirm this active-test command before it runs.")
        return {"status": "pending", "output": "Confirm this active-test command before it runs.", "command": command}
    if budget is not None and not budget.take():
        store.audit("terminal", targets[:253], "refused", "Scan budget is exhausted.", run.get("id"))
        store.add_terminal(run["id"], command, "refused", "Scan budget is exhausted.")
        return {"status": "refused", "output": "Scan budget is exhausted.", "command": command}
    result = run_prepared(prepared, workdir=workdir, timeout=timeout, runner=runner)
    store.audit("terminal", targets[:253], result["status"], result["output"][:300], run.get("id"))
    store.add_terminal(run["id"], command, result["status"], result["output"])
    return {"status": result["status"], "output": result["output"], "command": command}


def react_loop(
    store,
    run: dict,
    scope: Scope,
    decide,
    *,
    workdir: Path,
    max_steps: int = MAX_STEPS,
    confirmed: bool = False,
    runner=None,
    budget: ScanBudget | None = None,
    allow_demo: bool = False,
) -> list[dict]:
    """Observe, then decide. Stops at max_steps or when the decider is done."""
    steps = []
    observations: list[dict] = []
    for _ in range(max(1, min(max_steps, MAX_STEPS))):
        choice = decide(observations) or {}
        if choice.get("done") or not choice.get("command"):
            break
        result = submit_command(
            store,
            run,
            scope,
            str(choice["command"]),
            workdir=workdir,
            confirmed=confirmed or (run.get("mode") or "passive") != "active-test",
            budget=budget,
            allow_demo=allow_demo,
            runner=runner,
        )
        observations.append(result)
        steps.append(result)
        if result["status"] in {"refused", "pending", "timeout"}:
            break
    return steps
