"""Locked scan plans. Missing binaries are skipped. Nothing is shelled through a string."""

from __future__ import annotations

import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path

from cybot.demo_app import DEMO_HOST, DEMO_PORT, create_demo_app
from cybot.rails import INTRUSIVE_TOOLS, ScanBudget, argv_is_safe, permit_scan, tool_allowed
from cybot.report import render_markdown
from cybot.scope import Scope
from cybot.store import Store, utcnow
from cybot.validate import validate_boolean, validate_reflection

REFLECT_MARKER = "cybot<probe"


@dataclass(frozen=True)
class Planned:
    name: str
    argv: tuple[str, ...]
    mode: str


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def plan_commands(mode: str, host: str, *, binaries: set[str] | None = None, workdir: str = "/tmp") -> list[Planned]:
    """Return locked argument lists for tools that are allowed and installed."""
    present = binaries if binaries is not None else {name for name in _CATALOG if _which(name)}
    root = Path(workdir)
    wordlist = str(root / "public-paths.txt")
    url = f"https://{host}" if host != DEMO_HOST else f"http://{DEMO_HOST}:{DEMO_PORT}/"
    commands = {
        "subfinder": ["subfinder", "-d", host, "-silent", "-nW", "-timeout", "15"],
        "dnsx": ["dnsx", "-silent", "-a", "-resp", "-retry", "1"],
        "whois": ["whois", host],
        "dig": ["dig", "+short", host],
        "httpx": ["httpx", "-silent", "-status-code", "-title", "-timeout", "8", "-no-color", "-u", url],
        "whatweb": ["whatweb", "--color=never", "-a", "1", url],
        "wafw00f": ["wafw00f", "-a", url],
        "naabu": ["naabu", "-host", host, "-p", "80,443,8080,8443", "-rate", "10", "-silent"],
        "nmap": ["nmap", "-sT", "-Pn", "-n", "--open", "-p", "80,443,8080,8443", host],
        "katana": ["katana", "-u", url, "-d", "1", "-silent", "-rate-limit", "2", "-timeout", "8"],
        "nuclei": [
            "nuclei",
            "-u",
            url,
            "-silent",
            "-rate-limit",
            "5",
            "-timeout",
            "8",
            "-severity",
            "info,low",
            "-tags",
            "exposure,tech,misconfig",
            "-exclude-tags",
            "rce,sqli,lfi,xss,dos",
        ],
        "ffuf": ["ffuf", "-u", url.rstrip("/") + "/FUZZ", "-w", wordlist, "-rate", "2", "-mc", "200", "-t", "1"],
        "gobuster": ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", "2", "-q", "--timeout", "8s"],
        "dalfox": ["dalfox", "url", url, "--worker", "1", "--delay", "300", "--timeout", "8", "--skip-mining-all", "--no-color"],
        "sqlmap": [
            "sqlmap",
            "-u",
            url,
            "--batch",
            "--technique=B",
            "--level=1",
            "--risk=1",
            "--threads=1",
            "--timeout=8",
            "--retries=0",
            "--disable-coloring",
            f"--output-dir={workdir}",
        ],
    }
    planned: list[Planned] = []
    for name, argv in commands.items():
        if name not in present:
            continue
        if not tool_allowed(name, mode):
            continue
        ok, _reason = argv_is_safe(argv, mode)
        if not ok:
            continue
        planned.append(Planned(name, tuple(argv), mode))
    return planned


_CATALOG = (
    "subfinder",
    "httpx",
    "naabu",
    "katana",
    "nuclei",
    "dnsx",
    "ffuf",
    "gobuster",
    "dalfox",
    "sqlmap",
    "nmap",
    "whatweb",
    "wafw00f",
    "dig",
    "whois",
)


def tool_status() -> list[dict]:
    rows = []
    for name in _CATALOG:
        installed = _which(name)
        rows.append(
            {
                "name": name,
                "title": name,
                "description": "Optional binary. Skipped when it is not installed. Argument list is locked.",
                "intensity": "active-test" if name in INTRUSIVE_TOOLS else ("soft-active" if name in {"httpx", "whatweb", "wafw00f", "naabu", "nmap"} else "passive"),
                "phase": "scan",
                "available": installed,
                "reason": "ready" if installed else f"binary {name} is not installed",
            }
        )
    return rows


def gate_plan(
    scope: Scope,
    host: str,
    mode: str,
    commands: list[Planned],
    *,
    active_approved: bool,
    attestation: str,
    budget: ScanBudget,
    allow_demo: bool = False,
) -> tuple[list[Planned], list[str]]:
    accepted: list[Planned] = []
    notes: list[str] = []
    for command in commands:
        ok, reason = argv_is_safe(list(command.argv), mode)
        if not ok:
            notes.append(f"{command.name} refused: {reason}")
            continue
        permit = permit_scan(
            scope,
            host,
            mode=mode,
            active_approved=active_approved,
            attestation=attestation,
            budget_ok=budget.allow(),
            rate_ok=True,
            allow_demo=allow_demo,
        )
        if not permit.allowed:
            notes.append(f"{command.name} refused: {permit.reason}")
            continue
        if not budget.take():
            notes.append(f"{command.name} refused: Scan budget is exhausted.")
            continue
        accepted.append(command)
    return accepted, notes


def execute_locked(commands: list[Planned], timeout: float = 12) -> list[str]:
    """Run already-gated argument lists. No shell string, no extra flags."""
    import subprocess

    notes: list[str] = []
    for command in commands:
        ok, reason = argv_is_safe(list(command.argv), command.mode)
        if not ok:
            notes.append(f"{command.name} refused: {reason}")
            continue
        try:
            completed = subprocess.run(
                list(command.argv),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
        except FileNotFoundError:
            notes.append(f"{command.name} skipped: binary is not installed.")
            continue
        except subprocess.TimeoutExpired:
            notes.append(f"{command.name} stopped: timeout.")
            continue
        text = " ".join((completed.stdout or completed.stderr or "").split())[:240]
        notes.append(f"{command.name} exit {completed.returncode}: {text or 'no output'}")
    return notes


def run_local_demo(store: Store, run_id: str) -> None:
    """Validate the bundled demo through Flask's client. No packet leaves the machine."""
    app = create_demo_app()
    client = app.test_client()
    reflected = client.get("/reflect", query_string={"q": REFLECT_MARKER})
    true_body = client.get("/lookup", query_string={"name": "widget' OR '1'='1"})
    false_body = client.get("/lookup", query_string={"name": "widget' AND '1'='2"})
    checks = [
        validate_reflection(reflected.get_data(as_text=True), REFLECT_MARKER),
        validate_boolean(true_body.get_data(as_text=True), false_body.get_data(as_text=True)),
    ]
    for index, item in enumerate(checks):
        if item.confidence < 0.4:
            store.event(run_id, "info", item.title)
            continue
        store.add_finding(
            id=secrets.token_hex(8),
            run_id=run_id,
            host=DEMO_HOST,
            tool="local-demo",
            severity="info",
            title=item.title,
            evidence=item.evidence,
            plain=item.plain,
            jev="",
            created_at=utcnow(),
            confidence=f"{item.confidence:.2f}",
            repro=item.repro,
            needs_human=1,
        )
        store.event(run_id, "ok", f"Demo check recorded ({item.confidence:.2f}). A person still has to retest it.")
    run = store.get_run(run_id)
    finished = dict(run or {})
    finished["status"] = "complete"
    markdown = render_markdown(finished, store.findings(run_id), store.recent_audit(40))
    store.save_report(run_id, markdown)
    store.event(run_id, "ok", "Local demo validation finished. Nothing was confirmed.")
    store.finish_run(run_id, "complete", "")
