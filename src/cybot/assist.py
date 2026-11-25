"""Per-finding guidance for a human researcher.

Answers stay inside the saved asset. Exploit code, WAF bypasses, and
out-of-scope origins are replaced with the playbook template.
"""

from __future__ import annotations

import re

from cybot.playbook import classify, loads_playbook, template_playbook
from cybot.redact import redact

ACTIONS = ("explain", "impact", "retest", "fix", "research", "ask")

_WEAPON = re.compile(
    r"union\s+select|<script|javascript:|onerror\s*=|waf\s*bypass|origin\s+ip|"
    r"sqlmap|metasploit|/etc/passwd|nc\s+-e|<?php",
    re.I,
)
_FENCE = re.compile(r"```.*?```", re.S)

SYSTEM = (
    "You advise one human bug bounty researcher about a single saved finding. "
    "The answer is guidance to validate by hand. It is not a confirmed vulnerability. "
    "Retest steps are manual checks (curl, a browser, or Burp) against the named in-scope asset only. "
    "Do not write exploit payloads, shells, automated attack scripts, WAF or CDN bypasses, "
    "or requests to any host other than the asset in the context. "
    "If the asset is 127.0.0.1, you may repeat the stored curl repro and nothing more. "
    "Remind the reader to stay inside the program scope. "
    "Do not invent reference URLs."
)


def is_local_demo(host: str) -> bool:
    return (host or "").strip().lower() in {"127.0.0.1", "localhost"}


def template_answer(action: str, finding: dict, book: dict) -> str:
    host = finding.get("host") or "the asset"
    title = finding.get("title") or "This note"
    kind = book.get("class") or classify(finding)
    local = is_local_demo(str(host))
    repro = redact(str(finding.get("repro") or "")).strip()
    steps = [str(item) for item in (book.get("verify") or book.get("next_steps") or [])[:4]]
    impact = book.get("impact") or "Unverified until a person retests it."
    why = book.get("why") or f"{title} is a reconnaissance note."
    refs = [
        f"{item.get('label')}: {item.get('url')}"
        for item in (book.get("references") or [])[:4]
        if item.get("url")
    ]
    if action == "impact":
        body = f"Impact, unverified: {impact} Severity on the card is {finding.get('severity') or 'info'}."
    elif action == "retest":
        lines = [f"Manual retest for {host}. Stay inside the program scope."]
        if local and repro:
            lines.append("Local demo only. Repeat the saved request:")
            lines.append(repro)
        else:
            lines.append("Use curl, a browser, or Burp against this in-scope asset only.")
            lines.extend(f"- {step}" for step in steps)
            lines.append("Do not send exploit payloads. Stop if the asset is outside the written scope.")
        body = "\n".join(lines)
    elif action == "fix":
        body = _fix_text(kind, host)
    elif action == "research":
        body = "Related reading from the saved playbook:\n" + ("\n".join(f"- {item}" for item in refs) or "- No catalog links were stored.")
    elif action == "ask":
        body = f"{why} Answer only for {host}, and only after a person retests it."
    else:
        body = f"{why} This is not a confirmed vulnerability."
    return guard_answer(body, str(host)) or body


def _fix_text(kind: str, host: str) -> str:
    if kind == "headers":
        return (
            f"Suggested fix for {host}: add the missing browser headers (HSTS, nosniff, CSP) "
            "after you confirm the response. This is hardening, not proof of a vulnerability."
        )
    if kind == "cve":
        return (
            f"Suggested fix for {host}: if a person confirms the version is in the affected range, "
            "upgrade or apply the vendor advisory. Do not exploit the issue to prove it."
        )
    if kind == "endpoint":
        return (
            f"Suggested fix for {host}: remove or restrict the public path if it should not be exposed. "
            "Confirm the contents manually first."
        )
    return (
        f"Suggested fix for {host}: reduce exposure only after a person confirms the note. "
        "Keep the change inside the program scope."
    )


def guard_answer(text: str, host: str) -> str:
    cleaned = redact(text or "").strip()
    if not cleaned:
        return ""
    local = is_local_demo(host)
    if not local:
        if _WEAPON.search(cleaned):
            return ""
        cleaned = _FENCE.sub("[code block removed]", cleaned).strip()
    if "scope" not in cleaned.lower():
        cleaned += "\n\nStay inside the program scope. A person must retest this before reporting it."
    return cleaned[:4000]


def context_block(finding: dict, book: dict, kb: list[dict]) -> str:
    refs = "; ".join(
        f"{item.get('label')} {item.get('url')}" for item in (book.get("references") or [])[:6] if item.get("url")
    )
    steps = "; ".join(str(item) for item in (book.get("next_steps") or [])[:4])
    reading = "; ".join(f"{item.get('title')} {item.get('url')}" for item in kb[:4] if item.get("url"))
    return "\n".join(
        [
            f"Title: {finding.get('title') or ''}",
            f"Severity: {finding.get('severity') or ''}",
            f"Asset: {finding.get('host') or ''}",
            f"Evidence: {redact(str(finding.get('evidence') or ''))[:800]}",
            f"Confidence: {finding.get('confidence') or 'n/a'}",
            f"Needs human validation: {finding.get('needs_human', 1)}",
            f"Curl repro: {redact(str(finding.get('repro') or ''))[:500]}",
            f"Playbook next steps: {steps}",
            f"Playbook references: {refs}",
            f"Knowledge base: {reading}",
        ]
    )
