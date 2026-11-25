from __future__ import annotations

import re

from fpdf import FPDF
from fpdf.enums import WrapMode

from cybot.redact import redact

_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda row: (_ORDER.get(row.get("severity", "info"), 9), row.get("title", "")))


def finding_card_markdown(finding: dict) -> str:
    """HackerOne and Bugcrowd style note. Evidence is redacted. Not a confirmed issue."""
    from cybot.playbook import classify, cwe_numbers, loads_playbook

    book = loads_playbook(finding.get("playbook")) or {}
    host = finding.get("host") or ""
    title = finding.get("title") or "Finding"
    severity = finding.get("severity") or "info"
    kind = book.get("class") or classify(finding)
    cwes = cwe_numbers(finding, kind)
    weakness = f"CWE-{cwes[0]}" if cwes else "Not classified"
    rationale = _cvss_rationale(str(finding.get("evidence") or ""), severity)
    steps = _repro_steps(finding, book)
    refs = [
        f"- {item.get('label')}: {item.get('url')}"
        for item in (book.get("references") or [])
        if item.get("url")
    ]
    further = [
        f"- {item.get('label')}: {item.get('url')}"
        for item in (book.get("further_reading") or [])
        if item.get("url")
    ]
    confidence = finding.get("confidence") or "n/a"
    human = "yes" if finding.get("needs_human", finding.get("needs_human_validation", 1)) else "no"
    lines = [
        f"## {title}",
        "",
        f"- Severity: {severity}",
        f"- Severity rationale: {rationale}",
        f"- Asset: `{host}`",
        f"- Weakness: {weakness}",
        "",
        "### Summary",
        "",
        redact(str(finding.get("plain") or book.get("why") or "Reconnaissance note. Not confirmed.")),
        "",
        "### Steps to reproduce",
        "",
    ]
    lines.extend(steps or ["1. Review the saved evidence. A person must retest it inside program scope."])
    lines.extend(
        [
            "",
            "### Evidence",
            "",
            redact(str(finding.get("evidence") or "No response snippet was stored.")),
            "",
            "### Impact",
            "",
            str(book.get("impact") or "Unverified until a person retests it."),
            "",
            "### Suggested fix",
            "",
            _fix_line(kind, host),
            "",
            "### References",
            "",
        ]
    )
    lines.extend(refs or ["- No reference links were stored."])
    if further:
        lines.extend(["", "### Further reading", ""])
        lines.extend(further)
    lines.extend(
        [
            "",
            "### Validation",
            "",
            f"- Confidence: {confidence}",
            f"- Needs human validation: {human}",
            "",
            "This is not a confirmed vulnerability. Stay inside the program scope.",
            "",
        ]
    )
    return "\n".join(lines)


def _cvss_rationale(evidence: str, severity: str) -> str:
    match = re.search(r"CVSS[^.;]{0,40}", evidence, re.I)
    if match:
        return f"{match.group(0).strip()} (from the stored note, not a confirmed score on this asset)."
    return f"Mapped from CYBOT severity '{severity}'. Not a confirmed CVSS score."


def _repro_steps(finding: dict, book: dict) -> list[str]:
    steps = []
    repro = redact(str(finding.get("repro") or "")).strip()
    if repro:
        for index, line in enumerate(repro.splitlines(), start=1):
            if line.strip():
                steps.append(f"{index}. `{line.strip()}`")
    start = len(steps) + 1
    for offset, item in enumerate(book.get("verify") or []):
        steps.append(f"{start + offset}. {item}")
    return steps[:8]


def _fix_line(kind: str, host: str) -> str:
    from cybot.assist import _fix_text

    return _fix_text(kind, host or "the asset")


def render_markdown(run: dict, findings: list[dict], audit: list[dict]) -> str:
    from cybot.playbook import loads_playbook, render_playbook_markdown, render_target_markdown

    findings = sort_findings(findings)
    lines = [
        "# CYBOT recon report",
        "",
        f"- Program: {run.get('program', '')}",
        f"- Target: {run.get('target', '')}",
        f"- Intensity: {run.get('intensity', '')}",
        f"- Provider: {run.get('provider', '')}",
        f"- Model: {run.get('model') or 'none'}",
        f"- Source: {run.get('source', '')}",
        f"- Started: {run.get('created_at', '')}",
        f"- Status: {run.get('status', '')}",
        "",
        "These notes are reconnaissance observations. They are not confirmed vulnerabilities",
        "and they are not exploit instructions. CYBOT contacted a host only after the scope",
        "gate allowed it, and it logged the authorization statement with the scope hash.",
        "",
        "Only test in-scope assets with authorization. No auto-exploitation - CYBOT only suggests, never runs exploits.",
        "",
    ]
    lines.extend(render_target_markdown(loads_playbook(run.get("playbook")) or {}))
    lines.extend(["## Findings", ""])
    if not findings:
        lines.append("No findings were recorded.")
        lines.append("")
    for finding in findings:
        lines.append(finding_card_markdown(finding))
        book = loads_playbook(finding.get("playbook"))
        if book:
            lines.extend(render_playbook_markdown(book))
    lines.extend(["## Authorization log", ""])
    related = [row for row in audit if row.get("run_id") in {run.get("id"), None}]
    if not related:
        lines.append("No audit rows were attached to this run.")
    for row in related[:30]:
        lines.append(
            f"- {row['ts']} {row['decision']} {row['target']}: {row['detail']}"
        )
    lines.extend(
        [
            "",
            "## What CYBOT did not do",
            "",
            "- No exploit templates, fuzzing, credential attacks, or payload tools.",
            "- No requests to names that failed the scope check.",
            "- No confirmed-vulnerability claims from a version header alone.",
            "",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def _soften(text: str) -> str:
    pieces: list[str] = []
    for word in text.split(" "):
        while len(word) > 48:
            pieces.append(word[:48])
            word = word[48:]
        pieces.append(word)
    return " ".join(pieces)


def render_pdf(markdown: str) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    for paragraph in markdown.splitlines():
        safe = _soften(paragraph).encode("latin-1", "replace").decode("latin-1") or " "
        if safe.startswith("# "):
            pdf.set_font("Helvetica", "B", 16)
            pdf.multi_cell(pdf.epw, 8, safe[2:], wrapmode=WrapMode.CHAR)
            pdf.set_font("Helvetica", size=11)
        elif safe.startswith("## "):
            pdf.ln(2)
            pdf.set_font("Helvetica", "B", 13)
            pdf.multi_cell(pdf.epw, 7, safe[3:], wrapmode=WrapMode.CHAR)
            pdf.set_font("Helvetica", size=11)
        elif safe.startswith("### "):
            pdf.set_font("Helvetica", "B", 12)
            pdf.multi_cell(pdf.epw, 6, safe[4:], wrapmode=WrapMode.CHAR)
            pdf.set_font("Helvetica", size=11)
        else:
            pdf.multi_cell(pdf.epw, 5, safe, wrapmode=WrapMode.CHAR)
    return bytes(pdf.output())
