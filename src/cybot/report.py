from __future__ import annotations

from fpdf import FPDF
from fpdf.enums import WrapMode

_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda row: (_ORDER.get(row.get("severity", "info"), 9), row.get("title", "")))


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
        lines.extend(
            [
                f"### [{finding['severity']}] {finding['title']}",
                "",
                f"- Host: `{finding['host']}`",
                f"- Tool: `{finding['tool']}`",
                f"- Evidence: {finding['evidence']}",
                "",
                finding.get("plain") or "",
                "",
            ]
        )
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
