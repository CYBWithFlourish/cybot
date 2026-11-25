import json

from cybot.playbook import (
    classify,
    reference_links,
    template_playbook,
    apply_narratives,
)
from cybot.report import render_markdown
from tests.test_api import DEMO, HEADERS


CVE = {
    "id": "f1",
    "host": "www.example.com",
    "tool": "nvd_cves",
    "severity": "medium",
    "title": "Unverified: CVE-2026-0001 mentions nginx",
    "evidence": "CVSS unknown; keyword nginx 1.25.3; not confirmed on this host",
    "plain": "NVD keyword hit only.",
}


def test_reference_links_are_built_from_the_cve_id():
    links = {item["label"]: item["url"] for item in reference_links(CVE)}
    assert links["NVD"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    assert links["CVE.org"] == "https://www.cve.org/CVERecord?id=CVE-2026-0001"
    assert links["Exploit-DB search"] == "https://www.exploit-db.com/search?cve=CVE-2026-0001"
    assert links["GitHub PoC search"] == "https://github.com/search?q=CVE-2026-0001&type=repositories"
    assert links["CWE-1395"] == "https://cwe.mitre.org/data/definitions/1395.html"
    assert all(item["url"].startswith("https://") for item in reference_links(CVE))
    assert classify({"title": "Missing security headers", "tool": "header_hygiene", "evidence": ""}) == "headers"


def test_template_fallback_when_the_model_fails():
    import asyncio

    class Broken:
        name = "gemini"

        async def complete(self, system, user):
            raise RuntimeError("LLMError: Gemini returned no text (SAFETY).")

    base = [template_playbook(CVE)]
    books = asyncio.run(apply_narratives(Broken(), [CVE], base))
    assert books[0]["source"] == "template"
    assert "CVE-2026-0001" in books[0]["why"]
    assert any("curl -fsSI" in step for step in books[0]["verify"])
    assert "www.example.com" in books[0]["verify"][0]
    assert "exploit payload" not in " ".join(books[0]["verify"]).lower() or "do not send" in " ".join(books[0]["verify"]).lower()


def test_report_includes_the_playbook_for_the_demo_cve(client):
    started = client.post("/api/runs", headers=HEADERS, json=DEMO)
    assert started.status_code == 200, started.text
    report = client.get(f"/api/runs/{started.json()['id']}/report.md", headers=HEADERS)
    assert "attachment" in report.headers.get("content-disposition", "")
    text = report.text
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" in text
    assert "never runs exploits" in text
    assert "### Steps to reproduce" in text
    assert "No audit rows" not in text
    findings = client.get(f"/api/runs/{started.json()['id']}/findings", headers=HEADERS).json()["findings"]
    cve = next(row for row in findings if "CVE-2026-0001" in row["title"])
    urls = [item["url"] for item in cve["playbook"]["references"]]
    assert any(url.endswith("CVE-2026-0001") for url in urls)
    assert "https://cwe.mitre.org/data/definitions/1395.html" in urls
    rendered = render_markdown(
        {"program": "CYBOT demo", "target": "www.example.com", "status": "complete", "playbook": json.dumps({"surface": "notes", "stack": ["nginx"], "services": [], "endpoints": [], "scope": {}})},
        [{**CVE, "playbook": json.dumps(template_playbook(CVE))}],
        [],
    )
    assert "https://www.exploit-db.com/search?cve=CVE-2026-0001" in rendered
