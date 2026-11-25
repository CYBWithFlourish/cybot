"""Research playbooks for a human tester.

Reference URLs are built from identifiers. The model may write the narrative,
but it does not choose links. If the model fails, a fixed template is used.
CYBOT never runs the suggested commands.
"""

from __future__ import annotations

import inspect
import json
import re
from urllib.parse import quote

from cybot.llm import (
    GEMINI_MAX_OUTPUT_TOKENS,
    LLMError,
    NARRATIVE_SCHEMA,
    STRICT_NARRATIVE,
    TRIAGE_CHUNK,
    parse_model_json,
    snippet_text,
)

DISCLAIMER = (
    "Only test in-scope assets with authorization. "
    "No auto-exploitation - CYBOT only suggests, never runs exploits. "
    "Every item below is unverified until you confirm it."
)

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_CWE = re.compile(r"CWE-(\d+)", re.I)
_URL = re.compile(r"https?://\S+")
_HOST = re.compile(r"^[A-Za-z0-9._-]{1,253}$")

# Curated pages for common classes. The model cannot add to this list.
TOPICS = {
    "xss": {
        "cwe": 79,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
        "portswigger": "https://portswigger.net/web-security/cross-site-scripting",
        "hacktricks": "https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting.html",
        "nuclei": "http/vulnerabilities/generic/xss-reflected",
    },
    "ssrf": {
        "cwe": 918,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
        "portswigger": "https://portswigger.net/web-security/ssrf",
        "hacktricks": "https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery.html",
        "nuclei": "http/vulnerabilities/generic/ssrf-detection",
    },
    "idor": {
        "cwe": 639,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        "portswigger": "https://portswigger.net/web-security/access-control/idor",
        "hacktricks": "https://book.hacktricks.wiki/en/pentesting-web/idor.html",
        "nuclei": "http/vulnerabilities/generic/idor",
    },
    "redirect": {
        "cwe": 601,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
        "portswigger": "https://portswigger.net/web-security/dom-based/open-redirection",
        "hacktricks": "https://book.hacktricks.wiki/en/pentesting-web/open-redirect.html",
        "nuclei": "http/vulnerabilities/generic/open-redirect",
    },
    "headers": {
        "cwe": 693,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",
        "portswigger": "https://portswigger.net/kb/issues/01000300_strict-transport-security-not-enforced",
        "hacktricks": "https://book.hacktricks.wiki/en/pentesting-web/hardening-http-headers.html",
        "nuclei": "http/misconfiguration/http-missing-security-headers",
    },
    "tls": {
        "cwe": 326,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
        "portswigger": "https://portswigger.net/kb/issues/01000300_strict-transport-security-not-enforced",
        "hacktricks": "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/pentesting-web-checklist.html",
        "nuclei": "ssl/tls-version",
    },
    "takeover": {
        "cwe": 1395,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
        "portswigger": "https://portswigger.net/web-security/host-header",
        "hacktricks": "https://book.hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html",
        "nuclei": "http/takeovers",
    },
    "admin": {
        "cwe": 200,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
        "portswigger": "https://portswigger.net/web-security/information-disclosure",
        "hacktricks": "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/pentesting-web-checklist.html",
        "nuclei": "http/exposed-panels",
    },
    "cve": {
        "cwe": 1395,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        "portswigger": "https://portswigger.net/web-security/information-disclosure",
        "hacktricks": "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/pentesting-web-checklist.html",
        "nuclei": "http/technologies",
    },
    "service": {
        "cwe": 200,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        "portswigger": "https://portswigger.net/web-security/information-disclosure",
        "hacktricks": "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/pentesting-web-checklist.html",
        "nuclei": "http/technologies",
    },
    "endpoint": {
        "cwe": 200,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        "portswigger": "https://portswigger.net/web-security/information-disclosure",
        "hacktricks": "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/pentesting-web-checklist.html",
        "nuclei": "http/exposures",
    },
    "generic": {
        "cwe": 200,
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage",
        "portswigger": "https://portswigger.net/web-security/information-disclosure",
        "hacktricks": "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/pentesting-web-checklist.html",
        "nuclei": "http/technologies",
    },
}


def classify(finding: dict) -> str:
    blob = f"{finding.get('title') or ''} {finding.get('evidence') or ''} {finding.get('tool') or ''}".lower()
    if _CVE.search(blob) or finding.get("tool") == "nvd_cves":
        return "cve"
    if any(word in blob for word in ("xss", "cross-site scripting", "cross site scripting")):
        return "xss"
    if "ssrf" in blob or "server-side request" in blob:
        return "ssrf"
    if "idor" in blob or "direct object" in blob:
        return "idor"
    if "redirect" in blob:
        return "redirect"
    if "takeover" in blob:
        return "takeover"
    if "admin" in blob or "panel" in blob:
        return "admin"
    if finding.get("tool") == "header_hygiene" or "security header" in blob or "strict-transport" in blob:
        return "headers"
    if "tls" in blob or "certificate" in blob or "ssl" in blob:
        return "tls"
    if finding.get("tool") in {"port_probe", "http_probe"}:
        return "service"
    if finding.get("tool") in {"known_paths", "robots"}:
        return "endpoint"
    if finding.get("tool") == "fingerprint":
        return "service"
    return "generic"


def safe_host(host: str) -> str:
    text = (host or "").strip()
    if _HOST.fullmatch(text) and ".." not in text:
        return text
    return "TARGET"


def cve_ids(finding: dict) -> list[str]:
    blob = f"{finding.get('title') or ''} {finding.get('evidence') or ''}"
    seen = []
    for match in _CVE.findall(blob):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def cwe_numbers(finding: dict, kind: str) -> list[int]:
    blob = f"{finding.get('title') or ''} {finding.get('evidence') or ''}"
    found = []
    for match in _CWE.findall(blob):
        number = int(match)
        if number not in found:
            found.append(number)
    topic = TOPICS.get(kind) or TOPICS["generic"]
    if topic["cwe"] not in found:
        found.append(topic["cwe"])
    return found


def reference_links(finding: dict, kind: str | None = None) -> list[dict]:
    """Build public reference URLs from ids already present on the finding."""
    kind = kind or classify(finding)
    topic = TOPICS.get(kind) or TOPICS["generic"]
    links: list[dict] = []
    seen: set[str] = set()

    def add(label: str, url: str) -> None:
        if url in seen or not url.startswith("https://") or " " in url:
            return
        seen.add(url)
        links.append({"label": label, "url": url})

    for cve in cve_ids(finding):
        add("NVD", f"https://nvd.nist.gov/vuln/detail/{cve}")
        add("CVE.org", f"https://www.cve.org/CVERecord?id={cve}")
        add("GitHub Advisory search", f"https://github.com/advisories?query={quote(cve)}")
        add("Exploit-DB search", f"https://www.exploit-db.com/search?cve={cve}")
        add("GitHub PoC search", f"https://github.com/search?q={quote(cve)}&type=repositories")
        add("Packet Storm search", f"https://packetstormsecurity.com/search/?q={quote(cve)}")
    for number in cwe_numbers(finding, kind):
        add(f"CWE-{number}", f"https://cwe.mitre.org/data/definitions/{number}.html")
    add("OWASP WSTG", topic["owasp"])
    add("PortSwigger", topic["portswigger"])
    add("HackTricks", topic["hacktricks"])
    return links


def _commands(kind: str, host: str) -> list[str]:
    host = safe_host(host)
    base = f"https://{host}"
    topic = TOPICS.get(kind) or TOPICS["generic"]
    common = [
        f'curl -fsSI --max-time 15 "{base}/"',
        f'httpx -silent -title -tech-detect -follow-redirects -u "{base}"',
    ]
    if kind == "cve":
        return common + [
            "Read the Server or product header and compare it with the affected range on the NVD page.",
            "Do not send an exploit payload. Stop if the version does not match.",
            f'nuclei -silent -severity info -u "{base}" -t {topic["nuclei"]}',
        ]
    if kind == "headers":
        return common + [
            f'nuclei -silent -severity info -u "{base}" -t {topic["nuclei"]}',
        ]
    if kind == "endpoint":
        return common + [
            f'ffuf -u "{base}/FUZZ" -w public-well-known.txt -mc 200,204,301,302 -t 5',
            "Use a short list of public paths only. Skip names outside the written scope.",
        ]
    return common + [
        f'nuclei -silent -severity info -u "{base}" -t {topic["nuclei"]}',
    ]


def template_playbook(finding: dict, kind: str | None = None) -> dict:
    kind = kind or classify(finding)
    host = safe_host(str(finding.get("host") or ""))
    title = str(finding.get("title") or "This note")
    cves = cve_ids(finding)
    if kind == "cve" and cves:
        why = (
            f"{cves[0]} appeared in a keyword search. "
            "That does not mean this host is affected."
        )
        likelihood = "Unknown until the running version is confirmed."
        impact = "Unverified. Use the upstream severity only as a hint."
    elif kind == "headers":
        why = "Missing browser headers weaken defenses. They are not, by themselves, a vulnerability."
        likelihood = "High that the headers are absent if the evidence shows the response."
        impact = "Low. They matter when another bug needs a missing browser control."
    elif kind == "service":
        why = "An open web port or a product header shows what is exposed."
        likelihood = "High that the port accepted a connection. The product guess may be wrong."
        impact = "Informational until a version is tied to an affected range."
    elif kind == "endpoint":
        why = "A public path is part of the attack surface. CYBOT did not fetch secret files."
        likelihood = "High that the path responded, if the status is in the evidence."
        impact = "Depends on what the path actually contains. Unverified."
    else:
        why = f"{title} is a reconnaissance note, not a confirmed issue."
        likelihood = "Unknown."
        impact = "Unverified."
    return {
        "class": kind,
        "unverified": True,
        "source": "template",
        "disclaimer": DISCLAIMER,
        "why": why,
        "likelihood": likelihood,
        "impact": impact,
        "verify": _commands(kind, host),
        "evidence": [
            "Save the command, the full response headers, and the time.",
            "Record the in-scope host and the program rule that allowed it.",
            "If a CVE is involved, save the NVD affected-range text next to the version you observed.",
        ],
        "false_positive": [
            "A keyword or a header can name a product the host does not run.",
            "A CDN or default page can mimic the technology.",
            "Do not file the note if the version is outside the affected range.",
        ],
        "next_steps": [
            "Stay inside the written include rules and the intensity you approved.",
            "If the version matches, read the vendor advisory before any further check.",
            "Escalate only with evidence the program asked for. Do not exploit.",
        ],
        "references": reference_links(finding, kind),
        "kev": None,
        "epss": None,
        "writeups": [],
    }


def _strip_urls(value: str) -> str:
    return _URL.sub("[link removed]", value or "").replace("\u2014", "-").replace("\u2013", "-").strip()


def _as_list(value, fallback: list[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        return list(fallback)
    cleaned = [_strip_urls(str(item)) for item in value if str(item).strip()]
    return cleaned or list(fallback)


def merge_narrative(base: dict, narrative: dict) -> dict:
    merged = dict(base)
    merged["source"] = "model"
    merged["why"] = _strip_urls(str(narrative.get("why") or base["why"]))
    merged["likelihood"] = _strip_urls(str(narrative.get("likelihood") or base["likelihood"]))
    merged["impact"] = _strip_urls(str(narrative.get("impact") or base["impact"]))
    merged["verify"] = _as_list(narrative.get("verify"), base["verify"])
    merged["evidence"] = _as_list(narrative.get("evidence"), base["evidence"])
    merged["false_positive"] = _as_list(narrative.get("false_positive"), base["false_positive"])
    merged["next_steps"] = _as_list(narrative.get("next_steps"), base["next_steps"])
    merged["references"] = base["references"]
    return merged


def parse_narrative(raw: str, count: int) -> list[dict]:
    try:
        data = parse_model_json(raw, prefer="array")
    except LLMError as exc:
        if not exc.snippet:
            exc.snippet = snippet_text(raw)
        raise
    items = data if isinstance(data, list) else None
    if items is None and isinstance(data, dict) and isinstance(data.get("items"), list):
        items = data.get("items")
    if not isinstance(items, list) or len(items) != count:
        raise LLMError("Narrative length did not match the findings.", snippet=raw)
    return [item if isinstance(item, dict) else {} for item in items]


def _schema_complete(llm):
    complete = getattr(llm, "complete", None)
    try:
        parameters = inspect.signature(complete).parameters
    except (TypeError, ValueError):
        parameters = {}
    return "response_schema" in parameters


async def _narrative_complete(llm, system: str, user: str) -> str:
    if _schema_complete(llm):
        return await llm.complete(
            system,
            user,
            json_mode=True,
            response_schema=NARRATIVE_SCHEMA,
            max_output_tokens=GEMINI_MAX_OUTPUT_TOKENS,
        )
    return await llm.complete(system, user)


async def apply_narratives(llm, findings: list[dict], playbooks: list[dict], on_fail=None) -> list[dict]:
    if not findings:
        return []
    if llm is None or not hasattr(llm, "complete") or getattr(llm, "name", "") == "mock":
        return playbooks
    system = "You write cautious reconnaissance guidance. You never provide exploit steps or URLs."
    merged: list[dict] = []
    for start in range(0, len(findings), TRIAGE_CHUNK):
        chunk_findings = findings[start : start + TRIAGE_CHUNK]
        chunk_books = playbooks[start : start + TRIAGE_CHUNK]
        brief = [
            {
                "title": row.get("title"),
                "host": safe_host(str(row.get("host") or "")),
                "evidence": str(row.get("evidence") or "")[:400],
                "class": book["class"],
            }
            for row, book in zip(chunk_findings, chunk_books)
        ]
        prompt = (
            "Write unverified manual-research notes for a bug bounty tester. "
            "Do not include URLs, payloads, or exploit steps. "
            "verify must be safe observations such as reading headers or comparing a version. "
            "Return a JSON array with one object per input, same order. "
            "Each object has why, likelihood, impact, verify, evidence, false_positive, and next_steps.\n"
            + json.dumps(brief)
        )
        raw = ""
        try:
            raw = await _narrative_complete(llm, system, prompt)
            try:
                items = parse_narrative(raw, len(chunk_books))
            except LLMError:
                raw = await _narrative_complete(llm, STRICT_NARRATIVE, prompt)
                items = parse_narrative(raw, len(chunk_books))
        except Exception as exc:
            if not getattr(exc, "snippet", "") and raw:
                try:
                    exc.snippet = snippet_text(raw)
                except Exception:
                    pass
            if on_fail is not None:
                on_fail(exc)
            merged.extend(chunk_books)
            continue
        merged.extend(merge_narrative(book, item) for book, item in zip(chunk_books, items))
    return merged


def target_notes(run: dict, findings: list[dict]) -> dict:
    scope = {}
    raw = run.get("scope_json") or ""
    if isinstance(raw, str) and raw.strip():
        try:
            scope = json.loads(raw)
        except json.JSONDecodeError:
            scope = {}
    stack = [row.get("evidence") or row.get("title") for row in findings if row.get("tool") == "fingerprint"]
    services = [row.get("title") for row in findings if row.get("tool") in {"port_probe", "http_probe"}]
    endpoints = [row.get("title") for row in findings if row.get("tool") == "known_paths"]
    hosts = sorted({str(row.get("host") or "") for row in findings if row.get("host")})
    summary = (
        f"{len(findings)} unverified notes across {len(hosts) or 1} host(s). "
        f"{len(services)} service observations, {len(endpoints)} public paths, {len(stack)} fingerprints."
    )
    return {
        "unverified": True,
        "disclaimer": DISCLAIMER,
        "stack": [str(item) for item in stack][:8] or ["No product fingerprint was recorded."],
        "services": [str(item) for item in services][:8] or ["No exposed-service note was recorded."],
        "endpoints": [str(item) for item in endpoints][:8] or ["No extra public path was recorded."],
        "surface": summary,
        "scope": {
            "include": scope.get("include") or [],
            "exclude": scope.get("exclude") or [],
            "authorization": str(scope.get("authorization") or "")[:400],
            "reminder": "Test only names the include rules allow. Excluded names stay out. Authorization was logged with the scope hash.",
        },
    }


def loads_playbook(raw) -> dict | None:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def render_playbook_markdown(book: dict) -> list[str]:
    lines = [
        "",
        "#### Research playbook",
        "",
        book.get("disclaimer") or DISCLAIMER,
        "",
        f"- Why it matters: {book.get('why') or ''}",
        f"- Likelihood: {book.get('likelihood') or ''}",
        f"- Impact: {book.get('impact') or ''}",
        f"- Source: {book.get('source') or 'template'} (unverified)",
    ]
    if book.get("kev") is True:
        lines.append("- CISA KEV: listed")
    elif book.get("kev") is False:
        lines.append("- CISA KEV: not listed")
    else:
        lines.append("- CISA KEV: catalog not available")
    lines.append(f"- EPSS: {book.get('epss') or 'not available'}")
    lines.append("- Manual verification:")
    for step in book.get("verify") or []:
        lines.append(f"  - {step}")
    lines.append("- Evidence to capture:")
    for step in book.get("evidence") or []:
        lines.append(f"  - {step}")
    lines.append("- False-positive checks:")
    for step in book.get("false_positive") or []:
        lines.append(f"  - {step}")
    lines.append("- Next steps:")
    for step in book.get("next_steps") or []:
        lines.append(f"  - {step}")
    lines.append("- References:")
    for link in book.get("references") or []:
        lines.append(f"  - {link.get('label')}: {link.get('url')}")
    for link in book.get("writeups") or []:
        lines.append(f"  - Writeup ({link.get('label')}): {link.get('url')}")
    lines.append("")
    return lines


def render_target_markdown(notes: dict) -> list[str]:
    if not notes:
        return []
    scope = notes.get("scope") or {}
    lines = [
        "## Target notes",
        "",
        notes.get("disclaimer") or DISCLAIMER,
        "",
        f"- Attack surface: {notes.get('surface') or ''}",
        "- Tech stack / fingerprints:",
    ]
    for item in notes.get("stack") or []:
        lines.append(f"  - {item}")
    lines.append("- Exposed services:")
    for item in notes.get("services") or []:
        lines.append(f"  - {item}")
    lines.append("- Interesting endpoints:")
    for item in notes.get("endpoints") or []:
        lines.append(f"  - {item}")
    lines.append("- Scope notes:")
    lines.append(f"  - In: {', '.join(scope.get('include') or []) or 'see the run scope'}")
    lines.append(f"  - Out: {', '.join(scope.get('exclude') or []) or 'none recorded'}")
    lines.append(f"  - {scope.get('reminder') or ''}")
    lines.append("")
    return lines


def short_summary(book: dict | None) -> str:
    if not book:
        return "Unverified. Open the dashboard for the research playbook."
    step = ""
    steps = book.get("next_steps") or book.get("verify") or []
    if steps:
        step = _strip_urls(str(steps[0]))[:140]
    kev = "KEV unknown"
    if book.get("kev") is True:
        kev = "KEV listed"
    elif book.get("kev") is False:
        kev = "KEV not listed"
    return f"Unverified. {kev}. Next: {step}"


async def cve_intel(cves: list[str], fetch=None) -> dict[str, dict]:
    """Best-effort KEV flag and EPSS score. Missing data stays null."""
    wanted = [cve.upper() for cve in cves]
    info = {cve: {"kev": None, "epss": None} for cve in wanted}
    if not wanted or fetch is None:
        return info
    try:
        catalog = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        listed = set()
        vulns = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
        for row in vulns or []:
            if isinstance(row, dict) and row.get("cveID"):
                listed.add(str(row["cveID"]).upper())
        for cve in wanted:
            info[cve]["kev"] = cve in listed
    except Exception:
        pass
    try:
        payload = await fetch("https://api.first.org/data/v1/epss?cve=" + ",".join(wanted))
        for row in (payload or {}).get("data") or []:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve") or "").upper()
            if cve in info and row.get("epss"):
                info[cve]["epss"] = str(row["epss"])[:16]
    except Exception:
        pass
    return info


async def _default_fetch(url: str) -> dict:
    import httpx

    async with httpx.AsyncClient(timeout=8) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, dict):
        raise ValueError("intel response was not an object")
    return data


async def search_writeups(gateway, cve: str) -> list[dict]:
    if gateway is None or not cve:
        return []
    for name in ("tavily", "exa"):
        if gateway.find(name) is None:
            continue
        try:
            if name == "tavily":
                data = await gateway.call(
                    "tavily",
                    "POST",
                    "/search",
                    json={"query": f"{cve} advisory writeup", "max_results": 3, "include_answer": False},
                )
            else:
                data = await gateway.call(
                    "exa",
                    "POST",
                    "/search",
                    json={"query": f"{cve} advisory", "type": "keyword", "numResults": 3},
                )
        except Exception:
            continue
        links = []
        for row in (data or {}).get("results") or []:
            if not isinstance(row, dict):
                continue
            url = str(row.get("url") or "")
            if url.startswith("https://") and " " not in url:
                links.append({"label": str(row.get("title") or "Writeup")[:120], "url": url})
        if links:
            return links[:3]
    return []


async def prepare_playbooks(llm, gateway, run: dict, findings: list[dict], fetch=None, on_fail=None) -> tuple[dict, list[dict]]:
    """Build target notes and one playbook per finding. Never raises."""
    notes = target_notes(run, findings)
    books = [template_playbook(row) for row in findings]
    try:
        books = await apply_narratives(llm, findings, books, on_fail=on_fail)
    except Exception as exc:
        if on_fail is not None:
            on_fail(exc)
        books = [template_playbook(row) for row in findings]
    cves = []
    for row in findings:
        for cve in cve_ids(row):
            if cve not in cves:
                cves.append(cve)
    intel_fetch = _default_fetch if fetch is None else fetch
    if fetch is False:
        intel = {cve: {"kev": None, "epss": None} for cve in cves}
    else:
        try:
            intel = await cve_intel(cves, intel_fetch)
        except Exception:
            intel = {cve: {"kev": None, "epss": None} for cve in cves}
    writeups: dict[str, list] = {}
    for cve in cves:
        try:
            writeups[cve] = await search_writeups(gateway, cve)
        except Exception:
            writeups[cve] = []
    enriched = []
    for row, book in zip(findings, books):
        ids = cve_ids(row)
        if ids:
            primary = ids[0]
            book["kev"] = intel.get(primary, {}).get("kev")
            book["epss"] = intel.get(primary, {}).get("epss")
            book["writeups"] = writeups.get(primary) or []
        item = dict(row)
        item["playbook"] = book
        enriched.append(item)
    return notes, enriched
