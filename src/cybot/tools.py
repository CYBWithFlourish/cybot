from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote

from cybot.redact import redact
from cybot.scope import ScopeBlocked, ip_is_public, registrable

# Public, documented paths only. No secret files, backups, or admin panels.
PUBLIC_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/humans.txt",
    "/ads.txt",
    "/.well-known/change-password",
)

PORTS = {
    "light": (80, 443, 8080, 8443),
    "standard": (80, 443, 8080, 8443, 8000, 8888),
}

_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")
_SERVER = re.compile(
    r"^(nginx|apache|openresty|cloudflare|express|php|microsoft-iis|gunicorn|caddy|envoy)"
    r"/(\d+\.\d+(?:\.\d+)?)",
    re.I,
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    title: str
    description: str
    intensity: str
    phase: str
    needs_secret: str | None = None
    needs_binary: str | None = None
    external: bool = False
    server_name: str = ""
    remote_name: str = ""
    needs_role: str = ""


@dataclass
class Observation:
    host: str
    tool: str
    severity: str
    title: str
    evidence: str
    plain: str


@dataclass
class ToolOutcome:
    observations: list[Observation] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    products: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class ToolContext:
    net: object
    host: str
    secret: str | None = None
    cache: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)
    outcome: ToolOutcome = field(default_factory=ToolOutcome)
    gateway: object | None = None

    def note(self, message: str) -> None:
        self.outcome.notes.append(redact(message)[:300])

    def observe(self, host: str, severity: str, title: str, evidence: str, plain: str) -> None:
        self.outcome.observations.append(
            Observation(
                host=host,
                tool="",
                severity=severity,
                title=redact(title)[:180],
                evidence=_clean(evidence),
                plain=_clean(plain, limit=600),
            )
        )


def builtin_specs() -> list[ToolSpec]:
    return [
        ToolSpec(
            "ct_subdomains",
            "Certificate transparency",
            "Passive names from crt.sh for the registrable domain.",
            "passive",
            "discover",
        ),
        ToolSpec(
            "dns_records",
            "DNS records",
            "Resolver lookups for A, AAAA, MX, TXT, NS, and CNAME.",
            "passive",
            "discover",
        ),
        ToolSpec(
            "rdap_lookup",
            "RDAP",
            "Registration status and nameservers.",
            "passive",
            "discover",
        ),
        ToolSpec(
            "shodan_dns",
            "Shodan passive DNS",
            "Passive subdomain names from Shodan for the registrable domain.",
            "passive",
            "discover",
            needs_secret="shodan",
        ),
        ToolSpec(
            "virustotal_domain",
            "VirusTotal domain",
            "Existing reputation counts for the registrable domain.",
            "passive",
            "discover",
            needs_secret="virustotal",
        ),
        ToolSpec(
            "subfinder_cli",
            "subfinder",
            "Passive subdomain enumeration with a locked subfinder command.",
            "passive",
            "discover",
            needs_binary="subfinder",
        ),
        ToolSpec(
            "osint_search",
            "OSINT search",
            "Public web search for the in-scope domain through Exa, Tavily, Linkup, or Kagi.",
            "passive",
            "discover",
            needs_role="search",
        ),
        ToolSpec(
            "github_public_code",
            "Public code paths",
            "GitHub code search for the in-scope domain under one named org. Paths only.",
            "passive",
            "discover",
            needs_role="github",
        ),
        ToolSpec(
            "http_probe",
            "HTTP probe",
            "One pinned request to / over HTTPS, then HTTP if that fails.",
            "light",
            "probe",
        ),
        ToolSpec(
            "fingerprint",
            "Header fingerprint",
            "Server and X-Powered-By notes from the homepage response.",
            "light",
            "probe",
        ),
        ToolSpec(
            "header_hygiene",
            "Header hygiene",
            "HSTS, nosniff, and CSP presence on the homepage response.",
            "light",
            "probe",
        ),
        ToolSpec(
            "port_probe",
            "Web ports",
            "TCP connect to a fixed list of web ports.",
            "light",
            "probe",
        ),
        ToolSpec(
            "known_paths",
            "Public paths",
            "Fetch a fixed list of public well-known paths.",
            "light",
            "probe",
        ),
        ToolSpec(
            "httpx_cli",
            "httpx",
            "Optional httpx probe with a locked argument list.",
            "standard",
            "probe",
            needs_binary="httpx",
        ),
        ToolSpec(
            "firecrawl_page",
            "Rendered homepage",
            "One Firecrawl scrape of the in-scope homepage. No further crawl.",
            "light",
            "probe",
            needs_role="crawl",
        ),
        ToolSpec(
            "nvd_cves",
            "NVD correlation",
            "Unverified CVE keyword lookup for a parsed server version.",
            "light",
            "enrich",
        ),
        ToolSpec(
            "cve_search",
            "CVE search",
            "Unverified public search for the parsed product version.",
            "light",
            "enrich",
            needs_role="search",
        ),
    ]


async def run_builtin(spec: ToolSpec, ctx: ToolContext) -> ToolOutcome:
    fn = _DISPATCH[spec.name]
    await fn(ctx)
    for observation in ctx.outcome.observations:
        observation.tool = spec.name
    return ctx.outcome


def assert_public_path(path: str) -> str:
    if path not in PUBLIC_PATHS and path != "/":
        raise ScopeBlocked("Path is not on the public list.")
    if not _SAFE_PATH.match(path):
        raise ScopeBlocked("Path failed validation.")
    return path


async def ct_subdomains(ctx: ToolContext) -> None:
    domain = registrable(ctx.host)
    url = "https://crt.sh/?q=" + quote("%." + domain) + "&output=json"
    try:
        data = await ctx.net.get_json(url, "crt.sh")
    except Exception as exc:
        ctx.note(f"crt.sh unavailable ({type(exc).__name__})")
        return
    rows = data if isinstance(data, list) else []
    if isinstance(data, dict):
        rows = data.get("results") or []
    names: set[str] = set()
    for row in rows[:500]:
        if not isinstance(row, dict):
            continue
        for part in str(row.get("name_value") or "").splitlines():
            name = part.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if _dns_name(name):
                names.add(name)
    ctx.outcome.hosts.extend(sorted(names))
    ctx.note(f"crt.sh returned {len(names)} names before the scope filter")


async def dns_records(ctx: ToolContext) -> None:
    records = await ctx.net.doh_records(ctx.host)
    ips = list(records.get("A") or []) + list(records.get("AAAA") or [])
    for ip in ips:
        if not ip_is_public(ip):
            raise ScopeBlocked(f"{ctx.host} has a non-public address")
    if not records:
        ctx.note(f"no DNS records for {ctx.host}")
        return
    evidence = "; ".join(f"{kind}={','.join(values)}" for kind, values in records.items() if values)
    ctx.observe(
        ctx.host,
        "info",
        "DNS records",
        evidence or "no answers",
        "These records came from a public resolver. They describe where the name points. They are not a vulnerability.",
    )


async def rdap_lookup(ctx: ToolContext) -> None:
    domain = registrable(ctx.host)
    if ip_is_public(domain) or _is_ipv4_text(domain):
        ctx.note("RDAP domain lookup skipped for an IP target")
        return
    try:
        data = await ctx.net.get_json(f"https://rdap.org/domain/{quote(domain)}", "rdap")
    except Exception as exc:
        ctx.note(f"RDAP unavailable ({type(exc).__name__})")
        return
    if not isinstance(data, dict):
        ctx.note("RDAP returned an unexpected payload")
        return
    status = ",".join(str(item) for item in (data.get("status") or [])[:6])
    nameservers = []
    for item in data.get("nameservers") or []:
        if isinstance(item, dict) and item.get("ldhName"):
            nameservers.append(str(item["ldhName"]))
    registrar = _registrar(data)
    evidence = f"status={status or 'unknown'}; nameservers={','.join(nameservers) or 'unknown'}"
    if registrar:
        evidence += f"; registrar={registrar}"
    ctx.observe(
        domain,
        "info",
        "RDAP registration summary",
        evidence,
        "Registration data is public. Contact records were not stored.",
    )


async def shodan_dns(ctx: ToolContext) -> None:
    domain = registrable(ctx.host)
    if not ctx.secret:
        return
    data = await ctx.net.get_json(
        f"https://api.shodan.io/dns/domain/{quote(domain)}",
        "shodan",
        params={"key": ctx.secret},
    )
    subs = data.get("subdomains") if isinstance(data, dict) else None
    names = []
    for label in (subs or [])[:200]:
        name = f"{str(label).strip().lower()}.{domain}"
        if _dns_name(name):
            names.append(name)
    ctx.outcome.hosts.extend(names)
    ctx.observe(
        domain,
        "info",
        "Shodan passive DNS",
        f"{len(names)} names from the Shodan DNS dataset",
        "This is a passive database lookup. CYBOT did not ask Shodan to scan the host.",
    )


async def virustotal_domain(ctx: ToolContext) -> None:
    domain = registrable(ctx.host)
    if not ctx.secret:
        return
    data = await ctx.net.get_json(
        f"https://www.virustotal.com/api/v3/domains/{quote(domain)}",
        "virustotal",
        headers={"x-apikey": ctx.secret},
    )
    stats = {}
    if isinstance(data, dict):
        stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    severity = "low" if malicious else "info"
    ctx.observe(
        domain,
        severity,
        "VirusTotal reputation counts",
        f"malicious={malicious}; harmless={harmless}",
        "These are vendor votes already stored at VirusTotal. They are not a confirmed vulnerability and no sample was submitted.",
    )


async def subfinder_cli(ctx: ToolContext) -> None:
    domain = registrable(ctx.host)
    names = await ctx.net.subfinder(domain)
    clean = [name for name in names if _dns_name(name)]
    ctx.outcome.hosts.extend(clean)
    ctx.note(f"subfinder returned {len(clean)} names before the scope filter")


async def http_probe(ctx: ToolContext) -> None:
    result = await ctx.net.pinned_http(ctx.host, "/", "https")
    scheme = "https"
    if result.status == 0:
        result = await ctx.net.pinned_http(ctx.host, "/", "http")
        scheme = "http"
    ctx.cache["home"] = (scheme, result)
    if result.status == 0:
        ctx.note(f"no HTTP response from {ctx.host}")
        return
    title = extract_title(result.body)
    server = result.headers.get("server", "")
    severity = "low" if scheme == "http" else "info"
    title_text = f"{scheme.upper()} responded {result.status}"
    plain = (
        "The host answered a single GET of the homepage. "
        "The status and title are inventory, not proof of a flaw."
    )
    if scheme == "http":
        plain = "HTTPS did not answer and HTTP did. That is worth noting if the program expects TLS."
    ctx.observe(
        ctx.host,
        severity,
        title_text,
        f"title={title or 'none'}; server={server or 'unset'}",
        plain,
    )


async def fingerprint(ctx: ToolContext) -> None:
    home = ctx.cache.get("home")
    if not home or home[1].status == 0:
        ctx.note("fingerprint skipped, no homepage")
        return
    _scheme, result = home
    server = result.headers.get("server", "")
    powered = result.headers.get("x-powered-by", "")
    bits = []
    if server:
        bits.append(f"server={server}")
    if powered:
        bits.append(f"x-powered-by={powered}")
    if result.headers.get("cf-ray"):
        bits.append("cloudflare=yes")
    matched = _SERVER.match(server.strip())
    if matched:
        product, version = matched.group(1).lower(), matched.group(2)
        ctx.outcome.products.append((product, version))
        bits.append(f"parsed={product} {version}")
    if not bits:
        ctx.note("no technology headers")
        return
    ctx.observe(
        ctx.host,
        "info",
        "Technology headers",
        "; ".join(bits),
        "The server volunteered these headers. A version string is a lead for the program, not confirmation the host is vulnerable.",
    )


async def header_hygiene(ctx: ToolContext) -> None:
    home = ctx.cache.get("home")
    if not home or home[1].status == 0:
        return
    scheme, result = home
    missing = []
    if scheme == "https" and "strict-transport-security" not in result.headers:
        missing.append("strict-transport-security")
    if "x-content-type-options" not in result.headers:
        missing.append("x-content-type-options")
    if "content-security-policy" not in result.headers:
        missing.append("content-security-policy")
    if not missing:
        ctx.observe(
            ctx.host,
            "info",
            "Common security headers are present",
            "HSTS (on HTTPS), nosniff, and CSP were all set",
            "The homepage sets the headers CYBOT checks. This is not a full header review.",
        )
        return
    severity = "low" if "strict-transport-security" in missing else "info"
    ctx.observe(
        ctx.host,
        severity,
        "Some common security headers are missing",
        "missing " + ", ".join(missing),
        "Missing headers are hardening notes. They are not, by themselves, a vulnerability you can demonstrate.",
    )


async def port_probe(ctx: ToolContext) -> None:
    intensity = ctx.extra.get("intensity", "light")
    ports = PORTS["standard"] if intensity == "standard" else PORTS["light"]
    opened = await ctx.net.tcp_ports(ctx.host, list(ports))
    for port, is_open in opened.items():
        if not is_open:
            continue
        severity = "info" if port in {80, 443} else "low"
        ctx.observe(
            ctx.host,
            severity,
            f"TCP {port} accepted a connection",
            f"port {port} open (connect only, no protocol probe)",
            "CYBOT only checked whether the port accepted a TCP connection. It did not speak an exploit or grab a service banner beyond HTTP on the homepage.",
        )


async def known_paths(ctx: ToolContext) -> None:
    scheme = "https"
    home = ctx.cache.get("home")
    if home:
        scheme = home[0]
    for path in PUBLIC_PATHS:
        assert_public_path(path)
        result = await ctx.net.pinned_http(ctx.host, path, scheme)
        if result.status not in {200, 204, 401, 403}:
            continue
        snippet = ""
        if result.status == 200 and path.endswith(".txt"):
            snippet = re.sub(r"\s+", " ", result.body)[:180]
        label = "published" if result.status == 200 else f"returned {result.status}"
        ctx.observe(
            ctx.host,
            "info",
            f"{path} is {label}",
            snippet or f"status {result.status}",
            "This path is a public well-known file. CYBOT does not look for secret files, backups, or admin panels.",
        )


async def httpx_cli(ctx: ToolContext) -> None:
    line = await ctx.net.httpx_cli(ctx.host)
    if not line:
        ctx.note("httpx produced no output")
        return
    ctx.observe(
        ctx.host,
        "info",
        "httpx summary",
        line[:300],
        "httpx ran with a fixed argument list against this one in-scope host. Redirects were not followed.",
    )


async def nvd_cves(ctx: ToolContext) -> None:
    product = str(ctx.extra.get("product") or "")
    version = str(ctx.extra.get("version") or "")
    if not re.fullmatch(r"[a-z0-9.-]{2,40}", product) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
        raise ScopeBlocked("NVD lookup was not given a parsed product version.")
    headers = {}
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": "3"}
    if ctx.secret:
        headers["apiKey"] = ctx.secret
    try:
        data = await ctx.net.get_json(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "nvd",
            params=params,
            headers=headers or None,
        )
    except Exception as exc:
        ctx.note(f"NVD unavailable ({type(exc).__name__})")
        return
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    kept = 0
    for item in (vulns or [])[:3]:
        cve = (item or {}).get("cve") or {}
        description = ""
        for entry in cve.get("descriptions") or []:
            if entry.get("lang") == "en":
                description = str(entry.get("value") or "")
                break
        if product not in description.lower():
            continue
        score = _cvss(cve)
        if score >= 9:
            severity = "high"
        elif score >= 7:
            severity = "medium"
        else:
            severity = "info"
        cve_id = str(cve.get("id") or "CVE")
        ctx.observe(
            ctx.host,
            severity,
            f"Unverified: {cve_id} mentions {product}",
            f"CVSS {score or 'unknown'}; keyword {product} {version}; not confirmed on this host",
            f"NVD has {cve_id} in a keyword search for {product} {version}. "
            "The score is upstream. CYBOT did not confirm the host is affected and did not attempt the issue.",
        )
        kept += 1
    if kept == 0:
        ctx.note(f"no NVD keyword hit for {product} {version}")


async def osint_search(ctx: ToolContext) -> None:
    if ctx.gateway is None:
        return
    domain = registrable(ctx.host)
    if _is_ipv4_text(domain):
        ctx.note("OSINT search skipped for an IP target")
        return
    found = await search_by_kind(
        ctx,
        "discover",
        f"related sites, assets, research papers, and public code for {domain}",
    )
    if found is None:
        ctx.note("no discovery search connector")
        return
    provider, data = found
    lines = _search_lines(data)[:4]
    if lines:
        ctx.observe(
            domain,
            "info",
            f"Related public material via {provider}",
            "; ".join(lines),
            "Exa is used for this neural discovery when it is granted. Tavily is the fallback. Titles and URLs only.",
        )
    if provider == "exa":
        await _exa_contents(ctx, domain, data)
    if ctx.gateway.find("exa") and ctx.gateway.find("tavily"):
        factual = await search_by_kind(ctx, "factual", f"what is publicly known about {domain}")
        if factual:
            source, payload = factual
            summary = _search_lines(payload)[:3]
            answer = _clean(str(payload.get("answer") or ""), 240) if isinstance(payload, dict) else ""
            evidence = answer or "; ".join(summary)
            if evidence:
                ctx.observe(
                    domain,
                    "info",
                    f"Factual snapshot via {source}",
                    evidence,
                    "This is a short public answer about the domain, not a vulnerability finding.",
                )


async def cve_search(ctx: ToolContext) -> None:
    product = str(ctx.extra.get("product") or "")
    version = str(ctx.extra.get("version") or "")
    if not re.fullmatch(r"[a-z0-9.-]{2,40}", product):
        return
    found = await search_by_kind(ctx, "factual", f"{product} {version} CVE advisory")
    if found is None:
        ctx.note("no factual search connector")
        return
    provider, data = found
    lines = _search_lines(data)[:3]
    answer = _clean(str(data.get("answer") or ""), 240) if isinstance(data, dict) else ""
    evidence = answer or "; ".join(lines)
    if not evidence:
        ctx.note("no public CVE titles")
        return
    ctx.observe(
        ctx.host,
        "info",
        f"Unverified advisory notes for {product} {version} via {provider}",
        evidence,
        "Tavily is preferred for this factual lookup. Exa is the fallback. This is not confirmation and it is not an exploit note.",
    )


async def github_public_code(ctx: ToolContext) -> None:
    org = str(ctx.extra.get("github_org") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", org):
        ctx.note("GitHub org is not set. Public code search stayed off.")
        return
    if ctx.gateway is None or ctx.gateway.find("github") is None:
        return
    domain = registrable(ctx.host)
    data = await ctx.gateway.call(
        "github",
        "GET",
        "/search/code",
        params={"q": f"org:{org} {domain}", "per_page": "5"},
    )
    items = data.get("items") if isinstance(data, dict) else None
    paths = []
    for item in (items or [])[:5]:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")[:180]
        url = str(item.get("html_url") or "")[:240]
        if path:
            paths.append(f"{path} {url}".strip())
    if not paths:
        ctx.note(f"no public code hits for org:{org}")
        return
    ctx.observe(
        domain,
        "info",
        f"Public code under {org} mentions this domain",
        "; ".join(paths),
        "CYBOT stored file paths only. It does not copy file contents, so a credential in one of those files is not saved here.",
    )


async def firecrawl_page(ctx: ToolContext) -> None:
    if ctx.gateway is None or ctx.gateway.find("firecrawl") is None:
        return
    url = f"https://{ctx.host}/"
    data = await ctx.gateway.call(
        "firecrawl",
        "POST",
        "/v2/scrape",
        json={"url": url, "formats": ["markdown"], "onlyMainContent": True},
    )
    markdown = ""
    if isinstance(data, dict):
        inner = data.get("data") if isinstance(data.get("data"), dict) else data
        markdown = str((inner or {}).get("markdown") or "")
    excerpt = _clean(markdown, 280)
    ctx.observe(
        ctx.host,
        "info",
        "Rendered homepage excerpt",
        excerpt or "Firecrawl returned no markdown",
        "One in-scope homepage was rendered through the Firecrawl connector. No other URL was requested.",
    )


async def search_by_kind(ctx: ToolContext, kind: str, query: str):
    """Discover uses Exa, then Tavily. Factual lookups use Tavily, then Exa."""
    gateway = ctx.gateway
    if gateway is None:
        return None
    order = ("exa", "tavily") if kind == "discover" else ("tavily", "exa")
    for name in order:
        if gateway.find(name) is None:
            continue
        try:
            data = await _one_search(gateway, name, kind, query)
        except Exception as exc:
            ctx.note(f"{name} search failed ({type(exc).__name__})")
            continue
        if data:
            return name, data
    if gateway.find("exa") is None and gateway.find("tavily") is None:
        for name in ("linkup", "kagi"):
            if gateway.find(name) is None:
                continue
            try:
                data = await _one_search(gateway, name, kind, query)
            except Exception as exc:
                ctx.note(f"{name} search failed ({type(exc).__name__})")
                continue
            if data:
                return name, data
    return None


async def _one_search(gateway, name: str, kind: str, query: str):
    if name == "exa":
        return await gateway.call(
            "exa",
            "POST",
            "/search",
            json={
                "query": query,
                "type": "neural" if kind == "discover" else "keyword",
                "numResults": 4,
            },
        )
    if name == "tavily":
        return await gateway.call(
            "tavily",
            "POST",
            "/search",
            json={
                "query": query,
                "topic": "general",
                "search_depth": "basic",
                "max_results": 4,
                "include_answer": True,
            },
        )
    if name == "linkup":
        return await gateway.call("linkup", "POST", "/v1/search", json={"q": query, "depth": "standard"})
    if name == "kagi":
        return await gateway.call("kagi", "GET", "/api/v0/search", params={"q": query})
    return None


async def _exa_contents(ctx: ToolContext, domain: str, data) -> None:
    url = ""
    rows = data.get("results") if isinstance(data, dict) else None
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        candidate = str(row.get("url") or "")
        host = candidate.split("/")[2] if "://" in candidate else ""
        if host == domain or host.endswith("." + domain):
            url = candidate
            break
    if not url:
        return
    try:
        payload = await ctx.gateway.call(
            "exa",
            "POST",
            "/contents",
            json={"urls": [url], "text": {"maxCharacters": 400}},
        )
    except Exception as exc:
        ctx.note(f"Exa contents failed ({type(exc).__name__})")
        return
    text = ""
    results = payload.get("results") if isinstance(payload, dict) else None
    if results and isinstance(results[0], dict):
        text = str(results[0].get("text") or "")
    excerpt = _clean(text, 280)
    if excerpt:
        ctx.observe(
            domain,
            "info",
            "In-scope page text via Exa",
            excerpt,
            "Exa fetched text for one URL on the in-scope domain. Off-domain results were not fetched.",
        )


def _search_lines(data) -> list[str]:
    rows = []
    if isinstance(data, dict):
        rows = data.get("results") or data.get("data") or []
        if isinstance(data.get("output"), dict):
            rows = data["output"].get("results") or rows
    lines = []
    if not isinstance(rows, list):
        return lines
    for row in rows:
        if not isinstance(row, dict):
            continue
        title = _clean(str(row.get("title") or row.get("name") or ""), 80)
        url = _clean(str(row.get("url") or ""), 120)
        if title or url:
            lines.append(f"{title} {url}".strip())
    return lines


def extract_title(body: str) -> str:
    match = _TITLE.search(body or "")
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1))
    title = re.sub(r"<[^>]+>", "", title)
    return title.strip()[:120]


def _cvss(cve: dict) -> float:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows and isinstance(rows[0], dict):
            try:
                return float((rows[0].get("cvssData") or {}).get("baseScore") or 0)
            except (TypeError, ValueError):
                return 0
    return 0


def _registrar(data: dict) -> str:
    for entity in data.get("entities") or []:
        if "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray") or []
        if len(vcard) != 2 or not isinstance(vcard[1], list):
            continue
        for item in vcard[1]:
            if isinstance(item, list) and item and item[0] == "fn" and len(item) >= 4:
                return str(item[3])[:120]
    return ""


def _dns_name(name: str) -> bool:
    if not name or len(name) > 253 or not name.isascii():
        return False
    return all(re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in name.split("."))


def _is_ipv4_text(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value))


def _clean(text: str, limit: int = 400) -> str:
    collapsed = re.sub(r"\s+", " ", redact(text or "")).strip()
    return collapsed[:limit]


_DISPATCH = {
    "ct_subdomains": ct_subdomains,
    "dns_records": dns_records,
    "rdap_lookup": rdap_lookup,
    "shodan_dns": shodan_dns,
    "virustotal_domain": virustotal_domain,
    "subfinder_cli": subfinder_cli,
    "http_probe": http_probe,
    "fingerprint": fingerprint,
    "header_hygiene": header_hygiene,
    "port_probe": port_probe,
    "known_paths": known_paths,
    "httpx_cli": httpx_cli,
    "firecrawl_page": firecrawl_page,
    "osint_search": osint_search,
    "github_public_code": github_public_code,
    "nvd_cves": nvd_cves,
    "cve_search": cve_search,
}
