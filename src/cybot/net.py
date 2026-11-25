from __future__ import annotations

import asyncio
import json
import re
import shutil
import socket
import ssl
import time
from dataclasses import dataclass

import httpx

from cybot.redact import redact
from cybot.scope import ScopeBlocked, ip_is_public

_DNS_NAME = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
_UA = "CYBOT/0.1 (authorized recon; rate-limited)"
_RR = {"A": "1", "AAAA": "28", "MX": "15", "TXT": "16", "NS": "2", "CNAME": "5"}


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: str
    ip: str = ""


class RateLimiter:
    def __init__(self, per_minute: int):
        self.interval = 60 / max(1, per_minute)
        self._next: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def wait(self, key: str) -> None:
        async with self._lock:
            now = time.monotonic()
            earliest = self._next.get(key, 0)
            delay = max(0.0, earliest - now)
            self._next[key] = max(now, earliest) + self.interval
        if delay:
            await asyncio.sleep(delay)


class RealNet:
    """Network access used by recon tools. Connections to the target are pinned to a checked IP."""

    def __init__(self, rate_per_min: int = 20, timeout: float = 8.0):
        self.limiter = RateLimiter(rate_per_min)
        self.timeout = timeout
        self.client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> RealNet:
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout + 4),
            follow_redirects=False,
            headers={"User-Agent": _UA},
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self.client is not None:
            await self.client.aclose()

    async def which(self, binary: str) -> bool:
        return shutil.which(binary) is not None

    async def doh_records(self, host: str) -> dict[str, list[str]]:
        records: dict[str, list[str]] = {}
        for kind, code in _RR.items():
            try:
                payload = await self.get_json(
                    "https://cloudflare-dns.com/dns-query",
                    "doh",
                    params={"name": host, "type": code},
                    headers={"accept": "application/dns-json"},
                )
            except Exception:
                continue
            values = []
            for answer in (payload or {}).get("Answer") or []:
                if str(answer.get("type")) != code:
                    continue
                data = str(answer.get("data") or "").strip().strip('"')
                if data:
                    values.append(data[:200])
            if values:
                records[kind] = values
        if not records.get("A") and not records.get("AAAA"):
            infos = await asyncio.get_running_loop().run_in_executor(
                None, lambda: _getaddrinfo(host)
            )
            if infos:
                records["A"] = infos
        return records

    async def assert_public(self, host: str) -> list[str]:
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            ips = [host]
        else:
            records = await self.doh_records(host)
            ips = list(records.get("A") or []) + list(records.get("AAAA") or [])
        if not ips:
            raise ScopeBlocked(f"{host} did not resolve")
        for ip in ips:
            if not ip_is_public(ip):
                raise ScopeBlocked(f"{host} resolves to a non-public address")
        return ips

    async def get_json(
        self,
        url: str,
        limit_key: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
    ) -> dict | list:
        await self.limiter.wait(limit_key)
        assert self.client is not None
        try:
            response = await self.client.get(url, params=params, headers=headers)
            response.raise_for_status()
            return json.loads(response.content[:2_000_000])
        except Exception as exc:
            raise RuntimeError(redact(f"{type(exc).__name__}")) from None

    async def pinned_http(self, host: str, path: str, scheme: str) -> HttpResult:
        if not re.fullmatch(r"/[A-Za-z0-9._~/-]*", path) or ".." in path:
            raise ScopeBlocked("Refusing a path that is not on the public list.")
        if any(char in host for char in "\r\n\t "):
            raise ScopeBlocked("Refusing a malformed host.")
        ips = await self.assert_public(host)
        ip = ips[0]
        await self.limiter.wait(host)
        port = 443 if scheme == "https" else 80
        ssl_ctx = ssl.create_default_context() if scheme == "https" else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip,
                    port,
                    ssl=ssl_ctx,
                    server_hostname=host if ssl_ctx is not None else None,
                ),
                timeout=self.timeout,
            )
        except Exception:
            return HttpResult(0, {}, "", ip)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_UA}\r\n"
            "Accept: text/html,application/json;q=0.8,*/*;q=0.5\r\n"
            "Connection: close\r\n\r\n"
        )
        try:
            writer.write(request.encode("ascii"))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(16384), timeout=self.timeout)
        except Exception:
            return HttpResult(0, {}, "", ip)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return _parse_http(raw, ip)

    async def tcp_ports(self, host: str, ports: list[int]) -> dict[int, bool]:
        ips = await self.assert_public(host)
        ip = ips[0]
        found: dict[int, bool] = {}
        for port in ports:
            await self.limiter.wait(host)
            found[port] = await _tcp_open(ip, port)
        return found

    async def subfinder(self, domain: str) -> list[str]:
        _require_domain(domain)
        return await _exec(
            ["subfinder", "-d", domain, "-silent", "-nW", "-timeout", "15"],
            timeout=40,
        )

    async def httpx_cli(self, host: str) -> str:
        _require_domain(host)
        lines = await _exec(
            [
                "httpx",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-timeout",
                "8",
                "-no-color",
                "-u",
                f"https://{host}",
            ],
            timeout=25,
        )
        return lines[0] if lines else ""


class FixtureNet:
    """Offline stand-in for the example.com demo and tests. It never dials out."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.have_binary: set[str] = set()
        self.subfinder_names: list[str] = []
        self.httpx_line = ""

    async def __aenter__(self) -> FixtureNet:
        return self

    async def __aexit__(self, *_exc) -> None:
        return None

    async def which(self, binary: str) -> bool:
        return binary in self.have_binary

    async def doh_records(self, host: str) -> dict[str, list[str]]:
        self.calls.append(("doh", host))
        if host in {"example.com", "www.example.com"}:
            return {
                "A": ["93.184.216.34"],
                "NS": ["a.iana-servers.net"],
                "TXT": ["v=spf1 -all"],
            }
        return {"A": ["93.184.216.34"]}

    async def assert_public(self, host: str) -> list[str]:
        self.calls.append(("resolve", host))
        if host.endswith(".example.com") or host == "example.com":
            return ["93.184.216.34"]
        raise ScopeBlocked("fixture has no public address for this host")

    async def get_json(self, url: str, limit_key: str, *, params=None, headers=None):
        self.calls.append(("json", limit_key, url.split("?")[0]))
        if "crt.sh" in url:
            return [
                {
                    "name_value": "www.example.com\nexample.com\nmail.example.com\nevil.not-example.test"
                }
            ]
        if "rdap.org" in url:
            return {
                "ldhName": "example.com",
                "status": ["active"],
                "nameservers": [{"ldhName": "a.iana-servers.net"}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                    }
                ],
            }
        if "shodan.io" in url:
            return {"domain": "example.com", "subdomains": ["www", "mail"]}
        if "virustotal.com" in url:
            return {"data": {"attributes": {"last_analysis_stats": {"harmless": 70, "malicious": 0}}}}
        if "nvd.nist.gov" in url:
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-0001",
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": "Example issue in nginx. Not a real advisory.",
                                }
                            ],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                        }
                    }
                ]
            }
        raise RuntimeError("fixture has no response for this URL")

    async def pinned_http(self, host: str, path: str, scheme: str) -> HttpResult:
        self.calls.append(("http", host, scheme, path))
        await self.assert_public(host)
        if path == "/":
            return HttpResult(
                200,
                {"server": "nginx/1.25.3", "content-type": "text/html"},
                "<title>Example Domain</title><p>fixture</p>",
                "93.184.216.34",
            )
        if path == "/robots.txt":
            return HttpResult(200, {"content-type": "text/plain"}, "User-agent: *\nDisallow:\n", "93.184.216.34")
        return HttpResult(404, {}, "", "93.184.216.34")

    async def tcp_ports(self, host: str, ports: list[int]) -> dict[int, bool]:
        self.calls.append(("ports", host, tuple(ports)))
        await self.assert_public(host)
        return {port: port in {80, 443} for port in ports}

    async def subfinder(self, domain: str) -> list[str]:
        self.calls.append(("subfinder", domain))
        return list(self.subfinder_names)

    async def httpx_cli(self, host: str) -> str:
        self.calls.append(("httpx", host))
        return self.httpx_line


def _getaddrinfo(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def _parse_http(raw: bytes, ip: str) -> HttpResult:
    head, _, body = raw.partition(b"\r\n\r\n")
    text_head = head.decode("iso-8859-1", "replace")
    lines = text_head.splitlines()
    status = 0
    if lines and " " in lines[0]:
        parts = lines[0].split(" ")
        if len(parts) > 1 and parts[1].isdigit():
            status = int(parts[1])
    keep = {
        "server",
        "content-type",
        "x-powered-by",
        "strict-transport-security",
        "x-content-type-options",
        "content-security-policy",
        "cf-ray",
        "location",
    }
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        lowered = key.strip().lower()
        if lowered in keep:
            headers[lowered] = value.strip()[:300]
    return HttpResult(status, headers, body.decode("utf-8", "replace")[:8000], ip)


async def _tcp_open(ip: str, port: int) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.5)
    except Exception:
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True


def _require_domain(domain: str) -> None:
    if not _DNS_NAME.match(domain):
        raise ScopeBlocked("Refusing to pass this value to a subprocess.")


async def _exec(argv: list[str], timeout: float) -> list[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return []
    try:
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        return []
    lines = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        cleaned = line.strip().lower()
        if cleaned:
            lines.append(cleaned[:253])
    return lines[:200]
