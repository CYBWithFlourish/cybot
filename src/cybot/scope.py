from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MULTI = (
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "com.br",
    "co.jp",
    "co.za",
    "com.ng",
    "co.in",
    "com.mx",
)


@dataclass(frozen=True)
class Scope:
    program: str
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    authorization: str

    def canonical(self) -> str:
        payload = {
            "program": self.program.strip(),
            "include": list(self.include),
            "exclude": list(self.exclude),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    host: str
    reason: str
    rule: str


class ScopeError(ValueError):
    pass


class ScopeBlocked(RuntimeError):
    """A resolved address or a tool argument failed a safety check."""


def parse_scope(data: dict) -> Scope:
    program = str(data.get("program") or "").strip()
    authorization = str(data.get("authorization") or "").strip()
    include = _patterns(data.get("include"))
    exclude = _patterns(data.get("exclude") or [])
    if len(program) < 2 or len(program) > 120:
        raise ScopeError("Program name must be 2-120 characters.")
    if len(authorization) < 20 or len(authorization) > 500:
        raise ScopeError("Write an authorization statement of at least 20 characters.")
    if not include:
        raise ScopeError("Add at least one in-scope host or wildcard.")
    if len(include) > 50 or len(exclude) > 50:
        raise ScopeError("Scope lists are capped at 50 patterns.")
    for pattern in (*include, *exclude):
        if "/" in pattern and not pattern.startswith("http"):
            raise ScopeError(f"CIDR ranges are not accepted ({pattern}). List hosts or wildcards.")
        _validate_pattern(pattern)
    return Scope(program, tuple(include), tuple(exclude), authorization)


def normalize_host(target: str) -> str:
    raw = target.strip()
    if not raw or any(c.isspace() for c in raw):
        raise ScopeError("Target is empty or contains spaces.")
    if "@" in raw:
        raise ScopeError("Targets with user info are refused.")
    lower = raw.lower()
    if "://" in lower:
        scheme, rest = lower.split("://", 1)
        if scheme not in {"http", "https"}:
            raise ScopeError("Only http and https URLs are accepted.")
        raw = rest
    raw = raw.split("/")[0].split("?")[0].split("#")[0]
    if raw.startswith("["):
        raise ScopeError("IPv6 targets are not supported.")
    if ":" in raw:
        host, port = raw.rsplit(":", 1)
        if not port.isdigit():
            raise ScopeError("Could not read the target host.")
        raw = host
    host = raw.strip(".").lower()
    if not host or len(host) > 253:
        raise ScopeError("Target host is missing or too long.")
    return host


def check_scope(scope: Scope, target: str) -> Decision:
    try:
        host = normalize_host(target)
    except ScopeError as exc:
        return Decision(False, target[:253], str(exc), "syntax")
    blocked = _blocked_name(host)
    if blocked:
        return Decision(False, host, blocked, "reserved")
    if _is_ipv4(host):
        if not _public_ipv4(host):
            return Decision(
                False,
                host,
                "Private, loopback, link-local, and other non-public addresses are blocked even if you list them.",
                "non-public-ip",
            )
    for pattern in scope.exclude:
        if host_matches(host, pattern):
            return Decision(False, host, f"{host} matches an exclusion ({pattern}).", "exclude")
    for pattern in scope.include:
        if host_matches(host, pattern):
            return Decision(True, host, f"{host} matches {pattern}.", pattern)
    return Decision(
        False,
        host,
        f"{host} is not covered by an in-scope pattern. CYBOT will not contact it.",
        "not-in-scope",
    )


def host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().strip()
    if "://" in pattern:
        pattern = normalize_host(pattern)
    pattern = pattern.split("/")[0]
    if ":" in pattern:
        pattern = pattern.rsplit(":", 1)[0]
    if pattern.startswith("*."):
        parent = pattern[2:]
        if host == parent or not host.endswith("." + parent):
            return False
        label = host[: -(len(parent) + 1)]
        return bool(label) and "." not in label
    if pattern.startswith("."):
        parent = pattern[1:]
        return host == parent or host.endswith("." + parent)
    return host == pattern


def registrable(host: str) -> str:
    host = host.lower().rstrip(".")
    if _is_ipv4(host):
        return host
    for suffix in _MULTI:
        if host == suffix:
            return host
        if host.endswith("." + suffix):
            labels = host.split(".")
            take = len(suffix.split(".")) + 1
            if len(labels) >= take:
                return ".".join(labels[-take:])
            return host
    labels = host.split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def _patterns(value) -> list[str]:
    if isinstance(value, str):
        parts = re.split(r"[\s,]+", value)
    elif isinstance(value, list):
        parts = [str(item) for item in value]
    else:
        raise ScopeError("Scope patterns must be a list or a newline-separated string.")
    return [part.strip().lower() for part in parts if part.strip()]


def _validate_pattern(pattern: str) -> None:
    if pattern.startswith("*."):
        _dns_or_die(pattern[2:])
        return
    if pattern.startswith("."):
        _dns_or_die(pattern[1:])
        return
    try:
        host = normalize_host(pattern)
    except ScopeError as exc:
        raise ScopeError(f"Bad scope pattern {pattern}: {exc}") from exc
    if _is_ipv4(host):
        return
    _dns_or_die(host)


def _dns_or_die(host: str) -> None:
    if not host.isascii() or len(host) > 253:
        raise ScopeError(f"Host {host} must be plain ASCII.")
    labels = host.split(".")
    if len(labels) < 2 and not _is_ipv4(host):
        raise ScopeError(f"Host {host} needs a domain or an IPv4 address.")
    for label in labels:
        if not _LABEL.match(label):
            raise ScopeError(f"Host {host} has an invalid label.")


def _blocked_name(host: str) -> str | None:
    if not host.isascii():
        return "Non-ASCII hosts are refused (punycode homographs are out of scope for this version)."
    if host in {"localhost", "metadata", "metadata.google.internal"} or host.endswith(
        (".local", ".internal", ".localhost")
    ):
        return f"{host} is a local or metadata name and is blocked."
    if _is_ipv4(host):
        return None
    labels = host.split(".")
    if any(not _LABEL.match(label) for label in labels):
        return f"{host} is not a valid DNS name."
    return None


def _is_ipv4(host: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
    except ValueError:
        return False


def _public_ipv4(host: str) -> bool:
    try:
        return bool(ipaddress.ip_address(host).is_global)
    except ValueError:
        return False


def ip_is_public(value: str) -> bool:
    try:
        return bool(ipaddress.ip_address(value).is_global)
    except ValueError:
        return False
