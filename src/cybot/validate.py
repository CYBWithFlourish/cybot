"""Turn an observation into a score, a curl the human can retest, and a flag.

The flag stays on. CYBOT does not confirm a vulnerability by itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from cybot.demo_app import DEMO_HOST, DEMO_PORT


@dataclass(frozen=True)
class Validation:
    confidence: float
    repro: str
    needs_human_validation: bool
    title: str
    evidence: str
    plain: str


def _curl(url: str) -> str:
    return f"curl -sS '{url}'"


def validate_reflection(body: str, marker: str, *, port: int = DEMO_PORT) -> Validation:
    reflected = marker in (body or "")
    url = f"http://{DEMO_HOST}:{port}/reflect?q={quote(marker, safe='')}"
    if reflected:
        return Validation(
            confidence=0.72,
            repro=_curl(url),
            needs_human_validation=True,
            title="Reflected parameter on the local demo",
            evidence=f"The marker came back unescaped in the demo response ({marker}).",
            plain=(
                "The local demo echoed the query value without encoding. "
                "This is not a confirmed vulnerability. A person needs to retest it."
            ),
        )
    return Validation(
        confidence=0.1,
        repro=_curl(url),
        needs_human_validation=True,
        title="Reflection check did not match",
        evidence="The marker was not present in the response.",
        plain="No reflection was observed. A person can still retest the request.",
    )


def validate_boolean(true_body: str, false_body: str, *, port: int = DEMO_PORT) -> Validation:
    true_hit = "widget" in (true_body or "")
    false_miss = "widget" not in (false_body or "")
    true_name = "widget' OR '1'='1"
    false_name = "widget' AND '1'='2"
    true_url = f"http://{DEMO_HOST}:{port}/lookup?name={quote(true_name, safe='')}"
    false_url = f"http://{DEMO_HOST}:{port}/lookup?name={quote(false_name, safe='')}"
    repro = _curl(true_url) + "\n" + _curl(false_url)
    if true_hit and false_miss:
        return Validation(
            confidence=0.7,
            repro=repro,
            needs_human_validation=True,
            title="Boolean lookup difference on the local demo",
            evidence="A true condition returned the demo row and a false condition did not.",
            plain=(
                "Two requests to the local demo differed in a way that fits a boolean SQL condition. "
                "This is not a confirmed vulnerability. A person needs to retest both requests."
            ),
        )
    return Validation(
        confidence=0.15,
        repro=repro,
        needs_human_validation=True,
        title="Boolean lookup did not differ",
        evidence="The two demo responses did not show the expected difference.",
        plain="No boolean difference was observed. A person can still retest the requests.",
    )


def validate_observation(host: str, url: str, *, matched: bool) -> Validation:
    """A non-demo observation. The curl repeats the request CYBOT already made."""
    confidence = 0.45 if matched else 0.2
    return Validation(
        confidence=confidence,
        repro=_curl(url),
        needs_human_validation=True,
        title=f"Observation on {host}",
        evidence="Tool output was recorded. It is not a confirmed vulnerability.",
        plain="Retest this request manually before reporting it.",
    )
