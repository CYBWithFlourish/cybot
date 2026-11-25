import pytest

from cybot.connectors import (
    GatewayError,
    assert_route,
    connector_chat_url,
    connector_headers,
    parse_gateway_list,
    prefer_model,
)
from cybot.policy import select_builtin, vet_external
from cybot.redact import redact
from cybot.scope import Scope, check_scope, parse_scope


def test_wildcard_is_one_label_deep():
    scope = parse_scope(
        {
            "program": "Example",
            "include": ["*.example.com"],
            "exclude": ["mail.example.com"],
            "authorization": "I am authorized to test the listed assets only.",
        }
    )
    assert check_scope(scope, "www.example.com").allowed
    assert not check_scope(scope, "example.com").allowed
    assert not check_scope(scope, "a.b.example.com").allowed
    assert not check_scope(scope, "mail.example.com").allowed


def test_private_and_metadata_addresses_are_blocked_even_if_listed():
    scope = Scope(
        "Lab",
        ("127.0.0.1", "169.254.169.254"),
        (),
        "I am authorized to test only what this scope lists.",
    )
    assert check_scope(scope, "127.0.0.1").rule == "non-public-ip"
    assert not check_scope(scope, "169.254.169.254").allowed


def test_cidr_is_rejected():
    with pytest.raises(Exception):
        parse_scope(
            {
                "program": "Example",
                "include": ["10.0.0.0/8"],
                "authorization": "I am authorized to test this range.",
            }
        )


def test_passive_selection_does_not_include_active_probes():
    names = [spec.name for spec in select_builtin("passive", secrets=set(), binaries=set(), phase="probe")]
    assert names == []
    discover = [spec.name for spec in select_builtin("passive", secrets=set(), binaries=set(), phase="discover")]
    assert "dns_records" in discover
    assert "firecrawl_page" not in discover


def test_external_denylist_beats_an_allow_entry():
    allowed, reason = vet_external("nuclei_scan", "template scanner", ["nuclei_scan"])
    assert not allowed
    assert "denylist" in reason
    ok, _ = vet_external("get_domain_report", "domain report", ["get_domain_report"])
    assert ok
    blocked, _ = vet_external("get_domain_report", "domain report", ["other"])
    assert not blocked


def test_redact_strips_provider_keys():
    text = redact("Authorization: Bearer sk-testkeyvalue12345678 and AIzaSyTESTKEY1234567890")
    assert "sk-testkeyvalue12345678" not in text
    assert "AIzaSyTESTKEY1234567890" not in text


def test_connector_preference_is_ollama_then_openrouter():
    payload = {
        "connections": [
            {"id": "conn_or", "provider": "openrouter", "gateway_base_url": "https://api.sprites.dev/v1/gateway/openrouter/conn_or"},
            {"id": "conn_ol", "provider": "ollama", "gateway_base_url": "https://api.sprites.dev/v1/gateway/ollama/conn_ol"},
        ]
    }
    connectors = parse_gateway_list(payload)
    chosen = prefer_model(connectors, "auto")
    assert chosen is not None
    assert chosen.provider == "ollama"
    grok_path = connector_chat_url(connectors[0].gateway_base, "openrouter")
    assert grok_path.endswith("/api/v1/chat/completions")


def test_opencode_go_base_is_openai_compatible():
    from cybot.llm import chat_completions_url

    assert chat_completions_url("https://opencode.ai/zen/go/v1").endswith("/v1/chat/completions")
    assert chat_completions_url("https://opencode.ai/zen/v1").endswith("/v1/chat/completions")


def test_connector_calls_do_not_send_a_provider_key():
    headers = connector_headers(True, "sk-realsecret", "bearer")
    assert "Authorization" not in headers
    assert "sk-realsecret" not in str(headers)
    direct = connector_headers(False, "sk-realsecret", "bearer")
    assert direct["Authorization"] == "Bearer sk-realsecret"


def test_gateway_routes_are_allowlisted():
    assert_route("ollama", "POST", "/v1/chat/completions")
    assert_route("firecrawl", "POST", "/v2/scrape")
    assert_route("github", "GET", "/search/code")
    with pytest.raises(GatewayError):
        assert_route("github", "POST", "/repos/acme/acme/issues")
    with pytest.raises(GatewayError):
        assert_route("slack-bot", "POST", "/api/chat.postMessage")
    with pytest.raises(GatewayError):
        assert_route("firecrawl", "POST", "/v2/crawl")
