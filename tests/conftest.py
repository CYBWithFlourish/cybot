import pytest
from fastapi.testclient import TestClient

from cybot.app import create_app
from cybot.config import Config

HEADERS = {"X-CYBOT": "1"}


async def _no_connectors(_url):
    return {"connections": []}


@pytest.fixture
def cfg(tmp_path):
    return Config(
        data_dir=tmp_path / "data",
        demo=True,
        telegram=False,
        inline_runs=True,
        discover_mcp=False,
        mcp_token="mcp-test-token",
        rate_per_min=1000,
        run_timeout=20,
    )


@pytest.fixture
def client(cfg):
    app = create_app(cfg, connector_fetch=_no_connectors)
    with TestClient(app) as test_client:
        response = test_client.post(
            "/api/setup", headers=HEADERS, json={"password": "correct-horse"}
        )
        assert response.status_code == 200, response.text
        yield test_client
