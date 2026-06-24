"""HTTP server startup and security tests."""

import json

from src.fortigate_mcp import server_http
from src.fortigate_mcp.server_http import FortiGateMCPHTTPServer


class FakeFastMCP:
    """Minimal FastMCP test double."""

    instances = []

    def __init__(self, name, **kwargs):
        self.name = name
        self.kwargs = kwargs
        self.tools = []
        self.run_calls = []
        FakeFastMCP.instances.append(self)

    def tool(self, description=None):
        def decorator(func):
            self.tools.append((func.__name__, description))
            return func

        return decorator

    def run(self, **kwargs):
        self.run_calls.append(kwargs)


def _write_config(tmp_path, auth=None):
    config_path = tmp_path / "fortigate.config.json"
    config = {
        "server": {"host": "0.0.0.0", "port": 8814},
        "fortigate": {
            "devices": {
                "default": {
                    "host": "192.0.2.10",
                    "api_token": "test-token",
                    "vdom": "root",
                    "verify_ssl": True,
                }
            }
        },
        "auth": auth or {"require_auth": False, "api_tokens": []},
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return config_path


def test_http_server_configures_streamable_http(monkeypatch, tmp_path):
    """HTTP server passes host, port, and path to FastMCP construction."""
    FakeFastMCP.instances = []
    monkeypatch.setattr(server_http, "FastMCP", FakeFastMCP)

    server = FortiGateMCPHTTPServer(
        config_path=str(_write_config(tmp_path)),
        host="0.0.0.0",
        port=8814,
        path="/fortigate-mcp",
    )

    assert server.mcp.kwargs["host"] == "0.0.0.0"
    assert server.mcp.kwargs["port"] == 8814
    assert server.mcp.kwargs["streamable_http_path"] == "/fortigate-mcp"


def test_http_server_run_uses_streamable_transport(monkeypatch, tmp_path):
    """HTTP server run uses the current MCP SDK streamable HTTP transport."""
    FakeFastMCP.instances = []
    monkeypatch.setattr(server_http, "FastMCP", FakeFastMCP)

    server = FortiGateMCPHTTPServer(config_path=str(_write_config(tmp_path)))
    server.run()

    assert server.mcp.run_calls == [{"transport": "streamable-http"}]


def test_http_server_enables_auth_and_host_protection(monkeypatch, tmp_path):
    """Auth config wires FastMCP token verifier and transport security."""
    if not server_http.MCP_SECURITY_AVAILABLE:
        return

    FakeFastMCP.instances = []
    monkeypatch.setattr(server_http, "FastMCP", FakeFastMCP)
    config_path = _write_config(
        tmp_path,
        auth={
            "require_auth": True,
            "api_tokens": ["secret"],
            "allowed_hosts": ["mcp.example.test:8814"],
            "allowed_origins": ["https://mcp.example.test"],
        },
    )

    server = FortiGateMCPHTTPServer(config_path=str(config_path))

    assert "auth" in server.mcp.kwargs
    assert "token_verifier" in server.mcp.kwargs
    assert "transport_security" in server.mcp.kwargs


def test_http_server_accepts_auth_tokens_from_environment(monkeypatch, tmp_path):
    """Production can keep MCP bearer tokens outside JSON config files."""
    if not server_http.MCP_SECURITY_AVAILABLE:
        return

    FakeFastMCP.instances = []
    monkeypatch.setattr(server_http, "FastMCP", FakeFastMCP)
    monkeypatch.setenv("MCP_REQUIRE_AUTH", "true")
    monkeypatch.setenv("MCP_AUTH_TOKENS", '["env-secret"]')
    config_path = _write_config(
        tmp_path,
        auth={
            "require_auth": False,
            "api_tokens": [],
            "allowed_hosts": ["mcp.example.test:8814"],
        },
    )

    server = FortiGateMCPHTTPServer(config_path=str(config_path))

    assert "auth" in server.mcp.kwargs
    assert "token_verifier" in server.mcp.kwargs
    assert "transport_security" in server.mcp.kwargs


def test_start_script_does_not_overwrite_shell_path():
    """The HTTP startup script must not use PATH for the MCP endpoint."""
    lines = open("start_http_server.sh", encoding="utf-8").read().splitlines()

    assert 'MCP_PATH="${MCP_HTTP_PATH:-/fortigate-mcp}"' in lines
    assert 'PATH="${MCP_HTTP_PATH:-/fortigate-mcp}"' not in lines
