"""
Pytest configuration and fixtures for FortiGate MCP server tests.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from src.fortigate_mcp.core.fortigate import FortiGateManager, FortiGateAPI
from src.fortigate_mcp.config.models import FortiGateDeviceConfig, AuthConfig


@pytest.fixture
def auth_config():
    """Default auth configuration fixture."""
    return AuthConfig(require_auth=False, api_tokens=[], allowed_origins=[])


@pytest.fixture
def fortigate_manager(auth_config):
    """FortiGate manager fixture with no devices."""
    manager = FortiGateManager({}, auth_config)
    yield manager
    manager.devices.clear()


@pytest.fixture
def device_config():
    """Sample device configuration fixture."""
    return FortiGateDeviceConfig(
        host="192.168.1.1",
        username="admin",
        password="password",
        vdom="root",
        verify_ssl=False,
        timeout=30,
        port=443
    )


@pytest.fixture
def mock_fortigate_api():
    """Mock FortiGate API fixture with AsyncMock methods."""
    mock_api = MagicMock(spec=FortiGateAPI)
    mock_api.device_id = "test_device"

    # Mock config attribute
    mock_config = MagicMock()
    mock_config.host = "192.168.1.1"
    mock_config.vdom = "root"
    mock_api.config = mock_config
    mock_api.auth_method = "basic"

    # All API methods are now async - use AsyncMock
    mock_api.test_connection = AsyncMock(return_value=True)
    mock_api.close = AsyncMock()

    mock_api.get_system_status = AsyncMock(return_value={
        "hostname": "FortiGate",
        "version": "v7.0.0",
        "status": "ok"
    })

    mock_api.get_vdoms = AsyncMock(return_value={
        "results": [{"name": "root", "enabled": True}]
    })

    mock_api.get_dns_settings = AsyncMock(return_value={
        "results": {"primary": "8.8.8.8", "secondary": "1.1.1.1"}
    })

    mock_api.get_dns_databases = AsyncMock(return_value={
        "results": [{"name": "example.test", "domain": "example.test"}]
    })

    mock_api.get_dns_database_detail = AsyncMock(return_value={
        "results": {"name": "example.test", "domain": "example.test", "dns-entry": []}
    })

    mock_api.get_dns_servers = AsyncMock(return_value={
        "results": [{"name": "port1", "mode": "recursive"}]
    })

    mock_api.get_dhcp_servers = AsyncMock(return_value={
        "results": [{"id": 1, "interface": "port1", "default-gateway": "192.168.1.1"}]
    })

    mock_api.get_dhcp_server_detail = AsyncMock(return_value={
        "results": {"id": 1, "interface": "port1", "default-gateway": "192.168.1.1"}
    })

    mock_api.get_dhcp_leases = AsyncMock(return_value={
        "results": [{"ip": "192.168.1.10", "mac": "00:11:22:33:44:55", "status": "leased"}]
    })

    mock_api.get_interfaces = AsyncMock(return_value={
        "results": [
            {"name": "port1", "status": "up"},
            {"name": "port2", "status": "down"}
        ]
    })

    mock_api.get_interface_status = AsyncMock(return_value={
        "results": {"name": "port1", "status": "up", "ip": "192.168.1.1"}
    })

    mock_api.get_firewall_policies = AsyncMock(return_value={
        "results": [{"policyid": 1, "name": "Allow_HTTP", "action": "accept"}]
    })

    mock_api.get_firewall_policy_detail = AsyncMock(return_value={
        "results": {
            "policyid": 35,
            "name": "WAN->ManDown-Project",
            "srcintf": [{"name": "wan1"}],
            "dstintf": [{"name": "internal"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": "Yartu-1-TCP"}],
            "service": [{"name": "ALL"}],
            "action": "accept",
            "status": "enable"
        }
    })

    mock_api.create_firewall_policy = AsyncMock(return_value={"status": "success"})
    mock_api.update_firewall_policy = AsyncMock(return_value={"status": "success"})
    mock_api.delete_firewall_policy = AsyncMock(return_value={"status": "success"})

    mock_api.get_address_objects = AsyncMock(return_value={
        "results": [{"name": "test_addr", "subnet": "192.168.1.0/24"}]
    })
    mock_api.get_address_object_detail = AsyncMock(return_value={
        "results": {"name": "test_addr", "subnet": "192.168.1.0/24"}
    })
    mock_api.create_address_object = AsyncMock(return_value={"status": "success"})
    mock_api.update_address_object = AsyncMock(return_value={"status": "success"})
    mock_api.delete_address_object = AsyncMock(return_value={"status": "success"})

    mock_api.get_service_objects = AsyncMock(return_value={
        "results": [{"name": "HTTP", "tcp-portrange": "80"}]
    })
    mock_api.get_service_object_detail = AsyncMock(return_value={
        "results": {"name": "HTTP", "tcp-portrange": "80"}
    })
    mock_api.create_service_object = AsyncMock(return_value={"status": "success"})
    mock_api.update_service_object = AsyncMock(return_value={"status": "success"})
    mock_api.delete_service_object = AsyncMock(return_value={"status": "success"})

    mock_api.get_static_routes = AsyncMock(return_value={
        "results": [{"dst": "10.0.0.0/8", "gateway": "192.168.1.1"}]
    })
    mock_api.create_static_route = AsyncMock(return_value={"status": "success"})
    mock_api.update_static_route = AsyncMock(return_value={"status": "success"})
    mock_api.delete_static_route = AsyncMock(return_value={"status": "success"})
    mock_api.get_static_route_detail = AsyncMock(return_value={
        "results": {"seq-num": 1, "dst": "10.0.0.0/8", "gateway": "192.168.1.1"}
    })

    mock_api.get_routing_table = AsyncMock(return_value={
        "results": [{"dst": "0.0.0.0/0", "gateway": "192.168.1.1"}]
    })

    mock_api.get_virtual_ips = AsyncMock(return_value={
        "results": [{"name": "test_vip", "extip": "1.2.3.4", "mappedip": "10.0.0.1"}]
    })
    mock_api.create_virtual_ip = AsyncMock(return_value={"status": "success"})
    mock_api.update_virtual_ip = AsyncMock(return_value={"status": "success"})
    mock_api.delete_virtual_ip = AsyncMock(return_value={"status": "success"})
    mock_api.get_virtual_ip_detail = AsyncMock(return_value={
        "results": {"name": "test_vip", "extip": "1.2.3.4", "mappedip": "10.0.0.1"}
    })
    mock_api.get_virtual_servers = AsyncMock(return_value={
        "results": [
            {
                "name": "test_vs",
                "type": "server-load-balance",
                "extip": "1.2.3.4",
                "server-type": "http",
                "monitor": ["http-monitor"],
                "realservers": [{"id": 1, "ip": "10.0.0.10", "port": 80}]
            }
        ]
    })
    mock_api.get_virtual_server_detail = AsyncMock(return_value={
        "results": {
            "name": "test_vs",
            "type": "server-load-balance",
            "monitor": ["http-monitor"],
            "realservers": [{"id": 1, "ip": "10.0.0.10", "port": 80}]
        }
    })
    mock_api.create_virtual_server = AsyncMock(return_value={"status": "success"})
    mock_api.update_virtual_server = AsyncMock(return_value={"status": "success"})
    mock_api.delete_virtual_server = AsyncMock(return_value={"status": "success"})
    mock_api.get_virtual_server_status = AsyncMock(return_value={
        "runtime_status_available": True,
        "results": {"name": "test_vs", "status": "up"}
    })
    mock_api.get_load_balance_health_checks = AsyncMock(return_value={
        "results": [{"name": "http-monitor", "type": "http", "interval": 5}]
    })
    mock_api.get_load_balance_health_check_detail = AsyncMock(return_value={
        "results": {"name": "http-monitor", "type": "http", "interval": 5}
    })
    mock_api.create_load_balance_health_check = AsyncMock(return_value={"status": "success"})
    mock_api.update_load_balance_health_check = AsyncMock(return_value={"status": "success"})
    mock_api.delete_load_balance_health_check = AsyncMock(return_value={"status": "success"})

    return mock_api


@pytest.fixture
def sample_policy_data():
    """Sample policy data fixture."""
    return {
        "name": "Test_Policy",
        "srcintf": [{"name": "port1"}],
        "dstintf": [{"name": "port2"}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "service": [{"name": "ALL"}],
        "action": "accept",
        "schedule": "always",
        "comments": "Test policy created by pytest"
    }
