"""
FortiGate API management for the MCP server.

This module provides the core FortiGate API integration:
- Device connection management with persistent async HTTP clients
- Authentication handling (API token or basic auth)
- API session management with connection pooling
- Request/response processing
- Error handling and recovery
"""
import logging
import time
from typing import Dict, Any, Optional, Union, List
import httpx
import json
from ..config.models import FortiGateDeviceConfig, AuthConfig
from .logging import get_logger, log_api_call

class FortiGateAPIError(Exception):
    """Custom exception for FortiGate API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None,
                 device_id: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.device_id = device_id

class FortiGateAPI:
    """FortiGate API client for individual device communication.

    Handles all HTTP communication with a single FortiGate device using
    a persistent async HTTP client with connection pooling:
    - Authentication management
    - Request/response processing
    - Error handling and retries
    - Session management
    """

    def __init__(self, device_id: str, config: FortiGateDeviceConfig):
        """Initialize FortiGate API client.

        Args:
            device_id: Unique identifier for this device
            config: Device configuration including connection details
        """
        self.device_id = device_id
        self.config = config
        self.logger = get_logger(f"device.{device_id}")
        self._ngfw_mode_cache: Dict[str, str] = {}

        # Build base URL
        self.base_url = f"https://{config.host}:{config.port}/api/v2"

        # Setup authentication headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        if config.api_token:
            self.headers["Authorization"] = f"Bearer {config.api_token}"
            self.auth_method = "token"
        elif config.username and config.password:
            self.auth_method = "basic"
            self._basic_auth = (config.username, config.password)
        else:
            raise ValueError(f"Device {device_id}: Either api_token or username/password must be provided")

        if not config.verify_ssl:
            self.logger.warning(f"SSL verification disabled for device {device_id} - NOT recommended for production")

        verify: Union[bool, str]
        if not config.verify_ssl:
            verify = False
        elif config.ca_bundle:
            verify = config.ca_bundle
        else:
            verify = True

        # Create persistent async HTTP client with connection pooling
        self._client = httpx.AsyncClient(
            verify=verify,
            timeout=config.timeout,
            headers=self.headers,
            auth=(config.username, config.password) if self.auth_method == "basic" else None,
        )

        self.logger.info(f"Initialized FortiGate API client (auth: {self.auth_method})")

    async def close(self):
        """Close the underlying HTTP client and release connection pool resources."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        vdom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to FortiGate API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path (without /api/v2 prefix)
            params: Query parameters
            data: Request body data
            vdom: Virtual Domain (uses device default if not specified)

        Returns:
            API response as dictionary

        Raises:
            FortiGateAPIError: If API request fails
        """
        # Build URL
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        # Setup parameters
        if not params:
            params = {}
        params["vdom"] = vdom or self.config.vdom

        start_time = time.time()

        try:
            response = await self._client.request(
                method=method,
                url=url,
                params=params,
                json=data if data else None
            )

            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, response.status_code, duration_ms)

            # Handle error responses
            if response.status_code >= 400:
                error_msg = f"API request failed: {response.status_code}"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg += f" - {error_data['error']}"
                except Exception:
                    error_msg += f" - {response.text}"

                raise FortiGateAPIError(
                    error_msg,
                    status_code=response.status_code,
                    device_id=self.device_id
                )

            # Parse response
            try:
                return response.json()
            except json.JSONDecodeError:
                # Some endpoints may return empty responses
                return {"status": "success"}

        except httpx.RequestError as e:
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, method, endpoint, None, duration_ms)
            raise FortiGateAPIError(
                f"Network error: {str(e)}",
                device_id=self.device_id
            )

    async def test_connection(self) -> bool:
        """Test connection to FortiGate device.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            await self.get_system_status()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    # System endpoints
    async def get_system_status(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system status information."""
        return await self._make_request("GET", "monitor/system/status", vdom=vdom)

    async def get_system_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system settings for the target VDOM."""
        return await self._make_request("GET", "cmdb/system/settings", vdom=vdom)

    async def get_system_interface(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get system interface information."""
        return await self._make_request("GET", "monitor/system/interface", vdom=vdom)

    async def get_vdoms(self) -> Dict[str, Any]:
        """Get list of Virtual Domains."""
        return await self._make_request("GET", "cmdb/system/vdom")

    async def get_dns_settings(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS resolver settings."""
        return await self._make_request("GET", "cmdb/system/dns", vdom=vdom)

    async def get_dns_databases(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS database zones."""
        return await self._make_request("GET", "cmdb/system/dns-database", vdom=vdom)

    async def get_dns_database_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a DNS database zone."""
        return await self._make_request("GET", f"cmdb/system/dns-database/{name}", vdom=vdom)

    async def get_dns_servers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DNS server interfaces."""
        return await self._make_request("GET", "cmdb/system/dns-server", vdom=vdom)

    async def get_dhcp_servers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get DHCP server configuration."""
        return await self._make_request("GET", "cmdb/system.dhcp/server", vdom=vdom)

    async def get_dhcp_server_detail(self, server_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a DHCP server."""
        return await self._make_request("GET", f"cmdb/system.dhcp/server/{server_id}", vdom=vdom)

    async def get_dhcp_leases(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get runtime DHCP lease information."""
        return await self._make_request("GET", "monitor/system/dhcp", vdom=vdom)

    @staticmethod
    def _first_result(response: Dict[str, Any]) -> Dict[str, Any]:
        """Return the first result object from a FortiGate API response."""
        results = response.get("results", {})
        if isinstance(results, list):
            return results[0] if results else {}
        return results if isinstance(results, dict) else {}

    async def get_ngfw_mode(self, vdom: Optional[str] = None) -> str:
        """Get the FortiOS NGFW mode for the target VDOM."""
        effective_vdom = vdom or self.config.vdom
        if effective_vdom in self._ngfw_mode_cache:
            return self._ngfw_mode_cache[effective_vdom]

        settings = await self.get_system_settings(vdom=effective_vdom)
        settings_result = self._first_result(settings)
        mode = (
            settings_result.get("ngfw-mode")
            or settings_result.get("ngfw_mode")
            or "profile-based"
        )
        self._ngfw_mode_cache[effective_vdom] = str(mode)
        return str(mode)

    async def _firewall_policy_endpoint(self, vdom: Optional[str] = None) -> str:
        """Select the correct policy endpoint for the target VDOM mode."""
        try:
            mode = await self.get_ngfw_mode(vdom=vdom)
        except Exception as exc:
            self.logger.warning(
                "Unable to detect NGFW mode for device %s VDOM %s: %s",
                self.device_id,
                vdom or self.config.vdom,
                exc,
            )
            mode = "profile-based"

        if mode == "policy-based":
            return "cmdb/firewall/security-policy"
        return "cmdb/firewall/policy"

    # Interface endpoints
    async def get_interfaces(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get interface configuration."""
        return await self._make_request("GET", "cmdb/system/interface", vdom=vdom)

    async def get_interface_status(self, interface_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get specific interface status."""
        return await self._make_request("GET", f"monitor/system/interface?interface={interface_name}", vdom=vdom)

    # Firewall policy endpoints
    async def get_firewall_policies(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall policies."""
        endpoint = await self._firewall_policy_endpoint(vdom=vdom)
        return await self._make_request("GET", endpoint, vdom=vdom)

    async def create_firewall_policy(self, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new firewall policy."""
        endpoint = await self._firewall_policy_endpoint(vdom=vdom)
        return await self._make_request("POST", endpoint, data=policy_data, vdom=vdom)

    async def update_firewall_policy(self, policy_id: str, policy_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing firewall policy."""
        endpoint = await self._firewall_policy_endpoint(vdom=vdom)
        return await self._make_request("PUT", f"{endpoint}/{policy_id}", data=policy_data, vdom=vdom)

    async def get_firewall_policy_detail(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific firewall policy."""
        endpoint = await self._firewall_policy_endpoint(vdom=vdom)
        return await self._make_request("GET", f"{endpoint}/{policy_id}", vdom=vdom)

    async def delete_firewall_policy(self, policy_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete firewall policy."""
        endpoint = await self._firewall_policy_endpoint(vdom=vdom)
        return await self._make_request("DELETE", f"{endpoint}/{policy_id}", vdom=vdom)

    # Address object endpoints
    async def get_address_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get address objects."""
        return await self._make_request("GET", "cmdb/firewall/address", vdom=vdom)

    async def get_address_object_detail(self, address_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific address object."""
        return await self._make_request("GET", f"cmdb/firewall/address/{address_name}", vdom=vdom)

    async def create_address_object(self, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new address object."""
        return await self._make_request("POST", "cmdb/firewall/address", data=address_data, vdom=vdom)

    async def update_address_object(self, address_name: str, address_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing address object."""
        return await self._make_request("PUT", f"cmdb/firewall/address/{address_name}", data=address_data, vdom=vdom)

    async def delete_address_object(self, address_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete address object."""
        return await self._make_request("DELETE", f"cmdb/firewall/address/{address_name}", vdom=vdom)

    # Service object endpoints
    async def get_service_objects(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get service objects."""
        return await self._make_request("GET", "cmdb/firewall.service/custom", vdom=vdom)

    async def get_service_object_detail(self, service_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific service object."""
        return await self._make_request("GET", f"cmdb/firewall.service/custom/{service_name}", vdom=vdom)

    async def create_service_object(self, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new service object."""
        return await self._make_request("POST", "cmdb/firewall.service/custom", data=service_data, vdom=vdom)

    async def update_service_object(self, service_name: str, service_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing service object."""
        return await self._make_request("PUT", f"cmdb/firewall.service/custom/{service_name}", data=service_data, vdom=vdom)

    async def delete_service_object(self, service_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete service object."""
        return await self._make_request("DELETE", f"cmdb/firewall.service/custom/{service_name}", vdom=vdom)

    # Routing endpoints
    async def get_static_routes(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get static routes."""
        return await self._make_request("GET", "cmdb/router/static", vdom=vdom)

    async def create_static_route(self, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new static route."""
        return await self._make_request("POST", "cmdb/router/static", data=route_data, vdom=vdom)

    async def update_static_route(self, route_id: str, route_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing static route."""
        return await self._make_request("PUT", f"cmdb/router/static/{route_id}", data=route_data, vdom=vdom)

    async def delete_static_route(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete static route."""
        return await self._make_request("DELETE", f"cmdb/router/static/{route_id}", vdom=vdom)

    async def get_static_route_detail(self, route_id: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific static route."""
        return await self._make_request("GET", f"cmdb/router/static/{route_id}", vdom=vdom)

    async def get_routing_table(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get routing table."""
        return await self._make_request("GET", "monitor/router/ipv4", vdom=vdom)

    # Virtual IP endpoints
    async def get_virtual_ips(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get virtual IPs."""
        return await self._make_request("GET", "cmdb/firewall/vip", vdom=vdom)

    async def create_virtual_ip(self, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create new virtual IP."""
        return await self._make_request("POST", "cmdb/firewall/vip", data=vip_data, vdom=vdom)

    async def update_virtual_ip(self, vip_name: str, vip_data: Dict[str, Any], vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update existing virtual IP."""
        return await self._make_request("PUT", f"cmdb/firewall/vip/{vip_name}", data=vip_data, vdom=vdom)

    async def delete_virtual_ip(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete virtual IP."""
        return await self._make_request("DELETE", f"cmdb/firewall/vip/{vip_name}", vdom=vdom)

    async def get_virtual_ip_detail(self, vip_name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a specific virtual IP."""
        return await self._make_request("GET", f"cmdb/firewall/vip/{vip_name}", vdom=vdom)

    # Load-balancing endpoints. FortiGate represents virtual servers as
    # firewall VIP objects with type=server-load-balance.
    async def get_virtual_servers(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get load-balancing virtual servers."""
        response = await self.get_virtual_ips(vdom=vdom)
        results = response.get("results")
        if isinstance(results, list):
            response["results"] = [
                item for item in results
                if item.get("type") == "server-load-balance"
                or item.get("server-type")
                or item.get("realservers")
            ]
        return response

    async def get_virtual_server_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get a load-balancing virtual server."""
        return await self.get_virtual_ip_detail(name, vdom=vdom)

    async def create_virtual_server(self, virtual_server_data: Dict[str, Any],
                                    vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create a load-balancing virtual server."""
        data = dict(virtual_server_data)
        data["type"] = "server-load-balance"
        return await self._make_request("POST", "cmdb/firewall/vip", data=data, vdom=vdom)

    async def update_virtual_server(self, name: str, virtual_server_data: Dict[str, Any],
                                    vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update a load-balancing virtual server."""
        data = dict(virtual_server_data)
        if "type" not in data:
            data["type"] = "server-load-balance"
        return await self._make_request("PUT", f"cmdb/firewall/vip/{name}", data=data, vdom=vdom)

    async def delete_virtual_server(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a load-balancing virtual server."""
        return await self.delete_virtual_ip(name, vdom=vdom)

    async def get_virtual_server_status(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get virtual server status where the appliance exposes it."""
        try:
            status = await self._make_request("GET", f"monitor/firewall/vip/{name}", vdom=vdom)
            status["runtime_status_available"] = True
            return status
        except FortiGateAPIError as exc:
            detail = await self.get_virtual_server_detail(name, vdom=vdom)
            detail["runtime_status_available"] = False
            detail["runtime_status_error"] = str(exc)
            return detail

    async def get_load_balance_health_checks(self, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get load-balance health checks."""
        return await self._make_request("GET", "cmdb/firewall/ldb-monitor", vdom=vdom)

    async def get_load_balance_health_check_detail(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed information for a load-balance health check."""
        return await self._make_request("GET", f"cmdb/firewall/ldb-monitor/{name}", vdom=vdom)

    async def create_load_balance_health_check(self, monitor_data: Dict[str, Any],
                                               vdom: Optional[str] = None) -> Dict[str, Any]:
        """Create a load-balance health check."""
        return await self._make_request("POST", "cmdb/firewall/ldb-monitor", data=monitor_data, vdom=vdom)

    async def update_load_balance_health_check(self, name: str, monitor_data: Dict[str, Any],
                                               vdom: Optional[str] = None) -> Dict[str, Any]:
        """Update a load-balance health check."""
        return await self._make_request("PUT", f"cmdb/firewall/ldb-monitor/{name}", data=monitor_data, vdom=vdom)

    async def delete_load_balance_health_check(self, name: str, vdom: Optional[str] = None) -> Dict[str, Any]:
        """Delete a load-balance health check."""
        return await self._make_request("DELETE", f"cmdb/firewall/ldb-monitor/{name}", vdom=vdom)


class FortiGateManager:
    """Manager for multiple FortiGate devices.

    Handles device registration, connection management, and provides
    unified access to multiple FortiGate devices.
    """

    def __init__(self, devices: Dict[str, FortiGateDeviceConfig], auth_config: AuthConfig):
        """Initialize FortiGate manager.

        Args:
            devices: Dictionary of device configurations
            auth_config: Authentication configuration
        """
        self.devices: Dict[str, FortiGateAPI] = {}
        self.auth_config = auth_config
        self.logger = get_logger("fortigate_manager")

        # Initialize devices
        for device_id, config in devices.items():
            try:
                self.devices[device_id] = FortiGateAPI(device_id, config)
                self.logger.info(f"Initialized device: {device_id}")
            except Exception as e:
                self.logger.error(f"Failed to initialize device {device_id}: {e}")

    def get_device(self, device_id: str) -> FortiGateAPI:
        """Get FortiGate API client for a device.

        Args:
            device_id: Device identifier

        Returns:
            FortiGateAPI client instance

        Raises:
            ValueError: If device not found
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")
        return self.devices[device_id]

    def list_devices(self) -> List[str]:
        """List all registered device IDs.

        Returns:
            List of device identifiers
        """
        return list(self.devices.keys())

    def add_device(self, device_id: str, host: str, port: int = 443,
                   username: Optional[str] = None, password: Optional[str] = None,
                   api_token: Optional[str] = None, vdom: str = "root",
                   verify_ssl: bool = True, timeout: int = 30,
                   ca_bundle: Optional[str] = None) -> None:
        """Add a new device to the manager.

        Args:
            device_id: Unique identifier for the device
            host: Device IP address or hostname
            port: HTTPS port
            username: Username for authentication
            password: Password for authentication
            api_token: API token for authentication
            vdom: Virtual Domain name
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            ca_bundle: Path to a CA bundle PEM file
        """
        if device_id in self.devices:
            raise ValueError(f"Device '{device_id}' already exists")

        # Create device configuration
        device_config = FortiGateDeviceConfig(
            host=host,
            port=port,
            username=username,
            password=password,
            api_token=api_token,
            vdom=vdom,
            verify_ssl=verify_ssl,
            ca_bundle=ca_bundle,
            timeout=timeout
        )

        # Create API client
        self.devices[device_id] = FortiGateAPI(device_id, device_config)
        self.logger.info(f"Added device: {device_id}")

    async def remove_device(self, device_id: str) -> None:
        """Remove a device from the manager and close its connection.

        Args:
            device_id: Device identifier to remove
        """
        if device_id not in self.devices:
            raise ValueError(f"Device '{device_id}' not found")

        await self.devices[device_id].close()
        del self.devices[device_id]
        self.logger.info(f"Removed device: {device_id}")

    async def test_all_connections(self) -> Dict[str, bool]:
        """Test connections to all devices.

        Returns:
            Dictionary mapping device IDs to connection status
        """
        results = {}
        for device_id, api_client in self.devices.items():
            try:
                results[device_id] = await api_client.test_connection()
            except Exception as e:
                self.logger.error(f"Connection test failed for {device_id}: {e}")
                results[device_id] = False
        return results

    async def close_all(self) -> None:
        """Close all device clients and release connection pool resources."""
        for device_id, api_client in self.devices.items():
            try:
                await api_client.close()
                self.logger.info(f"Closed connection for device: {device_id}")
            except Exception as e:
                self.logger.error(f"Error closing connection for {device_id}: {e}")
