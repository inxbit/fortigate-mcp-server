"""DNS and DHCP read tools for FortiGate MCP."""

from typing import List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateTool


class DNSDHCPTools(FortiGateTool):
    """Read-only tools for FortiGate DNS and DHCP state."""

    async def get_dns_settings(
        self,
        device_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Get DNS resolver settings."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dns_settings(vdom=vdom)
            return self._format_response(data, "dns_settings")
        except Exception as e:
            return self._handle_error("get DNS settings", device_id, e)

    async def list_dns_databases(
        self,
        device_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """List DNS database zones."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dns_databases(vdom=vdom)
            return self._format_response(data, "dns_databases")
        except Exception as e:
            return self._handle_error("list DNS databases", device_id, e)

    async def get_dns_database_detail(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Get DNS database zone detail."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dns_database_detail(name, vdom=vdom)
            return self._format_response(data, "dns_database_detail")
        except Exception as e:
            return self._handle_error("get DNS database detail", device_id, e)

    async def list_dns_servers(
        self,
        device_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """List DNS server interfaces."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dns_servers(vdom=vdom)
            return self._format_response(data, "dns_servers")
        except Exception as e:
            return self._handle_error("list DNS servers", device_id, e)

    async def list_dhcp_servers(
        self,
        device_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """List DHCP server configuration."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dhcp_servers(vdom=vdom)
            return self._format_response(data, "dhcp_servers")
        except Exception as e:
            return self._handle_error("list DHCP servers", device_id, e)

    async def get_dhcp_server_detail(
        self,
        device_id: str,
        server_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Get DHCP server detail."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(server_id=server_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dhcp_server_detail(
                server_id,
                vdom=vdom,
            )
            return self._format_response(data, "dhcp_server_detail")
        except Exception as e:
            return self._handle_error("get DHCP server detail", device_id, e)

    async def list_dhcp_leases(
        self,
        device_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """List DHCP leases."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_dhcp_leases(vdom=vdom)
            return self._format_response(data, "dhcp_leases")
        except Exception as e:
            return self._handle_error("list DHCP leases", device_id, e)
