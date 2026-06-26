"""DNS and DHCP tools for FortiGate MCP."""

from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateTool


class DNSDHCPTools(FortiGateTool):
    """Tools for FortiGate DNS and DHCP state."""

    @staticmethod
    def _target_id(data: Optional[Dict[str, Any]], *keys: str) -> Optional[str]:
        """Resolve a FortiOS object key from a payload or API result."""
        if not isinstance(data, dict):
            return None

        for key in keys:
            value = data.get(key)
            if value is not None:
                return str(value)

        results = data.get("results")
        if isinstance(results, dict):
            for key in keys:
                value = results.get(key)
                if value is not None:
                    return str(value)

        return None

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

    async def create_dns_database(
        self,
        device_id: str,
        database_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Create a DNS database zone."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(database_data=database_data)
            target_id = self._target_id(database_data, "name", "domain")
            if target_id is None:
                raise ValueError("DNS database data must include a name or domain")

            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_dns_database(database_data, vdom=vdom)
            target_id = (
                self._target_id(api_result, "mkey", "name", "domain") or target_id
            )
            after = await api_client.get_dns_database_detail(target_id, vdom=vdom)
            return self._format_write_result(
                "create DNS database",
                device_id,
                "dns_database",
                target_id,
                vdom=vdom,
                request_data=database_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create DNS database", device_id, e)

    async def update_dns_database(
        self,
        device_id: str,
        name: str,
        database_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Update a DNS database zone."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, database_data=database_data)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_dns_database_detail(name, vdom=vdom)
            api_result = await api_client.update_dns_database(
                name, database_data, vdom=vdom
            )
            after = await api_client.get_dns_database_detail(name, vdom=vdom)
            return self._format_write_result(
                "update DNS database",
                device_id,
                "dns_database",
                name,
                vdom=vdom,
                request_data=database_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update DNS database", device_id, e)

    async def delete_dns_database(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Delete a DNS database zone."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_dns_database_detail(name, vdom=vdom)
            api_result = await api_client.delete_dns_database(name, vdom=vdom)
            return self._format_write_result(
                "delete DNS database",
                device_id,
                "dns_database",
                name,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete DNS database", device_id, e)

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

    async def create_dns_server(
        self,
        device_id: str,
        server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Create a DNS server interface."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(server_data=server_data)
            target_id = self._target_id(server_data, "name", "interface")
            if target_id is None:
                raise ValueError("DNS server data must include a name or interface")

            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_dns_server(server_data, vdom=vdom)
            target_id = (
                self._target_id(api_result, "mkey", "name", "interface") or target_id
            )
            after = await api_client.get_dns_server_detail(target_id, vdom=vdom)
            return self._format_write_result(
                "create DNS server",
                device_id,
                "dns_server",
                target_id,
                vdom=vdom,
                request_data=server_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create DNS server", device_id, e)

    async def update_dns_server(
        self,
        device_id: str,
        name: str,
        server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Update a DNS server interface."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, server_data=server_data)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_dns_server_detail(name, vdom=vdom)
            api_result = await api_client.update_dns_server(
                name, server_data, vdom=vdom
            )
            after = await api_client.get_dns_server_detail(name, vdom=vdom)
            return self._format_write_result(
                "update DNS server",
                device_id,
                "dns_server",
                name,
                vdom=vdom,
                request_data=server_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update DNS server", device_id, e)

    async def delete_dns_server(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Delete a DNS server interface."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_dns_server_detail(name, vdom=vdom)
            api_result = await api_client.delete_dns_server(name, vdom=vdom)
            return self._format_write_result(
                "delete DNS server",
                device_id,
                "dns_server",
                name,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete DNS server", device_id, e)

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

    async def create_dhcp_server(
        self,
        device_id: str,
        server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Create a DHCP server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(server_data=server_data)

            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_dhcp_server(server_data, vdom=vdom)
            target_id = self._target_id(
                server_data, "id", "q_origin_key", "name"
            ) or self._target_id(api_result, "mkey", "id", "q_origin_key", "name")
            after = (
                await api_client.get_dhcp_server_detail(target_id, vdom=vdom)
                if target_id
                else None
            )
            return self._format_write_result(
                "create DHCP server",
                device_id,
                "dhcp_server",
                target_id or "unknown",
                vdom=vdom,
                request_data=server_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create DHCP server", device_id, e)

    async def update_dhcp_server(
        self,
        device_id: str,
        server_id: str,
        server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Update a DHCP server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(server_id=server_id, server_data=server_data)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_dhcp_server_detail(server_id, vdom=vdom)
            api_result = await api_client.update_dhcp_server(
                server_id, server_data, vdom=vdom
            )
            after = await api_client.get_dhcp_server_detail(server_id, vdom=vdom)
            return self._format_write_result(
                "update DHCP server",
                device_id,
                "dhcp_server",
                server_id,
                vdom=vdom,
                request_data=server_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update DHCP server", device_id, e)

    async def delete_dhcp_server(
        self,
        device_id: str,
        server_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Delete a DHCP server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(server_id=server_id)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_dhcp_server_detail(server_id, vdom=vdom)
            api_result = await api_client.delete_dhcp_server(server_id, vdom=vdom)
            return self._format_write_result(
                "delete DHCP server",
                device_id,
                "dhcp_server",
                server_id,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete DHCP server", device_id, e)

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
