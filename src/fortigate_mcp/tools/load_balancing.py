"""Load-balancing virtual server management tools for FortiGate MCP."""
from typing import Any, Dict, List, Optional

from mcp.types import TextContent as Content

from .base import FortiGateTool


class LoadBalancingTools(FortiGateTool):
    """Tools for FortiGate load-balancing virtual servers and health checks."""

    async def list_virtual_servers(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List load-balancing virtual servers."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_virtual_servers(vdom=vdom)
            return self._format_response(data, "virtual_servers")
        except Exception as e:
            return self._handle_error("list virtual servers", device_id, e)

    async def get_virtual_server_detail(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Get a load-balancing virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_virtual_server_detail(name, vdom=vdom)
            return self._format_response(data, "virtual_server_detail")
        except Exception as e:
            return self._handle_error("get virtual server detail", device_id, e)

    async def create_virtual_server(
        self,
        device_id: str,
        virtual_server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Create a load-balancing virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(virtual_server_data=virtual_server_data)
            name = str(virtual_server_data.get("name", ""))
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_virtual_server(virtual_server_data, vdom=vdom)
            after = await api_client.get_virtual_server_detail(name, vdom=vdom)
            return self._format_write_result(
                "create virtual server",
                device_id,
                "virtual_server",
                name,
                vdom=vdom,
                request_data=virtual_server_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create virtual server", device_id, e)

    async def update_virtual_server(
        self,
        device_id: str,
        name: str,
        virtual_server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Update a load-balancing virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, virtual_server_data=virtual_server_data)
            api_client = self._get_device_api(device_id)
            before = await api_client.get_virtual_server_detail(name, vdom=vdom)
            api_result = await api_client.update_virtual_server(name, virtual_server_data, vdom=vdom)
            after = await api_client.get_virtual_server_detail(name, vdom=vdom)
            return self._format_write_result(
                "update virtual server",
                device_id,
                "virtual_server",
                name,
                vdom=vdom,
                request_data=virtual_server_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update virtual server", device_id, e)

    async def delete_virtual_server(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Delete a load-balancing virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            before = await api_client.get_virtual_server_detail(name, vdom=vdom)
            api_result = await api_client.delete_virtual_server(name, vdom=vdom)
            return self._format_write_result(
                "delete virtual server",
                device_id,
                "virtual_server",
                name,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete virtual server", device_id, e)

    async def get_virtual_server_status(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Get virtual server and member health status."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            data = await api_client.get_virtual_server_status(name, vdom=vdom)
            return self._format_response(data, "virtual_server_status")
        except Exception as e:
            return self._handle_error("get virtual server status", device_id, e)

    async def list_real_servers(
        self,
        device_id: str,
        virtual_server: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """List real server members on a virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(virtual_server=virtual_server)
            detail = await self._get_device_api(device_id).get_virtual_server_detail(
                virtual_server,
                vdom=vdom,
            )
            return self._format_response(self._real_servers_response(detail), "real_servers")
        except Exception as e:
            return self._handle_error("list real servers", device_id, e)

    async def add_real_server(
        self,
        device_id: str,
        virtual_server: str,
        real_server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Add a real server member to a virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(
                virtual_server=virtual_server,
                real_server_data=real_server_data,
            )
            api_client = self._get_device_api(device_id)
            before = await api_client.get_virtual_server_detail(virtual_server, vdom=vdom)
            vip = self._first_result(before)
            realservers = list(vip.get("realservers") or [])
            member_id = self._member_id(real_server_data)
            if member_id is not None and any(self._member_id(item) == member_id for item in realservers):
                raise ValueError(f"Real server member '{member_id}' already exists")

            realservers.append(real_server_data)
            api_result = await api_client.update_virtual_server(
                virtual_server,
                {"realservers": realservers},
                vdom=vdom,
            )
            after = await api_client.get_virtual_server_detail(virtual_server, vdom=vdom)
            return self._format_write_result(
                "add real server",
                device_id,
                "real_server",
                str(member_id or real_server_data.get("ip") or "new"),
                vdom=vdom,
                request_data=real_server_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("add real server", device_id, e)

    async def update_real_server(
        self,
        device_id: str,
        virtual_server: str,
        member_id: str,
        real_server_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Update a real server member on a virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(
                virtual_server=virtual_server,
                member_id=member_id,
                real_server_data=real_server_data,
            )
            api_client = self._get_device_api(device_id)
            before = await api_client.get_virtual_server_detail(virtual_server, vdom=vdom)
            realservers = self._replace_real_server(before, member_id, real_server_data)
            api_result = await api_client.update_virtual_server(
                virtual_server,
                {"realservers": realservers},
                vdom=vdom,
            )
            after = await api_client.get_virtual_server_detail(virtual_server, vdom=vdom)
            return self._format_write_result(
                "update real server",
                device_id,
                "real_server",
                member_id,
                vdom=vdom,
                request_data=real_server_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update real server", device_id, e)

    async def delete_real_server(
        self,
        device_id: str,
        virtual_server: str,
        member_id: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Delete a real server member from a virtual server."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(virtual_server=virtual_server, member_id=member_id)
            api_client = self._get_device_api(device_id)
            before = await api_client.get_virtual_server_detail(virtual_server, vdom=vdom)
            realservers = self._remove_real_server(before, member_id)
            api_result = await api_client.update_virtual_server(
                virtual_server,
                {"realservers": realservers},
                vdom=vdom,
            )
            after = await api_client.get_virtual_server_detail(virtual_server, vdom=vdom)
            return self._format_write_result(
                "delete real server",
                device_id,
                "real_server",
                member_id,
                vdom=vdom,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete real server", device_id, e)

    async def list_health_checks(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List load-balance health checks."""
        try:
            self._validate_device_exists(device_id)
            data = await self._get_device_api(device_id).get_load_balance_health_checks(vdom=vdom)
            return self._format_response(data, "load_balance_health_checks")
        except Exception as e:
            return self._handle_error("list load-balance health checks", device_id, e)

    async def get_health_check_detail(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Get a load-balance health check."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            data = await self._get_device_api(device_id).get_load_balance_health_check_detail(
                name,
                vdom=vdom,
            )
            return self._format_response(data, "load_balance_health_check_detail")
        except Exception as e:
            return self._handle_error("get load-balance health check", device_id, e)

    async def create_health_check(
        self,
        device_id: str,
        monitor_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Create a load-balance health check."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(monitor_data=monitor_data)
            name = str(monitor_data.get("name", ""))
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_load_balance_health_check(monitor_data, vdom=vdom)
            after = await api_client.get_load_balance_health_check_detail(name, vdom=vdom)
            return self._format_write_result(
                "create load-balance health check",
                device_id,
                "load_balance_health_check",
                name,
                vdom=vdom,
                request_data=monitor_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create load-balance health check", device_id, e)

    async def update_health_check(
        self,
        device_id: str,
        name: str,
        monitor_data: Dict[str, Any],
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Update a load-balance health check."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, monitor_data=monitor_data)
            api_client = self._get_device_api(device_id)
            before = await api_client.get_load_balance_health_check_detail(name, vdom=vdom)
            api_result = await api_client.update_load_balance_health_check(name, monitor_data, vdom=vdom)
            after = await api_client.get_load_balance_health_check_detail(name, vdom=vdom)
            return self._format_write_result(
                "update load-balance health check",
                device_id,
                "load_balance_health_check",
                name,
                vdom=vdom,
                request_data=monitor_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update load-balance health check", device_id, e)

    async def delete_health_check(
        self,
        device_id: str,
        name: str,
        vdom: Optional[str] = None,
    ) -> List[Content]:
        """Delete a load-balance health check."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)
            api_client = self._get_device_api(device_id)
            before = await api_client.get_load_balance_health_check_detail(name, vdom=vdom)
            api_result = await api_client.delete_load_balance_health_check(name, vdom=vdom)
            return self._format_write_result(
                "delete load-balance health check",
                device_id,
                "load_balance_health_check",
                name,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete load-balance health check", device_id, e)

    @staticmethod
    def _first_result(response: Dict[str, Any]) -> Dict[str, Any]:
        results = response.get("results", {})
        if isinstance(results, list):
            return results[0] if results else {}
        return results if isinstance(results, dict) else {}

    @classmethod
    def _real_servers_response(cls, virtual_server_response: Dict[str, Any]) -> Dict[str, Any]:
        vip = cls._first_result(virtual_server_response)
        return {
            "status": virtual_server_response.get("status", "success"),
            "vdom": virtual_server_response.get("vdom"),
            "virtual_server": vip.get("name"),
            "results": vip.get("realservers") or [],
            "health_metadata": {
                "monitor": vip.get("monitor"),
                "server_type": vip.get("server-type"),
                "load_balance_method": vip.get("ldb-method"),
                "runtime_status_available": virtual_server_response.get(
                    "runtime_status_available",
                    False,
                ),
            },
        }

    @staticmethod
    def _member_id(member: Dict[str, Any]) -> Optional[str]:
        for key in ("id", "seq", "name", "ip"):
            value = member.get(key)
            if value is not None:
                return str(value)
        return None

    @classmethod
    def _replace_real_server(
        cls,
        virtual_server_response: Dict[str, Any],
        member_id: str,
        real_server_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        vip = cls._first_result(virtual_server_response)
        realservers = list(vip.get("realservers") or [])
        for index, member in enumerate(realservers):
            if cls._member_id(member) == str(member_id):
                updated = dict(member)
                updated.update(real_server_data)
                realservers[index] = updated
                return realservers
        raise ValueError(f"Real server member '{member_id}' not found")

    @classmethod
    def _remove_real_server(
        cls,
        virtual_server_response: Dict[str, Any],
        member_id: str,
    ) -> List[Dict[str, Any]]:
        vip = cls._first_result(virtual_server_response)
        realservers = list(vip.get("realservers") or [])
        filtered = [member for member in realservers if cls._member_id(member) != str(member_id)]
        if len(filtered) == len(realservers):
            raise ValueError(f"Real server member '{member_id}' not found")
        return filtered
