"""Virtual IP management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class VirtualIPTools(FortiGateTool):
    """Tools for FortiGate Virtual IP management."""

    @staticmethod
    def _mappedip_payload(mappedip: str) -> List[Dict[str, str]]:
        """Build FortiOS VIP mappedip payload from a single IP or range."""
        return [{"range": mappedip}]

    async def list_virtual_ips(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List virtual IPs."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            vips_data = await api_client.get_virtual_ips(vdom=vdom)
            return self._format_response(vips_data, "virtual_ips")
        except Exception as e:
            return self._handle_error("list virtual IPs", device_id, e)

    async def create_virtual_ip(self, device_id: str, name: str, extip: str, mappedip: str,
                         extintf: str, portforward: str = "disable",
                         protocol: str = "tcp", extport: Optional[str] = None,
                         mappedport: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Create virtual IP."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, extip=extip, mappedip=mappedip, extintf=extintf)

            vip_data = {
                "name": name,
                "type": "static-nat",
                "extip": extip,
                "mappedip": self._mappedip_payload(mappedip),
                "extintf": extintf,
                "portforward": portforward
            }

            if protocol:
                vip_data["protocol"] = protocol

            if extport:
                vip_data["extport"] = extport

            if mappedport:
                vip_data["mappedport"] = mappedport

            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_virtual_ip(vip_data, vdom=vdom)
            after = await api_client.get_virtual_ip_detail(name, vdom=vdom)
            return self._format_write_result(
                "create virtual IP",
                device_id,
                "virtual_ip",
                name,
                vdom=vdom,
                request_data=vip_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create virtual IP", device_id, e)

    async def update_virtual_ip(self, device_id: str, name: str, vip_data: Dict[str, Any],
                         vdom: Optional[str] = None) -> List[Content]:
        """Update virtual IP."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_virtual_ip_detail(name, vdom=vdom)
            api_result = await api_client.update_virtual_ip(name, vip_data, vdom=vdom)
            after = await api_client.get_virtual_ip_detail(name, vdom=vdom)
            return self._format_write_result(
                "update virtual IP",
                device_id,
                "virtual_ip",
                name,
                vdom=vdom,
                request_data=vip_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update virtual IP", device_id, e)

    async def get_virtual_ip_detail(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Get virtual IP detail."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            vip_data = await api_client.get_virtual_ip_detail(name, vdom=vdom)
            return self._format_response(vip_data, "virtual_ip_detail")
        except Exception as e:
            return self._handle_error("get virtual IP detail", device_id, e)

    async def delete_virtual_ip(self, device_id: str, name: str, vdom: Optional[str] = None) -> List[Content]:
        """Delete virtual IP."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_virtual_ip_detail(name, vdom=vdom)
            api_result = await api_client.delete_virtual_ip(name, vdom=vdom)
            return self._format_write_result(
                "delete virtual IP",
                device_id,
                "virtual_ip",
                name,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete virtual IP", device_id, e)
