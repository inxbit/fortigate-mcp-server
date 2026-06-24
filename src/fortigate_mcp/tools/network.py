"""Network object management tools for FortiGate MCP."""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool

class NetworkTools(FortiGateTool):
    """Tools for FortiGate network object management."""

    @staticmethod
    def _build_service_payload(name: str, service_type: str, protocol: str,
                               port: Optional[str] = None) -> Dict[str, Any]:
        """Build FortiOS firewall.service/custom payload from tool parameters."""
        service_type_upper = service_type.upper()
        protocol_upper = protocol.upper()

        if protocol_upper in {"TCP", "UDP", "SCTP", "TCP/UDP/SCTP"}:
            service_data: Dict[str, Any] = {
                "name": name,
                "protocol": "TCP/UDP/SCTP",
            }
            if port:
                if protocol_upper in {"TCP", "UDP", "SCTP"}:
                    port_protocol = protocol_upper
                elif service_type_upper in {"TCP", "UDP", "SCTP"}:
                    port_protocol = service_type_upper
                else:
                    port_protocol = "TCP"
                service_data[f"{port_protocol.lower()}-portrange"] = port
            return service_data

        return {
            "name": name,
            "protocol": protocol,
        }

    async def list_address_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List address objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            addresses_data = await api_client.get_address_objects(vdom=vdom)
            return self._format_response(addresses_data, "address_objects")
        except Exception as e:
            return self._handle_error("list address objects", device_id, e)

    async def create_address_object(self, device_id: str, name: str, address_type: str, address: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Create address object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, address_type=address_type, address=address)

            address_data = {
                "name": name,
                "type": address_type,
                "subnet": address
            }

            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_address_object(address_data, vdom=vdom)
            after = await api_client.get_address_object_detail(name, vdom=vdom)
            return self._format_write_result(
                "create address object",
                device_id,
                "address_object",
                name,
                vdom=vdom,
                request_data=address_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create address object", device_id, e)

    async def update_address_object(self, device_id: str, name: str, address_data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        """Update address object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, address_data=address_data)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_address_object_detail(name, vdom=vdom)
            api_result = await api_client.update_address_object(name, address_data, vdom=vdom)
            after = await api_client.get_address_object_detail(name, vdom=vdom)
            return self._format_write_result(
                "update address object",
                device_id,
                "address_object",
                name,
                vdom=vdom,
                request_data=address_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update address object", device_id, e)

    async def delete_address_object(self, device_id: str, name: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Delete address object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_address_object_detail(name, vdom=vdom)
            api_result = await api_client.delete_address_object(name, vdom=vdom)
            return self._format_write_result(
                "delete address object",
                device_id,
                "address_object",
                name,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete address object", device_id, e)

    async def list_service_objects(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List service objects."""
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)
            services_data = await api_client.get_service_objects(vdom=vdom)
            return self._format_response(services_data, "service_objects")
        except Exception as e:
            return self._handle_error("list service objects", device_id, e)

    async def create_service_object(self, device_id: str, name: str, service_type: str, protocol: str,
                             port: Optional[str] = None, vdom: Optional[str] = None) -> List[Content]:
        """Create service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, service_type=service_type, protocol=protocol)

            service_data = self._build_service_payload(name, service_type, protocol, port)

            api_client = self._get_device_api(device_id)
            api_result = await api_client.create_service_object(service_data, vdom=vdom)
            after = await api_client.get_service_object_detail(name, vdom=vdom)
            return self._format_write_result(
                "create service object",
                device_id,
                "service_object",
                name,
                vdom=vdom,
                request_data=service_data,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("create service object", device_id, e)

    async def update_service_object(self, device_id: str, name: str, service_data: Dict[str, Any],
                             vdom: Optional[str] = None) -> List[Content]:
        """Update service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name, service_data=service_data)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_service_object_detail(name, vdom=vdom)
            api_result = await api_client.update_service_object(name, service_data, vdom=vdom)
            after = await api_client.get_service_object_detail(name, vdom=vdom)
            return self._format_write_result(
                "update service object",
                device_id,
                "service_object",
                name,
                vdom=vdom,
                request_data=service_data,
                before=before,
                after=after,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("update service object", device_id, e)

    async def delete_service_object(self, device_id: str, name: str,
                             vdom: Optional[str] = None) -> List[Content]:
        """Delete service object."""
        try:
            self._validate_device_exists(device_id)
            self._validate_required_params(name=name)

            api_client = self._get_device_api(device_id)
            before = await api_client.get_service_object_detail(name, vdom=vdom)
            api_result = await api_client.delete_service_object(name, vdom=vdom)
            return self._format_write_result(
                "delete service object",
                device_id,
                "service_object",
                name,
                vdom=vdom,
                before=before,
                api_result=api_result,
            )
        except Exception as e:
            return self._handle_error("delete service object", device_id, e)
