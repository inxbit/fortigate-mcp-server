"""
Configuration loading utilities for the FortiGate MCP server.

This module handles loading and validation of server configuration:
- JSON configuration file loading
- Environment variable handling
- Configuration validation using Pydantic models
- Error handling for invalid configurations

The module ensures that all required configuration is present
and valid before the server starts operation.
"""

import json
import os
from pathlib import Path
from typing import Optional

from .models import Config


def _resolve_config_path(config_path: str) -> Path:
    """Resolve and validate a FortiGate MCP JSON config path."""
    config_file = Path(config_path).expanduser()
    if config_file.suffix.lower() != ".json":
        raise ValueError("Configuration file must use a .json extension")
    if config_file.is_symlink():
        raise ValueError("Configuration file must not be a symbolic link")

    try:
        resolved_file = config_file.resolve(strict=True)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    if resolved_file.suffix.lower() != ".json":
        raise ValueError("Configuration file must resolve to a .json file")
    if not resolved_file.is_file():
        raise ValueError(f"Configuration path is not a regular file: {config_path}")
    return resolved_file


def load_config(config_path: Optional[str] = None) -> Config:
    """Load and validate configuration from JSON file.

    Performs the following steps:
    1. Determines config path from parameter or environment variable
    2. Loads JSON configuration file
    3. Validates required fields are present
    4. Converts to typed Config object using Pydantic

    Configuration must include:
    - FortiGate device settings (host, port, authentication, etc.)
    - Server configuration (host, port, name)
    - Logging configuration
    - Optional: authentication, rate limiting settings

    Args:
        config_path: Path to the JSON configuration file
                    If not provided, uses FORTIGATE_MCP_CONFIG environment variable

    Returns:
        Config object containing validated configuration:
        {
            "server": {
                "host": "127.0.0.1",
                "port": 8814,
                ...
            },
            "fortigate": {
                "devices": {
                    "default": {
                        "host": "192.168.1.1",
                        "api_token": "...",
                        ...
                    }
                }
            },
            "logging": {
                "level": "INFO",
                ...
            },
            ...
        }

    Raises:
        ValueError: If:
                 - Config path is not provided and environment variable not set
                 - JSON is invalid
                 - Required fields are missing
                 - Field values are invalid
        FileNotFoundError: If config file doesn't exist
    """
    # Determine config path
    if not config_path:
        config_path = os.getenv("FORTIGATE_MCP_CONFIG")

    if not config_path:
        raise ValueError(
            "Configuration path must be provided either as parameter or FORTIGATE_MCP_CONFIG environment variable"
        )

    config_file = _resolve_config_path(config_path)

    # Load and parse JSON configuration file
    try:
        config_data = json.loads(config_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file: {e}")
    except Exception as e:
        raise ValueError(f"Failed to load config file: {e}")

    # Validate configuration structure
    if not isinstance(config_data, dict):
        raise ValueError("Configuration must be a JSON object")

    # Ensure required sections exist
    if "fortigate" not in config_data:
        raise ValueError("Configuration must contain 'fortigate' section")

    if "devices" not in config_data.get("fortigate", {}):
        raise ValueError("FortiGate configuration must contain 'devices' section")

    devices = config_data["fortigate"]["devices"]
    if not isinstance(devices, dict) or len(devices) == 0:
        raise ValueError("At least one FortiGate device must be configured")

    # Validate each device has required fields
    for device_id, device_config in devices.items():
        if not isinstance(device_config, dict):
            raise ValueError(f"Device '{device_id}' configuration must be an object")

        if not device_config.get("host"):
            raise ValueError(f"Device '{device_id}' must have a 'host' field")

        # Ensure authentication is configured
        has_token = bool(device_config.get("api_token"))
        has_credentials = bool(
            device_config.get("username") and device_config.get("password")
        )

        if not (has_token or has_credentials):
            raise ValueError(
                f"Device '{device_id}' must have either 'api_token' or both 'username' and 'password'"
            )

    # Create and validate Config object
    try:
        config = Config(**config_data)
    except Exception as e:
        raise ValueError(f"Configuration validation failed: {e}")

    return config


def create_example_config() -> dict:
    """Create an example configuration dictionary.

    Returns:
        Dictionary containing example configuration that can be
        saved as a JSON file for users to customize.
    """
    return {
        "server": {
            "host": "127.0.0.1",
            "port": 8814,
            "name": "fortigate-mcp-server",
            "version": "1.0.0",
        },
        "fortigate": {
            "devices": {
                "default": {
                    "host": "192.168.1.1",
                    "port": 443,
                    "username": "admin",
                    "vdom": "root",
                    "verify_ssl": True,
                    "ca_bundle": None,
                    "timeout": 30,
                },
                "backup": {
                    "host": "192.168.1.2",
                    "port": 443,
                    "vdom": "root",
                    "verify_ssl": True,
                    "ca_bundle": None,
                    "timeout": 30,
                },
            }
        },
        "auth": {
            "require_auth": False,
            "api_tokens": [],
            "allowed_hosts": [],
            "allowed_origins": [],
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": None,
            "console": True,
        },
        "rate_limiting": {
            "enabled": True,
            "max_requests_per_minute": 60,
            "burst_size": 10,
        },
    }
