import os
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when the local YAML configuration is invalid."""


def load_config(path: Path) -> dict[str, Any]:
    data = _load_yaml_mapping(path)

    target = _section(data, "target")
    langfuse = _section(data, "langfuse")
    logging = _section(data, "logging")

    _required_url(target, "base_url", "target")
    api_key_env = _required_value(target, "api_key_env", "target")
    if not os.environ.get(api_key_env):
        raise ConfigError(f"Environment variable '{api_key_env}' must be set")
    auth_mode = _required_value(target, "auth_mode", "target")
    if auth_mode not in {"vulnerable", "protected"}:
        raise ConfigError("'target.auth_mode' must be 'vulnerable' or 'protected'")
    _required_url(langfuse, "base_url", "langfuse")
    _required_value(logging, "path", "logging")
    return data


def load_campaign(path: Path) -> dict[str, Any]:
    data = _load_yaml_mapping(path)
    evaluation = _section(data, "evaluation")
    _required_value(evaluation, "expected_marker", "evaluation")
    return data


def load_impact_campaign(path: Path) -> dict[str, Any]:
    data = _load_yaml_mapping(path)
    impact = _section(data, "impact")
    tool = _section(impact, "tool")
    _required_value(impact, "expected_marker", "impact")
    denied_markers = impact.get("denied_markers")
    if not isinstance(denied_markers, list) or not all(isinstance(marker, str) and marker for marker in denied_markers):
        raise ConfigError("'impact.denied_markers' must be a non-empty list of strings")
    _required_value(tool, "name", "impact.tool")
    _required_value(tool, "expected_cus", "impact.tool")
    return data


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text())
    except FileNotFoundError as error:
        raise ConfigError(f"Configuration file not found: {path}") from error
    except yaml.YAMLError as error:
        raise ConfigError(f"Invalid YAML in {path}: {error}") from error

    if not isinstance(data, dict):
        raise ConfigError("Configuration must be a YAML mapping")
    return data


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    section = data.get(name)
    if not isinstance(section, dict):
        raise ConfigError(f"'{name}' must be a YAML mapping")
    return section


def _required_value(section: dict[str, Any], name: str, section_name: str) -> str:
    value = section.get(name)
    if not isinstance(value, str) or not value.strip() or value.startswith("replace-with-"):
        raise ConfigError(f"'{section_name}.{name}' must be set in the local configuration")
    return value


def _required_url(section: dict[str, Any], name: str, section_name: str) -> str:
    value = _required_value(section, name, section_name)
    if not value.startswith(("http://", "https://")):
        raise ConfigError(f"'{section_name}.{name}' must start with http:// or https://")
    return value.rstrip("/")
