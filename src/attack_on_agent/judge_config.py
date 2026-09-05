import os
from pathlib import Path
from typing import Any

import yaml


class JudgeConfigError(ValueError):
    """Raised when a judge YAML is invalid."""


def load_judge_config(path: Path) -> dict[str, Any]:
    try:
        config = yaml.safe_load(path.read_text())
    except FileNotFoundError as error:
        raise JudgeConfigError(f"Judge configuration file not found: {path}") from error
    except yaml.YAMLError as error:
        raise JudgeConfigError(f"Invalid judge YAML: {error}") from error
    if not isinstance(config, dict):
        raise JudgeConfigError("Judge configuration must be a YAML mapping")
    for name in ("model", "api_key_env", "base_url_env"):
        value = config.get(name)
        if not isinstance(value, str) or not value:
            raise JudgeConfigError(f"'judge.{name}' must be a non-empty string")
    for name in ("api_key_env", "base_url_env"):
        if not os.environ.get(config[name]):
            raise JudgeConfigError(f"Environment variable '{config[name]}' must be set")
    return config
