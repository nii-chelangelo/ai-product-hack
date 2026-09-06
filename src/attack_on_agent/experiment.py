from pathlib import Path
from typing import Any

import yaml


class ExperimentError(ValueError):
    """Raised when an experiment YAML is invalid."""


def load_experiment(path: Path) -> dict[str, Path | str | None]:
    try:
        data = yaml.safe_load(path.read_text())
    except FileNotFoundError as error:
        raise ExperimentError(f"Experiment file not found: {path}") from error
    except yaml.YAMLError as error:
        raise ExperimentError(f"Invalid experiment YAML: {error}") from error
    if not isinstance(data, dict):
        raise ExperimentError("Experiment must be a YAML mapping")
    run_id = data.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ExperimentError("'run_id' must be a non-empty string")
    base = path.parent
    result: dict[str, Path | str | None] = {"run_id": run_id}
    for name in ("target", "campaign"):
        value = data.get(name)
        if not isinstance(value, str) or not value:
            raise ExperimentError(f"'{name}' must be a non-empty path")
        result[name] = base / value
    judge = data.get("judge")
    if judge is not None and (not isinstance(judge, str) or not judge):
        raise ExperimentError("'judge' must be a path or null")
    result["judge"] = base / judge if judge else None
    users = data.get("users")
    if not isinstance(users, dict) or not isinstance(users.get("attacker"), str) or not users["attacker"]:
        raise ExperimentError("'users' must define a non-empty 'attacker'")
    victim = users.get("victim")
    if victim is not None and (not isinstance(victim, str) or not victim):
        raise ExperimentError("'users.victim' must be a non-empty string when present")
    result["users"] = users
    return result
