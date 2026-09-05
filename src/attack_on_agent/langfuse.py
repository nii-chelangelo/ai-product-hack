import base64
import json
import os
from time import sleep
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class LangfuseError(RuntimeError):
    """Raised when Langfuse evidence cannot be retrieved."""


def get_tool_calls(config: dict[str, Any], from_start_time: str, session_id: str) -> list[dict[str, Any]]:
    observations = _get_observations(config, from_start_time)
    return [
        {
            "trace_id": item.get("traceId"),
            "name": item.get("name"),
            "input": _json_value(item.get("input")),
            "output": _json_value(item.get("output")),
        }
        for item in observations
        if item.get("type") == "TOOL" and item.get("sessionId") == session_id
    ]


def get_trajectory_references(config: dict[str, Any], from_start_time: str, session_id: str) -> list[dict[str, str | None]]:
    """Return Langfuse references for a session without copying chat content into a run."""
    observations = _get_observations(config, from_start_time)
    references = [
        {
            "observation_id": item.get("id"),
            "trace_id": item.get("traceId"),
            "name": item.get("name"),
            "type": item.get("type"),
            "started_at": item.get("startTime"),
        }
        for item in observations
        if item.get("sessionId") == session_id and item.get("type") in {"AGENT", "CHAIN"}
    ]
    return sorted(references, key=lambda item: item["started_at"] or "")


def wait_for_trajectory_references(config: dict[str, Any], from_start_time: str, session_id: str) -> list[dict[str, str | None]]:
    for attempt in range(5):
        references = get_trajectory_references(config, from_start_time, session_id)
        if references or attempt == 4:
            return references
        sleep(1)
    return []


def get_session_io(config: dict[str, Any], from_start_time: str, session_id: str) -> list[dict[str, Any]]:
    return [
        {"input": _json_value(item.get("input")), "output": _json_value(item.get("output"))}
        for item in _get_observations(config, from_start_time)
        if item.get("sessionId") == session_id and item.get("type") == "AGENT"
    ]


def _get_observations(config: dict[str, Any], from_start_time: str) -> list[dict[str, Any]]:
    public_key = _credential(config["langfuse"]["public_key_env"])
    secret_key = _credential(config["langfuse"]["secret_key_env"])
    query = urlencode(
        {
            "fromStartTime": from_start_time,
            "toStartTime": datetime.now(UTC).isoformat(),
            "fields": "core,basic,io",
            "limit": "100",
        }
    )
    credentials = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
    request = Request(
        config["langfuse"]["base_url"] + "/api/public/v2/observations?" + query,
        headers={"Authorization": f"Basic {credentials}"},
    )
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read())
    except HTTPError as error:
        raise LangfuseError(f"Langfuse API returned HTTP {error.code}") from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise LangfuseError(f"Langfuse API request failed: {error}") from error

    observations = payload.get("data")
    if not isinstance(observations, list):
        raise LangfuseError("Langfuse API returned an unexpected response")
    return observations


def _credential(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise LangfuseError(f"Environment variable '{name}' must be set")
    return value


def _json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value
