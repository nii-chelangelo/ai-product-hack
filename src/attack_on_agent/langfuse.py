import base64
import json
import os
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


def find_markers_in_session(
    config: dict[str, Any], from_start_time: str, session_id: str, markers: list[str]
) -> dict[str, Any]:
    """Find markers in Langfuse I/O without storing the conversation in a run."""
    matches: list[dict[str, Any]] = []
    observations = 0
    for item in _get_observations(config, from_start_time):
        if item.get("sessionId") != session_id or item.get("type") != "AGENT":
            continue
        observations += 1
        text = json.dumps({"input": _json_value(item.get("input")), "output": _json_value(item.get("output"))}, ensure_ascii=False)
        found = [marker for marker in markers if marker in text]
        if found:
            matches.append({"observation_id": item.get("id"), "trace_id": item.get("traceId"), "markers": found})
    return {"observations": observations, "matches": matches}


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
