import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class TargetError(RuntimeError):
    """Raised when the target API cannot complete a request."""


def send_chat(config: dict[str, Any], message: str, session_id: str) -> str:
    target = config["target"]
    api_key = _api_key(config)
    payload = {
        "messages": [{"role": "user", "content": message}],
        "session_id": session_id,
        "auth_mode": target["auth_mode"],
        "stream": False,
    }
    request = Request(
        target["base_url"].rstrip("/") + target["chat_path"],
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=120) as response:
            body = json.loads(response.read())
    except HTTPError as error:
        raise TargetError(f"Target API returned HTTP {error.code}") from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise TargetError(f"Target API request failed: {error}") from error

    try:
        return body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as error:
        raise TargetError("Target API returned an unexpected chat response") from error


def finalize_session(config: dict[str, Any], session_id: str) -> tuple[int, int]:
    target = config["target"]
    api_key = _api_key(config)
    request = Request(
        target["base_url"].rstrip("/") + _session_path(config["memory"]["finalize_path"], session_id),
        headers={"Authorization": f"Bearer {api_key}"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=120) as response:
            body = json.loads(response.read())
    except HTTPError as error:
        raise TargetError(f"Target API returned HTTP {error.code}") from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise TargetError(f"Target API request failed: {error}") from error

    try:
        return len(body["episodes"]), len(body["facts"])
    except (KeyError, TypeError) as error:
        raise TargetError("Target API returned an unexpected finalize response") from error


def get_memory_snapshot(config: dict[str, Any], session_id: str) -> dict[str, Any]:
    target = config["target"]
    api_key = _api_key(config)
    request = Request(
        target["base_url"].rstrip("/") + _session_path(config["memory"]["snapshot_path"], session_id),
        headers={"Authorization": f"Bearer {api_key}"},
        method="GET",
    )

    try:
        with urlopen(request, timeout=30) as response:
            body = json.loads(response.read())
    except HTTPError as error:
        raise TargetError(f"Target API returned HTTP {error.code}") from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise TargetError(f"Target API request failed: {error}") from error

    if not isinstance(body, dict):
        raise TargetError("Target API returned an unexpected memory snapshot")
    return body


def _api_key(config: dict[str, Any]) -> str:
    return os.environ[config["users"]["user_1001"]["api_key_env"]]


def _session_path(template: str, session_id: str) -> str:
    return template.format(session_id=session_id)
