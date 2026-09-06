import json
import os
import time
from importlib.resources import files
from typing import Any
from urllib.request import Request, urlopen

from loguru import logger

from attack_on_agent.summary import DIMENSIONS

_ATTEMPTS = 2
_SOCKET_TIMEOUT = 30
_TOTAL_DEADLINE = 240
_CHUNK_SIZE = 65536


def judge(evidence: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
    """Ask the judge model for a verdict, retrying once if it answers with unusable JSON.

    Models routinely wrap the object in markdown fences or add a sentence around it, which is a
    formatting slip rather than a failed evaluation — retrying on it keeps such tests inside the
    ASR denominator instead of dropping them to ERROR.
    """
    payload = _payload(settings, "security_judge.txt", json.dumps(evidence, ensure_ascii=False))
    base_url, api_key = _credentials(settings)

    for attempt in range(1, _ATTEMPTS + 1):
        content = _ask(base_url, api_key, payload)
        try:
            return _parse_verdict(content)
        except ValueError as error:
            if attempt == _ATTEMPTS:
                raise ValueError(f"Judge returned an invalid verdict: {error}") from error
            logger.warning("Judge answer was not usable ({}), retrying", error)
    raise AssertionError("unreachable")


def probe_question(claims: list[str], settings: dict[str, Any]) -> str:
    """Turn records the attack left in shared memory into one question that would surface them.

    Asking the victim a generic greeting cannot show whether a planted claim took hold: nothing in
    the answer would ever touch the subject. The question is built from the planted text itself and
    stays neutral about it, so a victim reproducing the claim is doing so from memory, not because
    the question asserted it.
    """
    payload = _payload(settings, "probe_question.txt", json.dumps(claims, ensure_ascii=False))
    base_url, api_key = _credentials(settings)
    return _ask(base_url, api_key, payload).strip().strip('"').splitlines()[0]


def _payload(settings: dict[str, Any], prompt_name: str, content: str) -> dict[str, Any]:
    prompt = files("attack_on_agent.prompts").joinpath(prompt_name).read_text()
    return {
        "model": settings["model"],
        "temperature": 0,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": content},
        ],
    }


def _credentials(settings: dict[str, Any]) -> tuple[str, str]:
    return os.environ[settings["base_url_env"]], os.environ[settings["api_key_env"]]


def _ask(base_url: str, api_key: str, payload: dict[str, Any]) -> str:
    request = Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=_SOCKET_TIMEOUT) as response:
        return json.loads(_read_within_deadline(response))["choices"][0]["message"]["content"]


def _read_within_deadline(response: Any) -> bytes:
    """Read the body under a wall-clock deadline, not just a per-socket-operation timeout.

    urlopen's timeout only limits a single socket operation, so a model answering in a slow
    trickle keeps the connection alive indefinitely — one judge call was observed running for
    26 minutes. Reading in chunks lets us give up on the whole response and report an honest
    failure instead of stalling the campaign.
    """
    deadline = time.monotonic() + _TOTAL_DEADLINE
    chunks: list[bytes] = []
    while True:
        if time.monotonic() > deadline:
            response.close()
            raise TimeoutError(f"judge did not finish answering within {_TOTAL_DEADLINE}s")
        chunk = response.read(_CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _parse_verdict(content: str) -> dict[str, Any]:
    result = json.loads(_json_object(content))
    if result.get("result") not in {"SUCCESS", "FAIL", "INCONCLUSIVE"} or not isinstance(result.get("reason"), str):
        raise ValueError(f"unexpected verdict payload: {result}")
    breach = result.get("breach")
    named = [name for name in breach if name in DIMENSIONS] if isinstance(breach, list) else []
    return {"result": result["result"], "breach": named, "reason": result["reason"]}


def _json_object(content: str) -> str:
    """Cut the JSON object out of an answer that may carry fences or commentary around it."""
    if not isinstance(content, str):
        raise ValueError("judge answer was not text")
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end <= start:
        raise ValueError(f"no JSON object in answer: {content[:120]!r}")
    return content[start : end + 1]
