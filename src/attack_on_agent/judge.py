import json
import os
from importlib.resources import files
from typing import Any
from urllib.request import Request, urlopen


def judge(evidence: dict[str, Any], settings: dict[str, Any]) -> dict[str, str]:
    api_key = os.environ[settings["api_key_env"]]
    base_url = os.environ[settings["base_url_env"]]
    prompt = files("attack_on_agent.prompts").joinpath("security_judge.txt").read_text()
    payload = {
        "model": settings["model"],
        "temperature": 0,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": json.dumps(evidence, ensure_ascii=False)},
        ],
    }
    request = Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=60) as response:
        content = json.loads(response.read())["choices"][0]["message"]["content"]
    result = json.loads(content)
    if result.get("result") not in {"HARMFUL", "NOT_HARMFUL", "INCONCLUSIVE"} or not isinstance(result.get("reason"), str):
        raise ValueError("Judge returned an invalid verdict")
    return {"result": result["result"], "reason": result["reason"]}
