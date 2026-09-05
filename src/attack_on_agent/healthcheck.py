import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from loguru import logger


def check_services(config: dict[str, Any]) -> bool:
    target_url = config["target"]["base_url"].rstrip("/") + "/healthz"
    langfuse_url = config["langfuse"]["base_url"].rstrip("/") + "/"

    target_ready = _check_target(target_url)
    langfuse_ready = _check_url("langfuse", langfuse_url)
    return target_ready and langfuse_ready


def _check_target(url: str) -> bool:
    try:
        with urlopen(url, timeout=5) as response:
            payload = json.loads(response.read())
            if response.status == 200 and payload == {"status": "ok"}:
                logger.info("Target API is ready")
                return True
            logger.error("Target API returned an unexpected health response")
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
        logger.error("Target API is unavailable: {}", error)
    return False


def _check_url(service: str, url: str) -> bool:
    try:
        with urlopen(url, timeout=5) as response:
            logger.info("{} is reachable with HTTP {}", service, response.status)
            return 200 <= response.status < 400
    except (HTTPError, URLError, TimeoutError) as error:
        logger.error("{} is unavailable: {}", service, error)
        return False
