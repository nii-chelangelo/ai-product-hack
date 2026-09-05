import sys
from pathlib import Path

from loguru import logger


def configure(log_path: str) -> None:
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="{time:HH:mm:ss} | {level} | {message}")

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    logger.add(path, level="INFO", serialize=True)
