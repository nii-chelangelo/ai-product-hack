from pathlib import Path
import re
from typing import Any

import yaml


class CampaignError(ValueError):
    """Raised when an attack campaign YAML is invalid."""


def load_campaign(path: Path) -> dict[str, Any]:
    try:
        campaign = yaml.safe_load(path.read_text())
    except FileNotFoundError as error:
        raise CampaignError(f"Campaign file not found: {path}") from error
    except yaml.YAMLError as error:
        raise CampaignError(f"Invalid campaign YAML: {error}") from error

    if not isinstance(campaign, dict):
        raise CampaignError("Campaign must be a YAML mapping")
    _validate_llamator(campaign)
    tests = campaign.get("tests")
    if not isinstance(tests, list) or not tests:
        raise CampaignError("'tests' must be a non-empty YAML list")
    test_ids: set[str] = set()
    for test in tests:
        _validate_test(test)
        if test["id"] in test_ids:
            raise CampaignError("Each LLAMATOR test ID must be unique within a campaign")
        test_ids.add(test["id"])
    return campaign


def _validate_llamator(campaign: dict[str, Any]) -> None:
    source = campaign.get("llamator")
    if not isinstance(source, dict):
        raise CampaignError("'llamator' must be a YAML mapping")
    _validate_model(source, "attacker", required=True)
    # Some LLAMATOR attacks score their own attempts and are skipped without a judge model.
    _validate_model(source, "judge", required=False)


def _validate_model(source: dict[str, Any], role: str, *, required: bool) -> None:
    settings = source.get(role)
    if settings is None and not required:
        return
    if not isinstance(settings, dict):
        raise CampaignError(f"'llamator.{role}' must be a YAML mapping")
    for name in ("model", "api_key_env", "base_url_env"):
        value = settings.get(name)
        if not isinstance(value, str) or not value:
            raise CampaignError(f"'llamator.{role}.{name}' must be a non-empty string")


def _validate_test(test: Any) -> None:
    if not isinstance(test, dict):
        raise CampaignError("Each test must be a YAML mapping")
    test_id = _string(test, "id", "test")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", test_id):
        raise CampaignError("test.id must contain only letters, numbers, underscores, or hyphens")
    params = test.get("params", {})
    if not isinstance(params, dict):
        raise CampaignError("'test.params' must be a YAML mapping")


def _string(data: dict[str, Any], name: str, scope: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise CampaignError(f"'{scope}.{name}' must be a non-empty string")
    return value
