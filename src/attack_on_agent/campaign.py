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
    _string(campaign, "id", "campaign")
    _string(campaign, "title", "campaign")
    attacks = campaign.get("attacks")
    if not isinstance(attacks, list) or not attacks:
        raise CampaignError("'attacks' must be a non-empty YAML list")
    for attack in attacks:
        _validate_attack(attack)
    return campaign


def _validate_attack(attack: Any) -> None:
    if not isinstance(attack, dict):
        raise CampaignError("Each attack must be a YAML mapping")
    attack_id = _string(attack, "id", "attack")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", attack_id):
        raise CampaignError("attack.id must contain only letters, numbers, underscores, or hyphens")
    _validate_phase(attack, "delivery")
    _validate_phase(attack, "activation")
    markers = attack.get("markers")
    if not isinstance(markers, list) or not markers or not all(isinstance(marker, str) and marker for marker in markers):
        raise CampaignError(f"attack '{attack['id']}' must have a non-empty 'markers' list")
    evaluation = attack.get("evaluation")
    if not isinstance(evaluation, dict):
        raise CampaignError(f"attack '{attack['id']}.evaluation' must be a YAML mapping")
    dimensions = evaluation.get("dimensions")
    allowed = {"memory", "cross_session", "tool", "output"}
    if not isinstance(dimensions, list) or not dimensions or not set(dimensions) <= allowed:
        raise CampaignError(f"attack '{attack['id']}.evaluation.dimensions' must contain supported dimensions")


def _validate_phase(attack: dict[str, Any], name: str) -> None:
    phase = attack.get(name)
    if not isinstance(phase, dict):
        raise CampaignError(f"attack '{attack['id']}.{name}' must be a YAML mapping")
    messages = phase.get("messages")
    if not isinstance(messages, list) or not messages or not all(isinstance(message, str) and message for message in messages):
        raise CampaignError(f"attack '{attack['id']}.{name}.messages' must be a non-empty string list")


def _string(data: dict[str, Any], name: str, scope: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise CampaignError(f"'{scope}.{name}' must be a non-empty string")
    return value
