import json
from typing import Any


def diff_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    return {
        "working_memory": _diff_working_memory(before["working_memory"], after["working_memory"]),
        "dialog_sessions": _diff_collection(before["dialog_sessions"], after["dialog_sessions"], "session_id"),
        "episodic_memories": _diff_collection(before["episodic_memories"], after["episodic_memories"], "episode_id"),
        "semantic_memories": _diff_collection(before["semantic_memories"], after["semantic_memories"], "fact_id"),
        "agent_policies": _diff_collection(before["agent_policies"], after["agent_policies"], "policy_id"),
    }


def diff_summary(diff: dict[str, Any]) -> dict[str, int]:
    summary = {"working_messages_added": len(diff["working_memory"]["added_messages"])}
    for name in ("dialog_sessions", "episodic_memories", "semantic_memories", "agent_policies"):
        changes = diff[name]
        summary[f"{name}_added"] = len(changes["added"])
        summary[f"{name}_removed"] = len(changes["removed"])
        summary[f"{name}_changed"] = len(changes["changed"])
    return summary


def _diff_working_memory(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_messages = before.get("messages", [])
    after_messages = after.get("messages", [])
    return {
        "added_messages": after_messages[len(before_messages):],
        "summary_before": before.get("summary", ""),
        "summary_after": after.get("summary", ""),
        "summary_changed": before.get("summary", "") != after.get("summary", ""),
    }


def _diff_collection(before: list[dict[str, Any]], after: list[dict[str, Any]], key: str) -> dict[str, Any]:
    before_by_key = {entry[key]: entry for entry in before}
    after_by_key = {entry[key]: entry for entry in after}
    shared_keys = before_by_key.keys() & after_by_key.keys()
    return {
        "added": [after_by_key[item] for item in after_by_key.keys() - before_by_key.keys()],
        "removed": [before_by_key[item] for item in before_by_key.keys() - after_by_key.keys()],
        "changed": [
            {"id": item, "before": before_by_key[item], "after": after_by_key[item]}
            for item in shared_keys
            if _canonical(before_by_key[item]) != _canonical(after_by_key[item])
        ],
    }


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
