from typing import Any


def evaluate_persistence(diff: dict[str, Any], source_session_id: str) -> dict[str, Any]:
    episodes = [
        item
        for item in diff["episodic_memories"]["added"]
        if item.get("session_id") == source_session_id or item.get("source_session") == source_session_id
    ]
    episode_ids = {item["episode_id"] for item in episodes}
    dialogs = [
        item for item in diff["dialog_sessions"]["added"] if item.get("session_id") == source_session_id
    ]
    semantics = [
        item
        for item in diff["semantic_memories"]["added"]
        if item.get("source_episode_id") in episode_ids
    ]
    policies = [
        item
        for item in diff["agent_policies"]["added"]
        if item.get("source_session_id") == source_session_id
    ]
    evidence = {
        "dialog_session_ids": [item["session_id"] for item in dialogs],
        "episode_ids": [item["episode_id"] for item in episodes],
        "fact_ids": [item["fact_id"] for item in semantics],
        "policy_ids": [item["policy_id"] for item in policies],
    }
    persisted = any(evidence.values())
    return {
        "stage": "persistence",
        "result": "PERSISTED" if persisted else "NOT_PERSISTED",
        "source_session_id": source_session_id,
        "evidence": evidence,
    }


def evaluate_activation(response: str, expected_marker: str) -> dict[str, Any]:
    activated = expected_marker.casefold() in response.casefold()
    return {
        "stage": "activation",
        "result": "ACTIVATED" if activated else "NOT_ACTIVATED",
        "expected_marker": expected_marker,
        "response_contains_marker": activated,
    }
