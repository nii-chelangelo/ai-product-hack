import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class RunError(ValueError):
    """Raised when a run checkpoint cannot be safely continued."""


def start_step(
    run_id: str,
    step_id: str,
    operation: str,
    session_id: str,
    config: dict[str, Any],
    input_data: dict[str, Any] | None = None,
) -> None:
    run_dir = _run_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    state = _load_state(run_dir, run_id, config)

    if step_id in state["steps"]:
        status = state["steps"][step_id]["status"]
        raise RunError(f"Step '{step_id}' already exists with status '{status}'; do not retry it automatically")

    state["steps"][step_id] = {
        "operation": operation,
        "session_id": session_id,
        "status": "started",
        "started_at": _now(),
    }
    _write_state(run_dir, state)
    _append_event(
        run_dir,
        {
            "event": "started",
            "step_id": step_id,
            "operation": operation,
            "session_id": session_id,
            "input": input_data or {},
        },
    )


def complete_step(run_id: str, step_id: str, evidence: dict[str, Any]) -> None:
    run_dir = _run_dir(run_id)
    state = _load_existing_state(run_dir, run_id)
    step = _started_step(state, step_id)

    _append_event(run_dir, {"event": "completed", "step_id": step_id, "evidence": evidence})
    step["status"] = "completed"
    step["completed_at"] = _now()
    _write_state(run_dir, state)


def mark_unknown(run_id: str, step_id: str, error: str) -> None:
    run_dir = _run_dir(run_id)
    state = _load_existing_state(run_dir, run_id)
    step = _started_step(state, step_id)
    step["status"] = "unknown"
    step["error"] = error
    step["updated_at"] = _now()
    _write_state(run_dir, state)
    _append_event(run_dir, {"event": "unknown", "step_id": step_id, "error": error})


def get_status(run_id: str) -> dict[str, Any]:
    return _load_existing_state(_run_dir(run_id), run_id)


def get_snapshot(run_id: str, step_id: str) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    state = _load_existing_state(run_dir, run_id)
    step = state["steps"].get(step_id)
    if not step or step["operation"] != "snapshot" or step["status"] != "completed":
        raise RunError(f"Step '{step_id}' is not a completed snapshot")

    for line in reversed((run_dir / "events.jsonl").read_text().splitlines()):
        event = json.loads(line)
        if event.get("event") == "completed" and event.get("step_id") == step_id:
            snapshot = event.get("evidence", {}).get("memory_snapshot")
            if isinstance(snapshot, dict):
                return snapshot
    raise RunError(f"Snapshot evidence for step '{step_id}' is missing")


def save_diff(run_id: str, before_step: str, after_step: str, diff: dict[str, Any]) -> None:
    run_dir = _run_dir(run_id)
    _load_existing_state(run_dir, run_id)
    payload = {
        "before_step": before_step,
        "after_step": after_step,
        "diff": diff,
    }
    (run_dir / "state_diff.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def get_diff(run_id: str, before_step: str, after_step: str) -> dict[str, Any]:
    run_dir = _run_dir(run_id)
    payload = json.loads((run_dir / "state_diff.json").read_text())
    if payload.get("before_step") != before_step or payload.get("after_step") != after_step:
        raise RunError("Saved state diff does not match the requested snapshots")
    return payload["diff"]


def save_evaluation(run_id: str, name: str, result: dict[str, Any]) -> None:
    run_dir = _run_dir(run_id)
    _load_existing_state(run_dir, run_id)
    evaluations_dir = run_dir / "evaluations"
    evaluations_dir.mkdir(exist_ok=True)
    (evaluations_dir / f"{name}.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")


def _run_dir(run_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", run_id):
        raise RunError("run_id must contain only letters, numbers, underscores, or hyphens")
    return Path("runs") / run_id


def _load_state(run_dir: Path, run_id: str, config: dict[str, Any]) -> dict[str, Any]:
    state_path = run_dir / "state.json"
    if state_path.exists():
        return json.loads(state_path.read_text())
    return {
        "run_id": run_id,
        "created_at": _now(),
        "target": {
            "base_url": config["target"]["base_url"],
            "auth_mode": config["target"]["auth_mode"],
        },
        "steps": {},
    }


def _load_existing_state(run_dir: Path, run_id: str) -> dict[str, Any]:
    state_path = run_dir / "state.json"
    if not state_path.exists():
        raise RunError(f"Run '{run_id}' does not exist")
    return json.loads(state_path.read_text())


def _started_step(state: dict[str, Any], step_id: str) -> dict[str, Any]:
    step = state["steps"].get(step_id)
    if not step or step["status"] != "started":
        raise RunError(f"Step '{step_id}' is not in progress")
    return step


def _append_event(run_dir: Path, event: dict[str, Any]) -> None:
    record = {"at": _now(), **event}
    with (run_dir / "events.jsonl").open("a") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")


def _write_state(run_dir: Path, state: dict[str, Any]) -> None:
    temporary_path = run_dir / "state.tmp"
    temporary_path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    temporary_path.replace(run_dir / "state.json")


def _now() -> str:
    return datetime.now(UTC).isoformat()
