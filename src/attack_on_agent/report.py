import json
from pathlib import Path
from typing import Any

from attack_on_agent.run_store import RunError, get_status


def generate_report(run_id: str) -> Path:
    state = get_status(run_id)
    run_dir = Path("runs") / run_id
    evaluations = _evaluations(run_dir)
    diff = _load_json(run_dir / "state_diff.json")

    lines = [
        f"# Attack On Agent — run `{run_id}`",
        "",
        "## Result",
        "",
        f"- Persistence: {_result(evaluations, 'persistence')}",
        f"- Activation: {_result(evaluations, 'activation')}",
        "- Impact: not measured",
        "- Tools: not measured",
        "",
        "`SUCCESS` is not assigned yet: this run has no agreed impact criterion.",
        "",
        "## Execution",
        "",
        "| Step | Operation | Session | Status |",
        "| --- | --- | --- | --- |",
    ]
    for step_id, step in state["steps"].items():
        lines.append(
            f"| `{step_id}` | {step['operation']} | `{step['session_id']}` | {step['status']} |"
        )

    if diff:
        lines.extend(
            [
                "",
                "## State change",
                "",
                "| Store | Added | Removed | Changed |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for name in ("dialog_sessions", "episodic_memories", "semantic_memories", "agent_policies"):
            change = diff["diff"][name]
            lines.append(
                f"| {name} | {len(change['added'])} | {len(change['removed'])} | {len(change['changed'])} |"
            )

    lines.extend(
        [
            "",
            "## Evidence",
            "",
            "- `state.json` — checkpoints and execution status",
            "- `events.jsonl` — request and response evidence",
            "- `state_diff.json` — memory snapshot diff",
            "- `evaluations/` — deterministic evaluation results",
            "",
        ]
    )
    report_path = run_dir / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def _evaluations(run_dir: Path) -> dict[str, dict[str, Any]]:
    evaluations = {}
    for path in (run_dir / "evaluations").glob("*.json"):
        payload = _load_json(path)
        if payload:
            evaluations[path.stem] = payload
    return evaluations


def _result(evaluations: dict[str, dict[str, Any]], name: str) -> str:
    result = evaluations.get(name, {}).get("result")
    return result if isinstance(result, str) else "not measured"


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RunError(f"Invalid JSON evidence: {path}") from error
    if not isinstance(payload, dict):
        raise RunError(f"Expected a JSON object in {path}")
    return payload
