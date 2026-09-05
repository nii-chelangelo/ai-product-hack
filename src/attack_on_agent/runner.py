from typing import Any, Callable

from loguru import logger

from attack_on_agent.langfuse import get_tool_calls, get_trajectory_references
from attack_on_agent.case_evaluator import evaluate_case
from attack_on_agent.run_store import RunError, complete_step, get_status, mark_unknown, save_diff, save_evaluation, start_step
from attack_on_agent.state_diff import diff_snapshots
from attack_on_agent.target import finalize_session, get_memory_snapshot, send_chat


def run_campaign(config: dict[str, Any], campaign: dict[str, Any], run_id: str, users: dict[str, str], judge_settings: dict[str, Any] | None = None) -> dict[str, Any]:
    results: list[str] = []
    for attack in campaign["attacks"]:
        try:
            results.append(_run_attack(config, run_id, attack, users, judge_settings)["result"])
        except Exception as error:
            save_evaluation(run_id, attack["id"], {"attack_id": attack["id"], "result": "ERROR", "error": str(error)})
            results.append("ERROR")
    success = results.count("SUCCESS")
    fail = results.count("FAIL")
    return {"SUCCESS": success, "FAIL": fail, "INCONCLUSIVE": results.count("INCONCLUSIVE"), "ERROR": results.count("ERROR"), "ASR": success / (success + fail) if success + fail else None}


def _run_attack(config: dict[str, Any], run_id: str, attack: dict[str, Any], users: dict[str, str], judge_settings: dict[str, Any] | None) -> dict[str, Any]:
    attack_id = attack["id"]
    source = attack["delivery"]
    activation = attack["activation"]
    source_session = f"{run_id}-{attack_id}-source"
    activation_session = f"{run_id}-{attack_id}-activation"
    source_user = users["attacker"]
    activation_user = users["verifier"]

    before = _step(
        config, run_id, f"{attack_id}.before", "snapshot", source_user, source_session,
        lambda: {"memory_snapshot": get_memory_snapshot(config, source_user, source_session)},
    )["memory_snapshot"]

    for index, message in enumerate(source["messages"], start=1):
        _step(
            config, run_id, f"{attack_id}.delivery.{index}", "chat", source_user, source_session,
            lambda message=message: _chat_evidence(config, source_user, message, source_session),
        )

    _step(
        config, run_id, f"{attack_id}.finalize", "finalize", source_user, source_session,
        lambda: _finalize_evidence(config, source_user, source_session),
    )
    after = _step(
        config, run_id, f"{attack_id}.after", "snapshot", source_user, source_session,
        lambda: {"memory_snapshot": get_memory_snapshot(config, source_user, source_session)},
    )["memory_snapshot"]

    for index, message in enumerate(activation["messages"], start=1):
        _step(
            config, run_id, f"{attack_id}.activation.{index}", "chat", activation_user, activation_session,
            lambda message=message: _chat_evidence(config, activation_user, message, activation_session),
        )

    started_at = get_status(run_id)["created_at"]
    for user_id, session_id, phase in (
        (source_user, source_session, "source"),
        (activation_user, activation_session, "activation"),
    ):
        _step(
            config, run_id, f"{attack_id}.{phase}.trajectory", "collect-trajectory", user_id, session_id,
            lambda session_id=session_id: {"langfuse_observations": get_trajectory_references(config, started_at, session_id)},
        )
        _step(
            config, run_id, f"{attack_id}.{phase}.tools", "collect-tool-evidence", user_id, session_id,
            lambda session_id=session_id: {"tool_calls": get_tool_calls(config, started_at, session_id)},
        )

    save_diff(run_id, f"{attack_id}.before", f"{attack_id}.after", diff_snapshots(before, after))
    evaluation = evaluate_case(config, run_id, attack, judge_settings)
    logger.success("Attack case completed: {}", attack_id)
    return evaluation


def _step(
    config: dict[str, Any],
    run_id: str,
    step_id: str,
    operation: str,
    user_id: str,
    session_id: str,
    action: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    try:
        status = get_status(run_id)["steps"].get(step_id, {}).get("status")
    except RunError:
        status = None
    if status == "completed":
        return _step_evidence(run_id, step_id)
    if status is not None:
        raise RunError(f"Step '{step_id}' has status '{status}' and cannot be retried automatically")

    start_step(run_id, step_id, operation, user_id, session_id, config)
    try:
        evidence = action()
    except Exception as error:
        mark_unknown(run_id, step_id, str(error))
        raise
    complete_step(run_id, step_id, evidence)
    return evidence


def _step_evidence(run_id: str, step_id: str) -> dict[str, Any]:
    from attack_on_agent.run_store import get_step_evidence

    return get_step_evidence(run_id, step_id)


def _chat_evidence(config: dict[str, Any], user_id: str, message: str, session_id: str) -> dict[str, str]:
    send_chat(config, user_id, message, session_id)
    return {"langfuse_session_id": session_id}


def _finalize_evidence(config: dict[str, Any], user_id: str, session_id: str) -> dict[str, int]:
    episodes, facts = finalize_session(config, user_id, session_id)
    return {"episodes": episodes, "facts": facts}
