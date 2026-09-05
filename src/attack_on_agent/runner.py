import os
from typing import Any, Callable

from loguru import logger

from attack_on_agent.langfuse import get_tool_calls, wait_for_trajectory_references
from attack_on_agent.case_evaluator import evaluate_case
from attack_on_agent.run_store import RunError, complete_step, get_status, mark_unknown, save_diff, save_evaluation, start_step
from attack_on_agent.state_diff import diff_snapshots
from attack_on_agent.target import finalize_session, get_memory_snapshot


def run_campaign(config: dict[str, Any], campaign: dict[str, Any], run_id: str, users: dict[str, str], judge_settings: dict[str, Any] | None = None) -> dict[str, Any]:
    results: list[str] = []
    for test in campaign["tests"]:
        try:
            results.append(_run_test(config, run_id, campaign["llamator"], test, users, judge_settings)["security_verdict"])
        except Exception as error:
            save_evaluation(run_id, test["id"], {"test_id": test["id"], "result": "ERROR", "error": str(error)})
            results.append("ERROR")
    success = results.count("HARMFUL")
    fail = results.count("NOT_HARMFUL")
    return {"SUCCESS": success, "FAIL": fail, "INCONCLUSIVE": results.count("INCONCLUSIVE"), "ERROR": results.count("ERROR"), "ASR": success / (success + fail) if success + fail else None}


def _run_test(
    config: dict[str, Any], run_id: str, llamator_config: dict[str, Any], test: dict[str, Any], users: dict[str, str], judge_settings: dict[str, Any] | None
) -> dict[str, Any]:
    test_id = test["id"]
    source_session = f"{run_id}-{test_id}-source"
    source_user = users["attacker"]

    before = _step(
        config, run_id, f"{test_id}.before", "snapshot", source_user, source_session,
        lambda: {"memory_snapshot": get_memory_snapshot(config, source_user, source_session)},
    )["memory_snapshot"]

    _step(
        config, run_id, f"{test_id}.llamator", "llamator", source_user, source_session,
        lambda: _llamator_evidence(config, llamator_config, test, source_user, source_session),
    )

    _step(
        config, run_id, f"{test_id}.finalize", "finalize", source_user, source_session,
        lambda: _finalize_evidence(config, source_user, source_session),
    )
    after = _step(
        config, run_id, f"{test_id}.after", "snapshot", source_user, source_session,
        lambda: {"memory_snapshot": get_memory_snapshot(config, source_user, source_session)},
    )["memory_snapshot"]

    started_at = get_status(run_id)["created_at"]
    _step(
        config, run_id, f"{test_id}.trajectory", "collect-trajectory", source_user, source_session,
        lambda: {"langfuse_observations": wait_for_trajectory_references(config, started_at, source_session)},
    )
    _step(
        config, run_id, f"{test_id}.tools", "collect-tool-evidence", source_user, source_session,
        lambda: {"tool_calls": get_tool_calls(config, started_at, source_session)},
    )

    save_diff(run_id, f"{test_id}.before", f"{test_id}.after", diff_snapshots(before, after))
    evaluation = evaluate_case(config, run_id, test, judge_settings)
    logger.success("LLAMATOR test completed: {}", test_id)
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


def _finalize_evidence(config: dict[str, Any], user_id: str, session_id: str) -> dict[str, int]:
    episodes, facts = finalize_session(config, user_id, session_id)
    return {"episodes": episodes, "facts": facts}


def _llamator_evidence(
    config: dict[str, Any], llamator_config: dict[str, Any], test: dict[str, Any], user_id: str, session_id: str
) -> dict[str, Any]:
    """Run one configured LLAMATOR test without creating a second report store."""
    import llamator

    from attack_on_agent.llamator_bridge import TargetClient

    attacker = llamator_config["attacker"]
    api_key = os.environ.get(attacker["api_key_env"])
    base_url = os.environ.get(attacker["base_url_env"])
    if not api_key or not base_url:
        raise RunError("LLAMATOR attacker credentials are not set in the environment")
    attack_model = llamator.ClientOpenAI(
        api_key=api_key,
        base_url=base_url,
        model=attacker["model"],
        temperature=0.0,
    )
    results = llamator.start_testing(
        attack_model=attack_model,
        tested_model=TargetClient(config, user_id, session_id),
        config={"enable_logging": False, "enable_reports": False, "artifacts_path": None, "debug_level": 0},
        num_threads=1,
        basic_tests=[(test["id"], test.get("params", {}))],
    )
    return {"framework": "llamator", "test_id": test["id"], "results": results}
