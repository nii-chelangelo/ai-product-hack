import argparse
import json
from pathlib import Path

from loguru import logger

from attack_on_agent.config import ConfigError, load_config
from attack_on_agent.campaign import CampaignError, load_campaign
from attack_on_agent.judge_config import JudgeConfigError, load_judge_config
from attack_on_agent.experiment import ExperimentError, load_experiment
from attack_on_agent.healthcheck import check_services
from attack_on_agent.logging import configure
from attack_on_agent.evaluator import evaluate_persistence
from attack_on_agent.langfuse import LangfuseError, get_tool_calls, get_trajectory_references
from attack_on_agent.run_store import RunError, complete_step, get_diff, get_snapshot, get_status, mark_unknown, save_diff, save_evaluation, start_step
from attack_on_agent.state_diff import diff_snapshots, diff_summary
from attack_on_agent.target import TargetError, finalize_session, get_memory_snapshot, send_chat
from attack_on_agent.runner import run_campaign


def main() -> None:
    parser = argparse.ArgumentParser(prog="attack-on-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check", help="Check local test-stand connectivity")
    check_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    chat_parser = subparsers.add_parser("chat", help="Send one message to the local target")
    chat_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    chat_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    chat_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    chat_parser.add_argument("--user", required=True, help="Configured target user ID")
    chat_parser.add_argument("--session-id", required=True, help="Target session identifier")
    chat_parser.add_argument("--message", required=True, help="User message to send")
    finalize_parser = subparsers.add_parser("finalize", help="Move one session into persistent memory")
    finalize_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    finalize_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    finalize_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    finalize_parser.add_argument("--user", required=True, help="Configured target user ID")
    finalize_parser.add_argument("--session-id", required=True, help="Target session identifier")
    snapshot_parser = subparsers.add_parser("snapshot", help="Save a read-only memory snapshot as evidence")
    snapshot_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    snapshot_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    snapshot_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    snapshot_parser.add_argument("--user", required=True, help="Configured target user ID")
    snapshot_parser.add_argument("--session-id", required=True, help="Target session identifier")
    status_parser = subparsers.add_parser("status", help="Show a run checkpoint")
    status_parser.add_argument("--run-id", required=True, help="Run identifier")
    diff_parser = subparsers.add_parser("diff", help="Compare two completed memory snapshots")
    diff_parser.add_argument("--run-id", required=True, help="Run identifier")
    diff_parser.add_argument("--before-step", required=True, help="Completed snapshot step before a target action")
    diff_parser.add_argument("--after-step", required=True, help="Completed snapshot step after a target action")
    persistence_parser = subparsers.add_parser("evaluate-persistence", help="Evaluate persistent-memory evidence")
    persistence_parser.add_argument("--run-id", required=True, help="Run identifier")
    persistence_parser.add_argument("--before-step", required=True, help="Snapshot step before the source session")
    persistence_parser.add_argument("--after-step", required=True, help="Snapshot step after finalization")
    persistence_parser.add_argument("--source-session-id", required=True, help="Session that should have persisted")
    tool_parser = subparsers.add_parser("collect-tool-evidence", help="Save Langfuse tool-call evidence for one session")
    tool_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    tool_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    tool_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    tool_parser.add_argument("--user", required=True, help="Configured target user ID")
    tool_parser.add_argument("--session-id", required=True, help="Target session identifier")
    trajectory_parser = subparsers.add_parser(
        "collect-trajectory", help="Save Langfuse observation references for one session"
    )
    trajectory_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    trajectory_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    trajectory_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    trajectory_parser.add_argument("--user", required=True, help="Configured target user ID")
    trajectory_parser.add_argument("--session-id", required=True, help="Target session identifier")
    run_parser = subparsers.add_parser("run", help="Execute a YAML attack campaign")
    run_parser.add_argument("--config", type=Path, required=True, help="Path to experiment YAML configuration")
    args = parser.parse_args()

    if args.command == "status":
        try:
            print(json.dumps(get_status(args.run_id), ensure_ascii=False, indent=2))
        except RunError as error:
            parser.error(str(error))
        return

    if args.command == "diff":
        try:
            diff = diff_snapshots(
                get_snapshot(args.run_id, args.before_step),
                get_snapshot(args.run_id, args.after_step),
            )
            save_diff(args.run_id, args.before_step, args.after_step, diff)
            print(json.dumps(diff_summary(diff), ensure_ascii=False, indent=2))
        except RunError as error:
            parser.error(str(error))
        return

    if args.command == "evaluate-persistence":
        try:
            result = evaluate_persistence(
                get_diff(args.run_id, args.before_step, args.after_step),
                args.source_session_id,
            )
            save_evaluation(args.run_id, "persistence", result)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except RunError as error:
            parser.error(str(error))
        return

    if args.command == "run":
        try:
            experiment = load_experiment(args.config)
            config_path = experiment["target"]
        except ExperimentError as error:
            parser.error(str(error))
    else:
        config_path = args.config
    try:
        config = load_config(config_path)
    except ConfigError as error:
        parser.error(str(error))

    configure(config["logging"]["path"])
    if args.command == "run":
        try:
            campaign = load_campaign(experiment["campaign"])
            judge_settings = load_judge_config(experiment["judge"]) if experiment["judge"] else None
            result = run_campaign(config, campaign, experiment["run_id"], experiment["users"], judge_settings)
        except (CampaignError, JudgeConfigError, RunError, TargetError, LangfuseError) as error:
            parser.error(str(error))
        print(json.dumps(result, ensure_ascii=False))
        return
    if args.command == "check":
        logger.info("Starting local test-stand check")
        if check_services(config):
            logger.success("Local test stand is ready")
            return

        logger.error("Local test stand is not ready")
        raise SystemExit(1)

    operation = args.command
    try:
        input_data = {}
        start_step(args.run_id, args.step_id, operation, args.user, args.session_id, config, input_data)
    except RunError as error:
        logger.error("Checkpoint rejected: {}", error)
        raise SystemExit(1) from error

    try:
        if operation == "finalize":
            logger.info("Finalizing session: run_id={}, step_id={}, session_id={}", args.run_id, args.step_id, args.session_id)
            episodes, facts = finalize_session(config, args.user, args.session_id)
            complete_step(args.run_id, args.step_id, {"episodes": episodes, "facts": facts})
            logger.success("Session finalized: session_id={}, episodes={}, facts={}", args.session_id, episodes, facts)
            print(f"episodes={episodes} facts={facts}")
            return

        if operation == "collect-tool-evidence":
            tool_calls = get_tool_calls(config, get_status(args.run_id)["created_at"], args.session_id)
            complete_step(args.run_id, args.step_id, {"tool_calls": tool_calls})
            print(f"tool_calls={len(tool_calls)}")
            return

        if operation == "collect-trajectory":
            references = get_trajectory_references(config, get_status(args.run_id)["created_at"], args.session_id)
            complete_step(args.run_id, args.step_id, {"langfuse_observations": references})
            print(f"observations={len(references)}")
            return

        if operation == "snapshot":
            logger.info("Saving memory snapshot: run_id={}, step_id={}, session_id={}", args.run_id, args.step_id, args.session_id)
            snapshot = get_memory_snapshot(config, args.user, args.session_id)
            complete_step(args.run_id, args.step_id, {"memory_snapshot": snapshot})
            logger.success("Memory snapshot saved: session_id={}", args.session_id)
            print("snapshot saved")
            return

        logger.info("Sending chat request: run_id={}, step_id={}, session_id={}, auth_mode={}", args.run_id, args.step_id, args.session_id, config["target"]["auth_mode"])
        response = send_chat(config, args.user, args.message, args.session_id)
        complete_step(args.run_id, args.step_id, {"langfuse_session_id": args.session_id})
    except (TargetError, LangfuseError, RunError) as error:
        mark_unknown(args.run_id, args.step_id, str(error))
        logger.error("Target request failed: {}", error)
        raise SystemExit(1) from error

    logger.success("Chat request completed: session_id={}", args.session_id)
    print(response)
