import argparse
import json
from pathlib import Path

from loguru import logger

from attack_on_agent.config import ConfigError, load_campaign, load_config, load_impact_campaign
from attack_on_agent.healthcheck import check_services
from attack_on_agent.logging import configure
from attack_on_agent.evaluator import evaluate_activation, evaluate_impact, evaluate_persistence
from attack_on_agent.langfuse import LangfuseError, get_tool_calls
from attack_on_agent.report import generate_report
from attack_on_agent.run_store import RunError, complete_step, get_chat_response, get_diff, get_snapshot, get_status, get_tool_calls_from_step, mark_unknown, save_diff, save_evaluation, start_step
from attack_on_agent.state_diff import diff_snapshots, diff_summary
from attack_on_agent.target import TargetError, finalize_session, get_memory_snapshot, send_chat


def main() -> None:
    parser = argparse.ArgumentParser(prog="attack-on-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check", help="Check local test-stand connectivity")
    check_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    chat_parser = subparsers.add_parser("chat", help="Send one message to the local target")
    chat_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    chat_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    chat_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    chat_parser.add_argument("--session-id", required=True, help="Target session identifier")
    chat_parser.add_argument("--message", required=True, help="User message to send")
    finalize_parser = subparsers.add_parser("finalize", help="Move one session into persistent memory")
    finalize_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    finalize_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    finalize_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    finalize_parser.add_argument("--session-id", required=True, help="Target session identifier")
    snapshot_parser = subparsers.add_parser("snapshot", help="Save a read-only memory snapshot as evidence")
    snapshot_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    snapshot_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    snapshot_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
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
    activation_parser = subparsers.add_parser("evaluate-activation", help="Evaluate cross-session memory activation")
    activation_parser.add_argument("--run-id", required=True, help="Run identifier")
    activation_parser.add_argument("--trigger-step", required=True, help="Completed chat step in a new session")
    activation_parser.add_argument("--campaign", type=Path, required=True, help="YAML campaign with activation marker")
    tool_parser = subparsers.add_parser("collect-tool-evidence", help="Save Langfuse tool-call evidence for one session")
    tool_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    tool_parser.add_argument("--run-id", required=True, help="Run identifier for checkpoints")
    tool_parser.add_argument("--step-id", required=True, help="Unique step identifier within the run")
    tool_parser.add_argument("--session-id", required=True, help="Target session identifier")
    impact_parser = subparsers.add_parser("evaluate-impact", help="Evaluate output and tool impact")
    impact_parser.add_argument("--run-id", required=True, help="Run identifier")
    impact_parser.add_argument("--response-step", required=True, help="Completed chat step with the target response")
    impact_parser.add_argument("--tool-evidence-step", required=True, help="Completed tool-evidence step")
    impact_parser.add_argument("--campaign", type=Path, required=True, help="YAML campaign with impact criteria")
    report_parser = subparsers.add_parser("report", help="Generate a Markdown report from saved run evidence")
    report_parser.add_argument("--run-id", required=True, help="Run identifier")
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

    if args.command == "evaluate-activation":
        try:
            campaign = load_campaign(args.campaign)
            result = evaluate_activation(
                get_chat_response(args.run_id, args.trigger_step),
                campaign["evaluation"]["expected_marker"],
            )
            save_evaluation(args.run_id, "activation", result)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except (ConfigError, RunError) as error:
            parser.error(str(error))
        return

    if args.command == "evaluate-impact":
        try:
            campaign = load_impact_campaign(args.campaign)
            impact = campaign["impact"]
            result = evaluate_impact(
                get_chat_response(args.run_id, args.response_step),
                get_tool_calls_from_step(args.run_id, args.tool_evidence_step),
                impact["expected_marker"],
                impact["tool"]["name"],
                impact["tool"]["expected_cus"],
                impact["denied_markers"],
            )
            save_evaluation(args.run_id, "impact", result)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except (ConfigError, RunError) as error:
            parser.error(str(error))
        return

    if args.command == "report":
        try:
            print(generate_report(args.run_id))
        except RunError as error:
            parser.error(str(error))
        return

    try:
        config = load_config(args.config)
    except ConfigError as error:
        parser.error(str(error))

    configure(config["logging"]["path"])
    if args.command == "check":
        logger.info("Starting local test-stand check")
        if check_services(config):
            logger.success("Local test stand is ready")
            return

        logger.error("Local test stand is not ready")
        raise SystemExit(1)

    operation = args.command
    try:
        input_data = {"message": args.message} if operation == "chat" else {}
        start_step(args.run_id, args.step_id, operation, args.session_id, config, input_data)
    except RunError as error:
        logger.error("Checkpoint rejected: {}", error)
        raise SystemExit(1) from error

    try:
        if operation == "finalize":
            logger.info("Finalizing session: run_id={}, step_id={}, session_id={}", args.run_id, args.step_id, args.session_id)
            episodes, facts = finalize_session(config, args.session_id)
            complete_step(args.run_id, args.step_id, {"episodes": episodes, "facts": facts})
            logger.success("Session finalized: session_id={}, episodes={}, facts={}", args.session_id, episodes, facts)
            print(f"episodes={episodes} facts={facts}")
            return

        if operation == "collect-tool-evidence":
            tool_calls = get_tool_calls(config, get_status(args.run_id)["created_at"], args.session_id)
            complete_step(args.run_id, args.step_id, {"tool_calls": tool_calls})
            print(f"tool_calls={len(tool_calls)}")
            return

        if operation == "snapshot":
            logger.info("Saving memory snapshot: run_id={}, step_id={}, session_id={}", args.run_id, args.step_id, args.session_id)
            snapshot = get_memory_snapshot(config, args.session_id)
            complete_step(args.run_id, args.step_id, {"memory_snapshot": snapshot})
            logger.success("Memory snapshot saved: session_id={}", args.session_id)
            print("snapshot saved")
            return

        logger.info("Sending chat request: run_id={}, step_id={}, session_id={}, auth_mode={}", args.run_id, args.step_id, args.session_id, config["target"]["auth_mode"])
        response = send_chat(config, args.message, args.session_id)
        complete_step(args.run_id, args.step_id, {"message": args.message, "response": response})
    except (TargetError, LangfuseError, RunError) as error:
        mark_unknown(args.run_id, args.step_id, str(error))
        logger.error("Target request failed: {}", error)
        raise SystemExit(1) from error

    logger.success("Chat request completed: session_id={}", args.session_id)
    print(response)
