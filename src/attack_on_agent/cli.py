import argparse
import json
from pathlib import Path

from attack_on_agent.campaign import CampaignError, load_campaign
from attack_on_agent.config import ConfigError, load_config
from attack_on_agent.dashboard import build_dashboard
from attack_on_agent.experiment import ExperimentError, load_experiment
from attack_on_agent.healthcheck import check_services
from attack_on_agent.judge_config import JudgeConfigError, load_judge_config
from attack_on_agent.logging import configure
from attack_on_agent.runner import run_campaign
from attack_on_agent.summary import build_run_report, build_validation_summary
from attack_on_agent.run_store import RunError, get_status
from attack_on_agent.langfuse import LangfuseError
from attack_on_agent.target import TargetError
from loguru import logger


def main() -> None:
    parser = argparse.ArgumentParser(prog="attack-on-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check_parser = subparsers.add_parser("check", help="Check local test-stand connectivity")
    check_parser.add_argument("--config", type=Path, required=True, help="Path to local YAML configuration")
    status_parser = subparsers.add_parser("status", help="Show a run checkpoint")
    status_parser.add_argument("--run-id", required=True, help="Run identifier")
    run_parser = subparsers.add_parser("run", help="Execute a YAML attack campaign")
    run_parser.add_argument("--config", type=Path, required=True, help="Path to experiment YAML configuration")
    validation_parser = subparsers.add_parser("validate", help="Build a synthetic validation summary")
    validation_parser.add_argument("--config", type=Path, required=True, help="Path to validation YAML configuration")
    report_parser = subparsers.add_parser("report", help="Build a Markdown report from a completed run")
    report_parser.add_argument("--config", type=Path, required=True, help="Path to experiment YAML configuration")
    dashboard_parser = subparsers.add_parser("dashboard", help="Build a local HTML dashboard over all runs")
    dashboard_parser.add_argument("--runs-dir", type=Path, default=Path("runs"), help="Directory containing run subdirectories")
    dashboard_parser.add_argument("--output", type=Path, default=None, help="Output HTML path (default: <runs-dir>/dashboard.html)")
    args = parser.parse_args()

    if args.command == "dashboard":
        output = args.output or args.runs_dir / "dashboard.html"
        output.write_text(build_dashboard(args.runs_dir))
        print(str(output))
        return

    if args.command == "status":
        try:
            print(json.dumps(get_status(args.run_id), ensure_ascii=False, indent=2))
        except RunError as error:
            parser.error(str(error))
        return

    if args.command == "validate":
        output, summary = build_validation_summary(args.config)
        print(json.dumps({"output": str(output), **summary}, ensure_ascii=False))
        return

    if args.command == "report":
        try:
            experiment = load_experiment(args.config)
            print(build_run_report(experiment["run_id"]))
        except (ExperimentError, RunError, ValueError) as error:
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
