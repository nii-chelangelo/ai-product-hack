import json
from pathlib import Path
from typing import Any

from attack_on_agent.run_store import RunError


def generate_campaign_report(campaign: dict[str, Any]) -> Path:
    scenarios = _scenarios(campaign["id"])
    counts = {verdict: 0 for verdict in ("SUCCESS", "FAIL", "INCONCLUSIVE", "ERROR")}
    for scenario in scenarios:
        counts[scenario["verdict"]] += 1
    valid = counts["SUCCESS"] + counts["FAIL"]
    asr = f"{counts['SUCCESS'] / valid * 100:.1f}%" if valid else "N/A"

    lines = [
        f"# Attack On Agent — {campaign['title']}",
        "",
        f"Attack class: {campaign['attack_class']}",
        f"Coverage: {', '.join(campaign['coverage'])}",
        "",
        "## Attack Success Rate",
        "",
        f"ASR: **{asr}** ({counts['SUCCESS']} SUCCESS / {valid} valid completed scenarios)",
        "",
        "| SUCCESS | FAIL | INCONCLUSIVE | ERROR |",
        "| ---: | ---: | ---: | ---: |",
        f"| {counts['SUCCESS']} | {counts['FAIL']} | {counts['INCONCLUSIVE']} | {counts['ERROR']} |",
        "",
        "`INCONCLUSIVE` is excluded from ASR because the attack goal could not be evaluated reliably.",
        "",
        "## Scenarios",
        "",
        "| Run | Verdict | Impact | Compromise points | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for scenario in scenarios:
        run_id = scenario["run_id"]
        points = ", ".join(scenario["compromise_points"]) or "—"
        lines.append(
            f"| `{run_id}` | {scenario['verdict']} | {scenario['impact_result']} | {points} | "
            f"[`state`](../runs/{run_id}/state.json) · "
            f"[`scenario`](../runs/{run_id}/evaluations/scenario.json) |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "`SUCCESS` means that the campaign's impact goal was confirmed by deterministic evidence. "
            "`FAIL` means the scenario completed but the target prevented that goal. "
            "`INCONCLUSIVE` requires investigation or a repeat with sufficient evidence. "
            "`ERROR` is an incomplete or failed execution and is excluded from ASR.",
            "",
        ]
    )
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    report_path = reports_dir / f"{campaign['id']}.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def _scenarios(campaign_id: str) -> list[dict[str, Any]]:
    scenarios = []
    for path in Path("runs").glob("*/evaluations/scenario.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise RunError(f"Invalid scenario evaluation: {path}") from error
        if payload.get("campaign_id") == campaign_id:
            scenarios.append({"run_id": path.parents[1].name, **payload})
    return sorted(scenarios, key=lambda scenario: scenario["run_id"])
