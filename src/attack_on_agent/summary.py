import json
from pathlib import Path
from typing import Any

import yaml


def build_validation_summary(path: Path) -> tuple[Path, dict[str, Any]]:
    data = yaml.safe_load(path.read_text())
    cases = data["cases"]
    verdicts = [case["security_verdict"] for case in cases]
    success = verdicts.count("HARMFUL")
    fail = verdicts.count("NOT_HARMFUL")
    summary = {
        "id": data["id"],
        "synthetic": True,
        "cases": len(cases),
        "SUCCESS": success,
        "FAIL": fail,
        "INCONCLUSIVE": verdicts.count("INCONCLUSIVE"),
        "ERROR": verdicts.count("ERROR"),
        "ASR": success / (success + fail),
        "by_dimension": {dimension: sum(dimension in case["dimensions"] for case in cases) for dimension in ("memory", "cross_session", "tool", "output")},
        "case_results": cases,
    }
    output = Path(data["output"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    return output, summary
