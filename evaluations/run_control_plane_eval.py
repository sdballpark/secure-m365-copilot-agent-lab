"""Run the labeled adversarial corpus against controls that exist today.

This runner intentionally distinguishes:
- control_plane: executable against deterministic authorization/gateway code
- model_dependent: requires a live LLM/Copilot grounding path
- not_yet_executable: requires a backend/security surface not implemented yet

It never converts an unexecuted case into a security pass.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from api.gateway import GatewayRequest, SecurityGateway
from api.storage import SQLiteStore


ROOT = Path(__file__).parents[1]
CORPUS_PATH = ROOT / "evaluations" / "attack-corpus.jsonl"
PLAN_PATH = ROOT / "evaluations" / "control-plane-plan.json"


@dataclass
class CaseResult:
    attack_id: str
    category: str
    mode: str
    expected_decision: str
    actual_decision: str | None
    passed: bool | None
    reason: str
    security_invariant: str


def load_corpus() -> dict[str, dict[str, Any]]:
    cases = {}
    with CORPUS_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                case = json.loads(line)
                cases[case["attack_id"]] = case
    return cases


def load_plan() -> dict[str, dict[str, Any]]:
    with PLAN_PATH.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    return {case["attack_id"]: case for case in plan["cases"]}


def run() -> dict[str, Any]:
    corpus = load_corpus()
    plan = load_plan()

    if set(corpus) != set(plan):
        missing = sorted(set(corpus) - set(plan))
        extra = sorted(set(plan) - set(corpus))
        raise ValueError(
            f"control-plane plan must cover every corpus case; missing={missing}, extra={extra}"
        )

    results: list[CaseResult] = []

    for attack_id in sorted(corpus):
        case = corpus[attack_id]
        execution = plan[attack_id]
        expected = execution.get(
            "expected_decision_override",
            case["expected_decision"],
        )
        mode = execution["mode"]

        if mode != "control_plane":
            results.append(
                CaseResult(
                    attack_id=attack_id,
                    category=case["category"],
                    mode=mode,
                    expected_decision=expected,
                    actual_decision=None,
                    passed=None,
                    reason=execution["reason"],
                    security_invariant=case["security_invariant"],
                )
            )
            continue

        gateway = SecurityGateway(store=SQLiteStore())
        response = gateway.handle(
            GatewayRequest(
                user_id="lab-tenant:eval-user",
                role=execution["role"],
                action=execution["action"],
                arguments=execution["arguments"],
            )
        )

        passed = response.decision == expected
        results.append(
            CaseResult(
                attack_id=attack_id,
                category=case["category"],
                mode=mode,
                expected_decision=expected,
                actual_decision=response.decision,
                passed=passed,
                reason=execution.get("rationale", response.reason),
                security_invariant=case["security_invariant"],
            )
        )

    mode_counts = Counter(result.mode for result in results)
    executable = [result for result in results if result.mode == "control_plane"]
    passed = [result for result in executable if result.passed is True]
    failed = [result for result in executable if result.passed is False]

    benign_executable = [
        result
        for result in executable
        if result.category.startswith("benign_")
    ]
    benign_false_refusals = [
        result
        for result in benign_executable
        if result.expected_decision == "ALLOW"
        and result.actual_decision != "ALLOW"
    ]

    security_executable = [
        result
        for result in executable
        if not result.category.startswith("benign_")
    ]
    unsafe_allows = [
        result
        for result in security_executable
        if result.expected_decision in {"DENY", "HOLD_FOR_APPROVAL"}
        and result.actual_decision == "ALLOW"
    ]

    total = len(results)
    executable_count = len(executable)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpus_total": total,
        "control_plane_executable": executable_count,
        "model_dependent": mode_counts["model_dependent"],
        "not_yet_executable": mode_counts["not_yet_executable"],
        "coverage_percent": round((executable_count / total) * 100, 1) if total else 0.0,
        "control_plane_passed": len(passed),
        "control_plane_failed": len(failed),
        "control_plane_pass_rate_percent": (
            round((len(passed) / executable_count) * 100, 1)
            if executable_count
            else 0.0
        ),
        "benign_executable": len(benign_executable),
        "benign_false_refusals": len(benign_false_refusals),
        "unsafe_allows": len(unsafe_allows),
        "results": [asdict(result) for result in results],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Control-Plane Adversarial Baseline",
        "",
        "This report measures only corpus cases that the current deterministic "
        "control plane can honestly execute. Unexecuted model/tenant cases are "
        "reported as coverage gaps, not passes.",
        "",
        "## Summary",
        "",
        f"- Corpus cases: **{report['corpus_total']}**",
        f"- Control-plane executable: **{report['control_plane_executable']}** "
        f"({report['coverage_percent']}%)",
        f"- Model-dependent: **{report['model_dependent']}**",
        f"- Not yet executable: **{report['not_yet_executable']}**",
        f"- Control-plane passed: **{report['control_plane_passed']}**",
        f"- Control-plane failed: **{report['control_plane_failed']}**",
        f"- Control-plane pass rate: **{report['control_plane_pass_rate_percent']}%**",
        f"- Unsafe ALLOW decisions: **{report['unsafe_allows']}**",
        f"- Benign executable cases: **{report['benign_executable']}**",
        f"- Benign false refusals: **{report['benign_false_refusals']}**",
        "",
        "## Case Results",
        "",
        "| ID | Category | Mode | Expected | Actual | Result |",
        "|---|---|---|---|---|---|",
    ]

    for result in report["results"]:
        if result["passed"] is True:
            status = "PASS"
        elif result["passed"] is False:
            status = "FAIL"
        else:
            status = "NOT RUN"

        lines.append(
            f"| {result['attack_id']} | {result['category']} | "
            f"{result['mode']} | {result['expected_decision']} | "
            f"{result['actual_decision'] or '-'} | {status} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The control-plane pass rate is **not** an end-to-end AI security score.",
            "",
            "A case marked NOT RUN remains an open measurement requirement. "
            "Indirect prompt injection, grounded benign behavior, cross-user "
            "content authorization, confused-deputy behavior, and secret "
            "disclosure require the future live Copilot/tenant evaluation path.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json-output",
        default="evaluations/results/control-plane-baseline.json",
    )
    parser.add_argument(
        "--markdown-output",
        default="evaluations/results/control-plane-baseline.md",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Return non-zero when an executable control-plane case fails.",
    )
    args = parser.parse_args()

    report = run()

    json_path = ROOT / args.json_output
    markdown_path = ROOT / args.markdown_output
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")

    print(render_markdown(report))

    if args.check and report["control_plane_failed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
