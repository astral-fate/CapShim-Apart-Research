"""Run the evaluation suite and print the headline metrics.

Usage:
    python -m evals.run_evals

Produces:
    * attack table (true positive rate)
    * benign table (false positive rate)
    * latency summary (median ms per call)
    * writes evals/results.json for the paper to read
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

# Ensure src/ is on the path when run directly.
_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from capshim.policy import load_policy  # noqa: E402
from capshim.proxy import CapShimProxy  # noqa: E402
from capshim.schema import ToolSchema  # noqa: E402
from examples.servers.toy_mcp_server import tool_schemas  # noqa: E402
from evals.scenarios import all_scenarios  # noqa: E402


def build_proxy() -> CapShimProxy:
    policy = load_policy(_REPO / "examples" / "policy.yaml")
    tools = {t["name"]: ToolSchema.from_json(t) for t in tool_schemas()}
    return CapShimProxy(tools=tools, policy=policy)


def main() -> int:
    proxy = build_proxy()

    rows: list[dict] = []
    latencies: list[float] = []
    correct = 0
    for scenario in all_scenarios():
        t0 = time.perf_counter()
        verdict = proxy.check(scenario.plan)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dt_ms)
        actual = "allow" if verdict.allow else "deny"
        ok = actual == scenario.expect
        correct += int(ok)
        rows.append(
            {
                "name": scenario.name,
                "expect": scenario.expect,
                "actual": actual,
                "ok": ok,
                "latency_ms": dt_ms,
                "reason": verdict.reason(),
                "note": scenario.note,
            }
        )

    total = len(rows)
    attacks = [r for r in rows if r["expect"] == "deny"]
    benign = [r for r in rows if r["expect"] == "allow"]
    tp = sum(1 for r in attacks if r["actual"] == "deny")
    tn = sum(1 for r in benign if r["actual"] == "allow")
    median_latency = statistics.median(latencies)
    p95_latency = sorted(latencies)[max(0, int(0.95 * len(latencies)) - 1)]

    summary = {
        "total_scenarios": total,
        "attacks": len(attacks),
        "benign": len(benign),
        "attacks_blocked": tp,
        "benign_allowed": tn,
        "true_positive_rate": tp / max(1, len(attacks)),
        "false_positive_rate": (len(benign) - tn) / max(1, len(benign)),
        "median_latency_ms": median_latency,
        "p95_latency_ms": p95_latency,
        "overall_correct": correct,
        "rows": rows,
    }

    # Pretty-print
    print(f"{'name':<40} {'expect':<7} {'actual':<7} {'ok':<5} {'ms':>7}")
    print("-" * 70)
    for r in rows:
        print(
            f"{r['name']:<40} {r['expect']:<7} {r['actual']:<7} "
            f"{'Y' if r['ok'] else 'N':<5} {r['latency_ms']:>7.3f}"
        )
    print()
    print("=" * 70)
    print(f"Attacks blocked: {tp}/{len(attacks)}  (TPR = {summary['true_positive_rate']:.0%})")
    print(f"Benign allowed:  {tn}/{len(benign)}  (FPR = {summary['false_positive_rate']:.0%})")
    print(f"Median latency:  {median_latency:.3f} ms")
    print(f"P95 latency:     {p95_latency:.3f} ms")
    print("=" * 70)

    out_path = _REPO / "evals" / "results.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nresults written to {out_path}")

    # Exit non-zero if any scenario failed its expected verdict.
    return 0 if correct == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
