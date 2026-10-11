#!/usr/bin/env python3
"""
Detection-as-Code (DaC) Rule Latency & Complexity Profiler.

Evaluates regex safety (ReDoS vulnerability detection), SIEM query complexity,
and microsecond-level query execution latency against high-volume synthetic telemetry.
Enforces SIEM performance budgets before production deployment.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("dac-latency-profiler")

# Regex heuristics indicating potential catastrophic backtracking / ReDoS
REDOS_SUSPECT_PATTERNS = [
    re.compile(r"\([^)]*[\+\*]\)[*+]"),                # Nested quantifiers: (a+)+ or (a*)*
    re.compile(r"\([^)]*[\+\*]\)\{[0-9]+,\}"),          # Quantifier followed by range: (a+){2,}
    re.compile(r"(\.\*|\.\+)\s*(\.\*|\.\+)"),          # Adjacent greedy catch-alls: .*.*
    re.compile(r"\([a-zA-Z0-9_\-\s]+\|[^)]+\)[+*]"),    # Overlapping alternation under star: (a|aa)+
]


@dataclass
class RuleProfileResult:
    """Dataclass encapsulating rule profiling metrics."""
    rule_path: str
    rule_id: str
    rule_title: str
    complexity_score: int
    complexity_tier: str
    redos_risk: str
    redos_warnings: List[str]
    batch_latency_ms: float
    avg_latency_us: float
    events_profiled: int
    passed_slo: bool


class LatencyProfiler:
    """Profiles Sigma rules for query complexity and execution latency."""

    def __init__(
        self,
        latency_threshold_ms: float = 10.0,
        max_complexity_score: int = 100,
        batch_size: int = 1000,
    ) -> None:
        self.latency_threshold_ms = latency_threshold_ms
        self.max_complexity_score = max_complexity_score
        self.batch_size = batch_size

    def check_regex_safety(self, pattern_str: str) -> Tuple[str, List[str]]:
        """
        Scans a regex pattern for ReDoS vulnerabilities and catastrophic backtracking risks.
        """
        warnings: List[str] = []
        risk_level = "LOW"

        for suspect in REDOS_SUSPECT_PATTERNS:
            if suspect.search(pattern_str):
                warnings.append(
                    "Dangerous regex construction detected: possible nested or overlapping "
                    f"quantifier in '{pattern_str}'"
                )
                risk_level = "HIGH"

        # Check for unanchored wildcards with large quantifier lengths
        if ".*" in pattern_str and len(pattern_str) > 100:
            warnings.append(f"Lengthy pattern ({len(pattern_str)} chars) containing unbounded '.*'")
            if risk_level != "HIGH":
                risk_level = "MEDIUM"

        return risk_level, warnings

    def calculate_complexity_score(self, detection: Dict[str, Any]) -> Tuple[int, str, List[str]]:
        """
        Calculates an algorithmic complexity score based on SIEM search cost:
        - Base selection fields: +5
        - Wildcard / substring matches (leading wildcards trigger full table scan): +15
        - Regex pattern: +25
        - Logical conditions: +5 per operator
        """
        score = 10  # base cost
        warnings: List[str] = []
        overall_redos_risk = "LOW"

        for key, val in detection.items():
            if key == "condition":
                condition_str = str(val)
                # Count logical junctions
                for op in ["and", "or", "not"]:
                    score += condition_str.lower().count(f" {op} ") * 5
                continue

            if isinstance(val, dict):
                for f_key, f_val in val.items():
                    score += 5
                    if "|endswith" in f_key or "|startswith" in f_key:
                        score += 10
                    elif "|contains" in f_key:
                        score += 15  # Substring search (costly in inverted index)
                    elif "|re" in f_key:
                        score += 25  # Regex match
                        risk, redos_warns = self.check_regex_safety(str(f_val))
                        warnings.extend(redos_warns)
                        if risk == "HIGH":
                            overall_redos_risk = "HIGH"
                            score += 50
                        elif risk == "MEDIUM" and overall_redos_risk != "HIGH":
                            overall_redos_risk = "MEDIUM"

                    # Check values for leading wildcards
                    val_items = f_val if isinstance(f_val, list) else [f_val]
                    for item in val_items:
                        s_item = str(item)
                        if s_item.startswith("*"):
                            score += 20  # Leading wildcard penalty
                            msg = f"Leading wildcard in field '{f_key}': '{s_item}' inhibits index acceleration"
                            warnings.append(msg)

        if score < 30:
            tier = "OPTIMAL"
        elif score < 60:
            tier = "MODERATE"
        elif score <= 100:
            tier = "HIGH"
        else:
            tier = "CRITICAL_OVERHEAD"

        return score, tier, warnings

    def _generate_synthetic_telemetry(self, sample_event: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Generates a batch of synthetic log telemetry events for benchmarking."""
        events: List[Dict[str, Any]] = []
        base = sample_event or {
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "CommandLine": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s BITS",
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "User": "NT AUTHORITY\\SYSTEM",
            "ProcessId": 1024,
        }

        for i in range(self.batch_size):
            evt = dict(base)
            evt["ProcessId"] = 1000 + (i % 50000)
            evt["CommandLine"] = f"{base.get('CommandLine', '')} --instance {i}"
            events.append(evt)

        return events

    def benchmark_execution_latency(
        self,
        detection: Dict[str, Any],
        sample_event: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, float]:
        """
        Simulates evaluation against synthetic event stream and measures execution latency.
        Returns (batch_latency_ms, avg_latency_us).
        """
        events = self._generate_synthetic_telemetry(sample_event)
        selections = {k: v for k, v in detection.items() if k != "condition"}

        # High-resolution benchmark
        start_ns = time.perf_counter_ns()

        for event in events:
            # Replay selection logic against event
            for sel_name, sel_dict in selections.items():
                if not isinstance(sel_dict, dict):
                    continue
                for f_key, expected in sel_dict.items():
                    field_name = f_key.split("|")[0]
                    actual = event.get(field_name)
                    if actual is None:
                        continue
                    # Match evaluation
                    _ = str(expected).lower() in str(actual).lower()

        end_ns = time.perf_counter_ns()
        total_time_ns = end_ns - start_ns
        batch_latency_ms = total_time_ns / 1_000_000.0
        avg_latency_us = (total_time_ns / len(events)) / 1_000.0

        return round(batch_latency_ms, 3), round(avg_latency_us, 3)

    def profile_rule(self, rule_path: Path) -> RuleProfileResult:
        """Profiles a single Sigma rule file."""
        with open(rule_path, "r", encoding="utf-8") as f:
            content = yaml.safe_load(f)

        rule_id = content.get("id", "unknown-uuid")
        title = content.get("title", rule_path.name)
        detection = content.get("detection", {})

        complexity_score, tier, redos_warnings = self.calculate_complexity_score(detection)
        redos_risk = "HIGH" if any("Dangerous" in w for w in redos_warnings) else "LOW"

        batch_latency_ms, avg_latency_us = self.benchmark_execution_latency(detection)

        passed_slo = (
            batch_latency_ms <= self.latency_threshold_ms
            and complexity_score <= self.max_complexity_score
            and redos_risk != "HIGH"
        )

        return RuleProfileResult(
            rule_path=str(rule_path.as_posix()),
            rule_id=rule_id,
            rule_title=title,
            complexity_score=complexity_score,
            complexity_tier=tier,
            redos_risk=redos_risk,
            redos_warnings=redos_warnings,
            batch_latency_ms=batch_latency_ms,
            avg_latency_us=avg_latency_us,
            events_profiled=self.batch_size,
            passed_slo=passed_slo,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Profile Sigma rule latency, algorithmic complexity, and ReDoS safety."
    )
    parser.add_argument(
        "--rules-dir",
        type=str,
        default="rules",
        help="Path to Sigma rules directory (default: 'rules')",
    )
    parser.add_argument(
        "--threshold-ms",
        type=float,
        default=10.0,
        help="Maximum allowed latency per 1,000 synthetic events in ms (default: 10.0)",
    )
    parser.add_argument(
        "--max-complexity",
        type=int,
        default=100,
        help="Maximum allowable rule complexity budget (default: 100)",
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="Optional destination path for JSON profile metrics",
    )
    args = parser.parse_args()

    profiler = LatencyProfiler(
        latency_threshold_ms=args.threshold_ms,
        max_complexity_score=args.max_complexity,
    )

    rules_path = Path(args.rules_dir)
    rule_files = sorted(list(rules_path.glob("**/*.yml")) + list(rules_path.glob("**/*.yaml")))

    print(f"[*] Profiling {len(rule_files)} rules for Latency & Query Cost (SLO Threshold: {args.threshold_ms}ms)...")
    print(f"{'Rule Title':<45} | {'Score':<6} | {'Tier':<10} | {'Batch Latency':<14} | {'Status'}")
    print("-" * 90)

    results: List[RuleProfileResult] = []
    failed_count = 0

    for rule_file in rule_files:
        res = profiler.profile_rule(rule_file)
        results.append(res)

        status_str = "PASS" if res.passed_slo else "FAIL (SLO Violated)"
        if not res.passed_slo:
            failed_count += 1

        print(
            f"{res.rule_title[:43]:<45} | "
            f"{res.complexity_score:<6} | "
            f"{res.complexity_tier:<10} | "
            f"{res.batch_latency_ms:<5} ms      | "
            f"{status_str}"
        )

        for w in res.redos_warnings:
            print(f"    [WARN] {w}")

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as jf:
            json.dump([asdict(r) for r in results], jf, indent=2)
        print(f"\n[*] Profiling report exported to {args.json_output}")

    if failed_count > 0:
        print(f"\n[ERROR] {failed_count} rule(s) failed performance and complexity budget requirements!")
        sys.exit(1)
    else:
        print(f"\n[SUCCESS] All {len(rule_files)} rules passed latency and complexity profiling!")
        sys.exit(0)


if __name__ == "__main__":
    main()
