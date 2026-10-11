"""
Regression test suite asserting rules fire on True Positive telemetry
and produce zero alerts on False Positive benign baselines.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from pipeline.latency_profiler import LatencyProfiler


def evaluate_simple_detection(rule_data: dict, log_event: dict) -> bool:
    """Evaluates whether a mock log event matches process creation rule logic."""
    detection = rule_data.get("detection", {})
    selection = detection.get("selection", {})

    for key, expected_val in selection.items():
        # Support both direct key lookup and field modifier stripping
        actual_val = log_event.get(key)
        if actual_val is None and "|" in key:
            actual_val = log_event.get(key.split("|")[0])

        if actual_val is None:
            return False

        if isinstance(expected_val, list):
            if not any(
                re.search(re.escape(str(item)), str(actual_val), re.IGNORECASE)
                for item in expected_val
            ):
                return False
        else:
            if not re.search(re.escape(str(expected_val)), str(actual_val), re.IGNORECASE):
                return False

    return True


def test_true_positive_lsass_dump():
    """Verifies LSASS memory dump detection triggers on synthetic True Positive event."""
    rule_path = Path("rules/windows/proc_creation_win_lsass_dump.yml")
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    # Synthetic True Positive Event
    tp_event = {
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    }

    assert evaluate_simple_detection(rule, tp_event) is True, "Rule failed to alert on True Positive LSASS dump!"


def test_false_positive_benign_rundll32():
    """Verifies LSASS memory dump detection yields zero alerts on benign rundll32 baseline."""
    rule_path = Path("rules/windows/proc_creation_win_lsass_dump.yml")
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    # Synthetic False Positive Event (Legitimate Windows print spooler)
    fp_event = {
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32.exe printui.dll,PrintUIEntry /?",
        "ParentImage": "C:\\Windows\\explorer.exe",
    }

    assert evaluate_simple_detection(rule, fp_event) is False, "Rule fired on benign rundll32 baseline!"


def test_true_positive_telemetry_file_lsass():
    """Asserts curated JSON file tp_lsass_comsvcs.json triggers detection."""
    rule_path = Path("rules/windows/proc_creation_win_lsass_dump.yml")
    telemetry_path = Path("telemetry_samples/true_positives/tp_lsass_comsvcs.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is True, "Failed to alert on curated tp_lsass_comsvcs.json!"


def test_false_positive_telemetry_file_printui():
    """Asserts curated JSON file fp_printui_rundll32.json produces zero alerts."""
    rule_path = Path("rules/windows/proc_creation_win_lsass_dump.yml")
    telemetry_path = Path("telemetry_samples/false_positives/fp_printui_rundll32.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is False, (
        "False positive alert triggered on fp_printui_rundll32.json!"
    )


def test_true_positive_office_spawning_powershell():
    """Asserts Office spawning PowerShell detection triggers on weaponized macro execution."""
    rule_path = Path("rules/windows/proc_creation_win_office_spawning_powershell.yml")
    telemetry_path = Path("telemetry_samples/true_positives/tp_office_pwsh.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is True, "Failed to detect Office spawning PowerShell!"


def test_false_positive_office_rule_against_sccm():
    """Asserts Office spawning PowerShell detection stays silent on IT SCCM maintenance script."""
    rule_path = Path("rules/windows/proc_creation_win_office_spawning_powershell.yml")
    telemetry_path = Path("telemetry_samples/false_positives/fp_it_sccm_script.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is False, "False positive fired on IT SCCM script!"


def test_true_positive_aws_iam_keys():
    """Asserts AWS CloudTrail detection fires on unauthorized IAM access key creation."""
    rule_path = Path("rules/cloud/aws_iam_backdoor_user_keys.yml")
    telemetry_path = Path("telemetry_samples/true_positives/tp_aws_iam_access_key.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is True, "Failed to alert on AWS IAM CreateAccessKey TP!"


def test_false_positive_aws_terraform():
    """Asserts AWS CloudTrail detection produces zero alerts on routine EC2 DescribeInstances."""
    rule_path = Path("rules/cloud/aws_iam_backdoor_user_keys.yml")
    telemetry_path = Path("telemetry_samples/false_positives/fp_aws_iam_terraform.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is False, "False positive fired on AWS Terraform telemetry!"


def test_true_positive_k8s_exec():
    """Asserts Kubernetes detection triggers on interactive container exec audit event."""
    rule_path = Path("rules/container/k8s_container_interactive_shell.yml")
    telemetry_path = Path("telemetry_samples/true_positives/tp_k8s_container_exec.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is True, "Failed to alert on K8s container exec TP!"


def test_false_positive_k8s_readiness():
    """Asserts Kubernetes detection produces zero alerts on routine kubelet status probe."""
    rule_path = Path("rules/container/k8s_container_interactive_shell.yml")
    telemetry_path = Path("telemetry_samples/false_positives/fp_k8s_readiness_probe.json")

    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    with open(telemetry_path, "r", encoding="utf-8") as f:
        event = json.load(f)

    assert evaluate_simple_detection(rule, event) is False, "False positive fired on K8s readiness probe!"


def test_rule_performance_and_latency_budgets():
    """Profiles all rules to assert SOC query latency < 10ms and complexity budget <= 100."""
    profiler = LatencyProfiler(latency_threshold_ms=10.0, max_complexity_score=100)
    rule_files = list(Path("rules").glob("**/*.yml"))

    assert len(rule_files) > 0, "No rules discovered for profiling!"

    for rule_file in rule_files:
        profile = profiler.profile_rule(rule_file)
        assert profile.passed_slo is True, (
            f"Rule {rule_file.name} violated SOC SLO budget! "
            f"Latency: {profile.batch_latency_ms}ms, Complexity: {profile.complexity_score}, "
            f"ReDoS: {profile.redos_risk}"
        )
