#!/usr/bin/env python3
"""
Detection-as-Code (DaC) Schema & ADS Metadata Validator.

Validates that every Sigma rule conforms to strict Alerting and Detection
Strategy (ADS) engineering standards, MITRE ATT&CK tagging guidelines (v14+),
and YAML schema integrity before merging into production.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger("dac-validator")

# Standard ADS mandatory fields
REQUIRED_ADS_FIELDS: List[str] = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "references",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "blindspots",
    "triage_sop",
]

ALLOWED_STATUSES: Set[str] = {
    "experimental",
    "test",
    "stable",
    "deprecated"
}

ALLOWED_LEVELS: Set[str] = {
    "informational",
    "low",
    "medium",
    "high",
    "critical"
}

MITRE_TECHNIQUE_PATTERN: re.Pattern[str] = re.compile(
    r"^attack\.t(1\d{3}|[0-9]{4})(\.[0-9]{3})?$",
    re.IGNORECASE
)

VALID_MITRE_TACTICS: Set[str] = {
    "attack.reconnaissance",
    "attack.resource_development",
    "attack.initial_access",
    "attack.execution",
    "attack.persistence",
    "attack.privilege_escalation",
    "attack.defense_evasion",
    "attack.credential_access",
    "attack.discovery",
    "attack.lateral_movement",
    "attack.collection",
    "attack.command_and_control",
    "attack.exfiltration",
    "attack.impact",
}


class RuleValidationError(Exception):
    """Custom exception raised when rule validation fails."""
    pass


def validate_uuid(rule_id: Any) -> Optional[str]:
    """Validates that rule ID is a valid RFC 4122 UUID."""
    if not isinstance(rule_id, str):
        return f"Rule ID must be a string UUID, got {type(rule_id).__name__}"
    try:
        val = uuid.UUID(rule_id)
        if str(val).lower() != rule_id.lower():
            return f"Rule ID '{rule_id}' is not a canonically formatted UUID"
    except (ValueError, AttributeError, TypeError):
        return f"Rule ID '{rule_id}' is not a valid UUID"
    return None


def validate_mitre_tags(tags: Any) -> List[str]:
    """
    Validates MITRE ATT&CK technique and tactic tags.
    Requires at least one valid ATT&CK technique tag (e.g. attack.t1003.001).
    """
    errors: List[str] = []
    if not isinstance(tags, list) or not tags:
        return ["'tags' must be a non-empty list of tags including MITRE ATT&CK techniques"]

    has_attack_technique = False
    for tag in tags:
        if not isinstance(tag, str):
            errors.append(f"Invalid tag entry: {tag} (must be a string)")
            continue

        tag_lower = tag.lower()
        if tag_lower.startswith("attack.t"):
            if MITRE_TECHNIQUE_PATTERN.match(tag_lower):
                has_attack_technique = True
            else:
                errors.append(
                    f"Malformed MITRE ATT&CK technique tag: '{tag}'. "
                    f"Expected format: 'attack.t1003' or 'attack.t1003.001'"
                )
        elif tag_lower.startswith("attack."):
            if tag_lower not in VALID_MITRE_TACTICS:
                errors.append(f"Unrecognized MITRE ATT&CK tactic tag: '{tag}'")

    if not has_attack_technique:
        errors.append("Rule is missing a valid MITRE ATT&CK technique tag (e.g. 'attack.t1003.001')")

    return errors


def validate_detection_block(detection: Any) -> List[str]:
    """Validates structure and condition integrity of detection definition."""
    errors: List[str] = []
    if not isinstance(detection, dict):
        return ["'detection' block must be a dictionary"]

    condition = detection.get("condition")
    if not condition or not isinstance(condition, str):
        errors.append("Detection block must define a string 'condition'")
        return errors

    # Check for at least one selection / filter
    keys = [k for k in detection.keys() if k != "condition"]
    if not keys:
        errors.append("Detection block must contain at least one selection or filter definition")

    return errors


def validate_rule(file_path: Path, base_dir: Optional[Path] = None) -> List[str]:
    """
    Validates a single Sigma rule against ADS engineering and security standards.

    Args:
        file_path: Path to YAML rule file.
        base_dir: Optional base directory to enforce path containment.

    Returns:
        List of validation error messages (empty if valid).
    """
    errors: List[str] = []

    # Path traversal and existence check
    try:
        resolved_path = file_path.resolve()
        if base_dir:
            resolved_base = base_dir.resolve()
            if not resolved_path.is_relative_to(resolved_base):
                return [f"Security Violation: Rule path {file_path} escapes boundary {base_dir}"]
    except Exception as e:
        return [f"Path resolution error for {file_path}: {e}"]

    if not resolved_path.is_file():
        return [f"File does not exist: {file_path}"]

    # Safe YAML parsing
    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            content = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML Syntax Error: {e}"]
    except Exception as e:
        return [f"File read error: {e}"]

    if not isinstance(content, dict):
        return ["Invalid Sigma file structure: Root element must be a YAML mapping (dict)"]

    # Mandatory ADS fields verification
    for field in REQUIRED_ADS_FIELDS:
        if field not in content or content[field] is None:
            errors.append(f"Missing mandatory ADS field: '{field}'")
        elif isinstance(content[field], (str, list, dict)) and len(content[field]) == 0:
            errors.append(f"Mandatory ADS field '{field}' cannot be empty")

    # UUID validation
    if "id" in content and content["id"]:
        uuid_err = validate_uuid(content["id"])
        if uuid_err:
            errors.append(uuid_err)

    # Status check
    status = content.get("status")
    if status and str(status).lower() not in ALLOWED_STATUSES:
        errors.append(f"Invalid status '{status}'. Must be one of {sorted(ALLOWED_STATUSES)}")

    # Severity level check
    level = content.get("level")
    if level and str(level).lower() not in ALLOWED_LEVELS:
        errors.append(f"Invalid severity level '{level}'. Must be one of {sorted(ALLOWED_LEVELS)}")

    # References check
    references = content.get("references")
    if references is not None and not isinstance(references, list):
        errors.append("'references' must be a list of URLs or documentation strings")

    # False positives check
    falsepositives = content.get("falsepositives")
    if falsepositives is not None and not isinstance(falsepositives, list):
        errors.append("'falsepositives' must be a list of expected benign operational scenarios")

    # Blindspots check (ADS requirement)
    blindspots = content.get("blindspots")
    if blindspots is not None and not isinstance(blindspots, list):
        errors.append("'blindspots' must be a list of known evasion techniques or coverage gaps")

    # Triage SOP check (ADS requirement)
    triage_sop = content.get("triage_sop")
    if triage_sop is not None and not isinstance(triage_sop, (list, str)):
        errors.append("'triage_sop' must be an actionable list or procedure string for SOC triage")

    # MITRE ATT&CK validation
    tags = content.get("tags")
    if tags is not None:
        errors.extend(validate_mitre_tags(tags))

    # Logsource validation
    logsource = content.get("logsource")
    if isinstance(logsource, dict):
        if not any(k in logsource for k in ("category", "product", "service")):
            errors.append("Logsource must define at least one of 'category', 'product', or 'service'")
    else:
        errors.append("'logsource' must be a dictionary specifying category, product, or service")

    # Detection logic validation
    detection = content.get("detection")
    if detection is not None:
        errors.extend(validate_detection_block(detection))

    return errors


def parse_arguments() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate Sigma detection rules against ADS and ATT&CK standards."
    )
    parser.add_argument(
        "--rules-dir",
        type=str,
        default="rules",
        help="Directory containing Sigma YAML rule files (default: 'rules')",
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="Optional path to output validation results as JSON",
    )
    return parser.parse_args()


def main() -> None:
    """Main CLI entrypoint for rule validation."""
    args = parse_arguments()
    rules_dir = Path(args.rules_dir)

    if not rules_dir.exists():
        logger.error(f"Target directory does not exist: {rules_dir}")
        sys.exit(1)

    print(f"[*] Starting Detection-as-Code Rule Validation in '{rules_dir}'...")

    total_rules = 0
    total_errors = 0
    results: Dict[str, Any] = {"passed": [], "failed": []}

    rule_files = sorted(list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml")))

    for yml_file in rule_files:
        total_rules += 1
        errs = validate_rule(yml_file, base_dir=rules_dir)
        rel_path = str(yml_file.as_posix())

        if errs:
            total_errors += len(errs)
            print(f"[FAIL] {rel_path}:")
            for e in errs:
                print(f"   - {e}")
            results["failed"].append({"rule": rel_path, "errors": errs})
        else:
            print(f"[PASS] {rel_path}")
            results["passed"].append(rel_path)

    if args.json_output:
        try:
            with open(args.json_output, "w", encoding="utf-8") as jf:
                json.dump(results, jf, indent=2)
            print(f"[*] Report saved to {args.json_output}")
        except Exception as e:
            logger.error(f"Failed to write JSON output: {e}")

    if total_rules == 0:
        print("[WARN] No Sigma YAML rule files discovered to validate.")
        sys.exit(0)

    if total_errors > 0:
        print(f"\n[ERROR] Validation failed with {total_errors} error(s) across {total_rules} rule(s).")
        sys.exit(1)
    else:
        print(f"\n[SUCCESS] All {total_rules} detection rules passed schema & ADS verification!")
        sys.exit(0)


if __name__ == "__main__":
    main()
