"""
Tests ADS (Alerting and Detection Strategy) engineering standard compliance
and MITRE ATT&CK taxonomy conformance for all Sigma rules.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import List

import pytest
import yaml

from pipeline.validator import (
    ALLOWED_LEVELS,
    ALLOWED_STATUSES,
    REQUIRED_ADS_FIELDS,
    validate_mitre_tags,
    validate_rule,
)


def get_all_rule_paths() -> List[Path]:
    """Discovers all Sigma rule YAML files in the repository."""
    rules_dir = Path("rules")
    return sorted(list(rules_dir.glob("**/*.yml")) + list(rules_dir.glob("**/*.yaml")))


@pytest.mark.parametrize("rule_path", get_all_rule_paths(), ids=lambda p: p.name)
def test_rule_schema_validation(rule_path: Path):
    """Asserts that each rule passes strict ADS validator logic without errors."""
    errors = validate_rule(rule_path, base_dir=Path("rules"))
    assert not errors, f"Rule {rule_path.name} failed ADS validation:\n" + "\n".join(f" - {e}" for e in errors)


@pytest.mark.parametrize("rule_path", get_all_rule_paths(), ids=lambda p: p.name)
def test_rule_unique_rfc4122_uuid(rule_path: Path):
    """Asserts that each rule defines a valid RFC 4122 UUID."""
    with open(rule_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rule_id = data.get("id")
    assert rule_id is not None, f"Rule {rule_path.name} is missing an 'id' field"
    parsed_uuid = uuid.UUID(rule_id)
    assert str(parsed_uuid).lower() == rule_id.lower(), f"UUID '{rule_id}' is not canonically formatted"


@pytest.mark.parametrize("rule_path", get_all_rule_paths(), ids=lambda p: p.name)
def test_rule_mitre_attack_tagging(rule_path: Path):
    """Asserts that each rule contains valid MITRE ATT&CK technique tags."""
    with open(rule_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    tags = data.get("tags", [])
    errors = validate_mitre_tags(tags)
    assert not errors, f"Rule {rule_path.name} failed MITRE ATT&CK validation:\n" + "\n".join(f" - {e}" for e in errors)


@pytest.mark.parametrize("rule_path", get_all_rule_paths(), ids=lambda p: p.name)
def test_rule_ads_metadata_fields(rule_path: Path):
    """Asserts presence and non-emptiness of all ADS core metadata fields."""
    with open(rule_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    for field in REQUIRED_ADS_FIELDS:
        assert field in data, f"Rule {rule_path.name} is missing mandatory ADS field: '{field}'"
        assert data[field] is not None, f"Mandatory ADS field '{field}' cannot be null in {rule_path.name}"
        if isinstance(data[field], (str, list, dict)):
            assert len(data[field]) > 0, f"Mandatory ADS field '{field}' cannot be empty in {rule_path.name}"

    assert data["level"].lower() in ALLOWED_LEVELS, f"Invalid level '{data['level']}' in {rule_path.name}"
    assert data["status"].lower() in ALLOWED_STATUSES, f"Invalid status '{data['status']}' in {rule_path.name}"


def test_no_duplicate_rule_uuids():
    """Asserts that all rules have globally unique UUIDs."""
    rule_paths = get_all_rule_paths()
    seen_ids = {}

    for path in rule_paths:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        rule_id = data.get("id")
        assert rule_id not in seen_ids, f"Duplicate UUID '{rule_id}' found in {path.name} and {seen_ids[rule_id]}"
        seen_ids[rule_id] = path.name
