#!/usr/bin/env python3
"""
Detection-as-Code (DaC) Multi-Target Transpiler & Release Packager.

Compiles Sigma YAML rules into native SIEM / XDR queries:
- Splunk SPL
- Microsoft Sentinel KQL (Kusto Query Language)
- Palo Alto Cortex XSIAM XQL
- Elasticsearch Lucene / ES|QL

Generates production release bundles (JSON & ZIP) tagged with semantic versions.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("dac-transpiler")

RELEASE_VERSION = "1.4.2"


@dataclass
class TranspiledRule:
    """Dataclass holding transpilation results across SIEM engines."""
    id: str
    title: str
    status: str
    level: str
    author: str
    mitre_tags: List[str]
    splunk_spl: str
    sentinel_kql: str
    elastic_lucene: str
    cortex_xql: str
    triage_sop: Any
    blindspots: Any
    source_file: str


class CortexXQLConverter:
    """Translates Sigma rule AST/dictionaries into Palo Alto Cortex XSIAM XQL."""

    @staticmethod
    def get_dataset(logsource: Dict[str, Any]) -> str:
        product = str(logsource.get("product", "")).lower()
        service = str(logsource.get("service", "")).lower()
        category = str(logsource.get("category", "")).lower()

        if product == "windows" or category == "process_creation":
            return "xdr_data"
        elif product == "aws" or service == "cloudtrail":
            return "cloud_audit_logs"
        elif product == "kubernetes" or service == "audit":
            return "kubernetes_audit"
        return "xdr_data"

    @classmethod
    def convert_rule(cls, rule_data: Dict[str, Any]) -> str:
        """Generates standard Cortex XSIAM XQL query."""
        logsource = rule_data.get("logsource", {})
        dataset = cls.get_dataset(logsource)
        detection = rule_data.get("detection", {})
        selection = detection.get("selection", {})

        filter_clauses: List[str] = []

        for key, val in selection.items():
            field_name = key.split("|")[0]
            if isinstance(val, list):
                # Escaped alternation
                escaped_vals = [re.escape(str(v)) for v in val]
                val_regex = "|".join(escaped_vals)
                filter_clauses.append(f'{field_name} ~= "{val_regex}"')
            else:
                escaped_val = re.escape(str(val))
                filter_clauses.append(f'{field_name} ~= "{escaped_val}"')

        combined_filter = " and ".join(filter_clauses) if filter_clauses else "true"
        return f'dataset = {dataset} | filter {combined_filter}'


class MultiTargetTranspiler:
    """Engine compiling Sigma rules into multi-SIEM targets and release bundles."""

    def __init__(self, input_dir: Path, output_dir: Path) -> None:
        self.input_dir = input_dir.resolve()
        self.output_dir = output_dir.resolve()
        self.splunk_backend = SplunkBackend()
        self.kusto_backend = KustoBackend()
        self.lucene_backend = LuceneBackend()
        self.cortex_converter = CortexXQLConverter()

    def _ensure_output_directories(self) -> Dict[str, Path]:
        """Creates target-specific distribution subdirectories."""
        targets = ["splunk", "sentinel", "elastic", "cortex"]
        paths = {}
        for target in targets:
            target_path = self.output_dir / target
            target_path.mkdir(parents=True, exist_ok=True)
            paths[target] = target_path
        return paths

    def transpile_rule(self, rule_path: Path) -> TranspiledRule:
        """Compiles a single rule file into all SIEM formats."""
        with open(rule_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
            rule_data = yaml.safe_load(raw_text)

        collection = SigmaCollection.from_yaml(raw_text)

        # Splunk conversion
        splunk_queries = self.splunk_backend.convert(collection)
        splunk_spl = splunk_queries[0] if splunk_queries else ""

        # Sentinel (Kusto) conversion
        kusto_queries = self.kusto_backend.convert(collection)
        sentinel_kql = kusto_queries[0] if kusto_queries else ""

        # Elastic Lucene conversion
        lucene_queries = self.lucene_backend.convert(collection)
        elastic_lucene = lucene_queries[0] if lucene_queries else ""

        # Palo Alto Cortex XQL conversion
        cortex_xql = self.cortex_converter.convert_rule(rule_data)

        mitre_tags = [t for t in rule_data.get("tags", []) if str(t).lower().startswith("attack.")]

        return TranspiledRule(
            id=str(rule_data.get("id", "")),
            title=str(rule_data.get("title", rule_path.stem)),
            status=str(rule_data.get("status", "stable")),
            level=str(rule_data.get("level", "medium")),
            author=str(rule_data.get("author", "")),
            mitre_tags=mitre_tags,
            splunk_spl=splunk_spl,
            sentinel_kql=sentinel_kql,
            elastic_lucene=elastic_lucene,
            cortex_xql=cortex_xql,
            triage_sop=rule_data.get("triage_sop", []),
            blindspots=rule_data.get("blindspots", []),
            source_file=str(rule_path.relative_to(self.input_dir).as_posix()),
        )

    def package_release(self, transpiled_rules: List[TranspiledRule]) -> Path:
        """Packages transpiled rules into JSON bundle and ZIP archive."""
        bundle_file = self.output_dir / "release_bundle.json"
        manifest = {
            "version": f"v{RELEASE_VERSION}",
            "generated_at": "2026-10-11T16:30:00Z",
            "rule_count": len(transpiled_rules),
            "rules": [asdict(r) for r in transpiled_rules],
        }

        with open(bundle_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        # Create zip bundle for distribution
        zip_path = self.output_dir / f"detection-bundle-v{RELEASE_VERSION}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.write(bundle_file, arcname="release_bundle.json")
            for target in ["splunk", "sentinel", "elastic", "cortex"]:
                target_dir = self.output_dir / target
                for query_file in target_dir.glob("*.*"):
                    zip_file.write(query_file, arcname=f"{target}/{query_file.name}")

        return zip_path

    def run(self) -> None:
        """Executes full transpilation and artifact publication pipeline."""
        target_dirs = self._ensure_output_directories()
        rule_files = sorted(list(self.input_dir.glob("**/*.yml")) + list(self.input_dir.glob("**/*.yaml")))

        if not rule_files:
            logger.warning(f"No rules found in {self.input_dir}")
            return

        print(f"[*] Starting Multi-Target Transpilation from '{self.input_dir}' to '{self.output_dir}'...")
        transpiled_rules: List[TranspiledRule] = []

        for rule_file in rule_files:
            rule_stem = rule_file.stem
            try:
                rule_result = self.transpile_rule(rule_file)
                transpiled_rules.append(rule_result)

                # Write Splunk SPL
                (target_dirs["splunk"] / f"{rule_stem}.spl").write_text(
                    f"# Rule: {rule_result.title} (ID: {rule_result.id})\n"
                    f"# ATT&CK: {', '.join(rule_result.mitre_tags)}\n"
                    f"{rule_result.splunk_spl}\n",
                    encoding="utf-8"
                )

                # Write Sentinel KQL
                (target_dirs["sentinel"] / f"{rule_stem}.kql").write_text(
                    f"// Rule: {rule_result.title} (ID: {rule_result.id})\n"
                    f"// ATT&CK: {', '.join(rule_result.mitre_tags)}\n"
                    f"{rule_result.sentinel_kql}\n",
                    encoding="utf-8"
                )

                # Write Elastic Lucene
                (target_dirs["elastic"] / f"{rule_stem}.lucene").write_text(
                    f"# Rule: {rule_result.title} (ID: {rule_result.id})\n"
                    f"# ATT&CK: {', '.join(rule_result.mitre_tags)}\n"
                    f"{rule_result.elastic_lucene}\n",
                    encoding="utf-8"
                )

                # Write Cortex XSIAM XQL
                (target_dirs["cortex"] / f"{rule_stem}.xql").write_text(
                    f"// Rule: {rule_result.title} (ID: {rule_result.id})\n"
                    f"// ATT&CK: {', '.join(rule_result.mitre_tags)}\n"
                    f"{rule_result.cortex_xql}\n",
                    encoding="utf-8"
                )

                print(f"[OK] {rule_file.name} -> Splunk, Sentinel, Elastic, Cortex XQL")

            except Exception as e:
                logger.error(f"Failed transpiling {rule_file.name}: {e}")
                raise

        zip_bundle = self.package_release(transpiled_rules)
        print(f"\n[SUCCESS] Compiled {len(transpiled_rules)} rules into multi-SIEM targets.")
        print(f"[ARTIFACT] Release bundle published: {zip_bundle}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-SIEM detection transpilation and packaging engine."
    )
    parser.add_argument(
        "--input-dir",
        type=str,
        default="rules",
        help="Input directory containing Sigma rules (default: 'rules')",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="build",
        help="Output directory for compiled SIEM queries and release bundles (default: 'build')",
    )
    args = parser.parse_args()

    transpiler = MultiTargetTranspiler(
        input_dir=Path(args.input_dir),
        output_dir=Path(args.output_dir),
    )
    transpiler.run()


if __name__ == "__main__":
    main()
