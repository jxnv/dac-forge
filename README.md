# Detection-as-Code Forge (`dac-forge`)

[![CI/CD Pipeline](https://github.com/jxnv/detection-as-code-forge/actions/workflows/dac-ci.yml/badge.svg)](https://github.com/jxnv/detection-as-code-forge/actions/workflows/dac-ci.yml)
[![Version](https://img.shields.io/badge/version-v1.4.2-blue.svg)](pyproject.toml)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14%2B-orange.svg)](https://attack.mitre.org/)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://python.org)
[![Security Standard](https://img.shields.io/badge/Framework-Palantir%20ADS-green.svg)](https://blog.palantir.com/alerting-and-detection-strategy-framework-527e69ae0c40)

An institutional-grade **Detection-as-Code (DaC)** lifecycle repository and CI/CD automation engine. `dac-forge` bridges the gap between software engineering discipline and security operations center (SOC) detection development by implementing schema validation, synthetic telemetry replay, query latency benchmarking, and automated multi-target SIEM transpilation.

---

## 1. System Architecture & CI/CD Pipeline Flow

```
  +-----------------------------------------------------------------------------+
  | DEVELOPER WORKFLOW (Local Git Branch)                                       |
  |  - Detection Engineer drafts or tunes rule: `rules/windows/proc_t1003.yml`  |
  |  - Attaches synthetic True Positive & False Positive log samples            |
  |  - Submits Pull Request to `main` branch                                    |
  +--------------------------------------+--------------------------------------+
                                         |
                                         | (git push / PR trigger)
                                         v
  +-----------------------------------------------------------------------------+
  | GITHUB ACTIONS CI/CD ENGINE (`.github/workflows/dac-ci.yml`)                 |
  |                                                                             |
  |  [PHASE 1: STATIC LINTING & SCHEMA VALIDATION]                              |
  |   - Enforces YAML syntax integrity (yamllint)                               |
  |   - Validates MITRE ATT&CK technique IDs (v14+)                             |
  |   - Asserts ADS (Alerting and Detection Strategy) metadata:                 |
  |     (Title, Author, Severity, Description, Blindspots, Triage SOP)          |
  |                                      |                                      |
  |                                      v (Pass)                               |
  |  [PHASE 2: SYNTHETIC TELEMETRY REPLAY & REGRESSION TESTING]                 |
  |   - Replays True Positive log samples  ==> MUST TRIGGER RULE (Assertion)    |
  |   - Replays False Positive log samples ==> MUST NOT TRIGGER (Zero FP check) |
  |   - Measures rule query latency & complexity score (ReDoS safeguards)       |
  |                                      |                                      |
  |                                      v (Pass)                               |
  |  [PHASE 3: AUTOMATED MULTI-TARGET TRANSPILATION (pySigma Engine)]           |
  |   - Compiles Sigma YAML -> Splunk SPL                                       |
  |   - Compiles Sigma YAML -> Microsoft Sentinel KQL                           |
  |   - Compiles Sigma YAML -> Palo Alto Cortex XSIAM XQL                       |
  |   - Compiles Sigma YAML -> Elastic Lucene / ES|QL                           |
  |                                      |                                      |
  |                                      v (Pass)                               |
  |  [PHASE 4: RELEASE PACKAGING & ARTIFACT PUBLISHING]                         |
  |   - Generates production JSON/ZIP distribution bundles                      |
  |   - Tags releases (Semantic Versioning: v1.4.2)                             |
  |   - Publishes build artifacts for automated SIEM API sync                   |
  +-----------------------------------------------------------------------------+
```

---

## 2. Alerting and Detection Strategy (ADS) Standard

Every detection rule in `rules/` is engineered in accordance with the **Palantir ADS Framework** and requires:
1. **Unique Identification**: RFC 4122 Canonical UUID (`id`).
2. **Metadata Context**: `title`, `author`, `date`, `modified`, `status`, `level`.
3. **MITRE ATT&CK Mapping**: Mandatory technique tag (`attack.tXXXX[.YYY]`) conforming to ATT&CK v14+.
4. **Logsource Scoping**: Explicit `category`, `product`, or `service`.
5. **Detection Logic**: Deterministic `selection` criteria and `condition` tree.
6. **False Positives**: Concrete operational baseline scenarios where alerts could be benign.
7. **ADS Blindspots**: Documented adversary evasion techniques, logging gaps, or unmonitored channels.
8. **ADS Triage SOP**: Sequenced, actionable investigation steps for Tier 1-3 SOC analysts.

---

## 3. Repository Structure

```
detection-as-code-forge/
├── .github/
│   └── workflows/
│       └── dac-ci.yml              # Complete 3-stage GitHub Actions workflow
├── rules/
│   ├── windows/                    # Production ATT&CK-mapped Windows Sigma rules
│   │   ├── proc_creation_win_lsass_dump.yml
│   │   └── proc_creation_win_office_spawning_powershell.yml
│   ├── cloud/                      # AWS CloudTrail & Okta Sigma rules
│   │   └── aws_iam_backdoor_user_keys.yml
│   └── container/                  # K8s container exec Sigma rules
│       └── k8s_container_interactive_shell.yml
├── telemetry_samples/
│   ├── true_positives/             # Curated JSON log events that MUST alert
│   │   ├── tp_lsass_comsvcs.json
│   │   ├── tp_office_pwsh.json
│   │   ├── tp_aws_iam_access_key.json
│   │   └── tp_k8s_container_exec.json
│   └── false_positives/            # Curated benign enterprise baseline logs
│       ├── fp_printui_rundll32.json
│       ├── fp_it_sccm_script.json
│       ├── fp_aws_iam_terraform.json
│       └── fp_k8s_readiness_probe.json
├── pipeline/
│   ├── __init__.py
│   ├── validator.py                # Schema & ADS metadata linting engine
│   ├── latency_profiler.py         # Evaluates regex complexity & query execution cost
│   └── transpile.py                # Multi-SIEM pySigma translation & packaging script
├── tests/
│   ├── __init__.py
│   ├── test_rule_execution.py      # Automated true/false positive regression runner
│   └── test_schema_conformance.py  # Tests ADS standard compliance
├── pyproject.toml                  # Packaging and pytest configuration
├── requirements.txt                # Production dependencies
├── requirements-test.txt           # Test harness and linting dependencies
└── README.md                       # Architecture & execution documentation
```

---

## 4. Quickstart: Step-by-Step Build & Local Execution

### Step 1: Clone Repository & Install Dependencies
```bash
git clone https://github.com/jxnv/detection-as-code-forge.git
cd detection-as-code-forge
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-test.txt
```

### Step 2: Validate Schema and Syntax Locally
Executes static schema verification and enforces ADS metadata requirements:
```bash
python3 pipeline/validator.py --rules-dir rules/
```

### Step 3: Run Latency & Algorithmic Complexity Profiling
Benchmarks rule execution times against high-volume synthetic telemetry streams and checks for ReDoS vulnerabilities:
```bash
python3 pipeline/latency_profiler.py --rules-dir rules/ --threshold-ms 10.0 --max-complexity 100
```

### Step 4: Run Synthetic Regression Testing
Executes unit tests verifying that all true positives alert and all benign baselines yield zero false positives:
```bash
python3 -m pytest tests/test_rule_execution.py tests/test_schema_conformance.py -v
```

### Step 5: Execute Multi-Target Transpilation & Packaging
Compiles all rules to Splunk SPL, Sentinel KQL, Cortex XQL, and Elastic Lucene, outputting production release bundles:
```bash
python3 pipeline/transpile.py --input-dir rules/ --output-dir build/
```

Inspect the generated distribution artifacts:
- `build/splunk/*.spl` — Splunk SPL queries
- `build/sentinel/*.kql` — Microsoft Sentinel KQL queries
- `build/elastic/*.lucene` — Elasticsearch queries
- `build/cortex/*.xql` — Palo Alto Cortex XSIAM XQL queries
- `build/release_bundle.json` — Aggregated manifest with queries and ADS metadata
- `build/detection-bundle-v1.4.2.zip` — Compressed release bundle ready for SIEM API deployment

### Step 6: Git Workflow
```bash
git checkout -b feature/new-lsass-detection
git add .
git commit -m "feat(detection): added T1003.001 LSASS mini dump detection with synthetic tests"
git push origin feature/new-lsass-detection
```

---

## 5. Security & Engineering Best Practices

- **Safe YAML Deserialization**: Uses `yaml.safe_load()` exclusively across all scripts to prevent arbitrary Python object execution vulnerabilities.
- **Path Traversal Protection**: All file path access in `pipeline/validator.py` and `pipeline/transpile.py` validates path containment against root boundary directories.
- **ReDoS Mitigation**: Regex expressions are statically analyzed for catastrophic backtracking (nested quantifiers, overlapping alternations) before reaching SIEM deployment.
- **Zero FP Assurance**: CI/CD gate halts immediately if a benign enterprise baseline log triggers an alert.
- **Strict Typing & Linting**: All codebase modules leverage Python type hints (`from __future__ import annotations`), pass strict Flake8 formatting (`--max-line-length=120`), and adhere to Yamllint schemas.
