# Compliance Automation

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![SOC2](https://img.shields.io/badge/SOC_2_Type_II-4A154B?style=flat-square&logoColor=white)
![ISO27001](https://img.shields.io/badge/ISO_27001%3A2022-0066CC?style=flat-square&logoColor=white)
![NIST](https://img.shields.io/badge/NIST_SP_800--53-003087?style=flat-square&logoColor=white)
![PCI DSS](https://img.shields.io/badge/PCI--DSS_v4-FF6B00?style=flat-square&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**Six production-ready Python scripts for automated compliance scanning, evidence collection, access reviews, and vulnerability SLA tracking — covering SOC 2, ISO 27001:2022, and PCI-DSS v4.0.**

</div>

---

## Overview

Manual compliance is expensive, inconsistent, and doesn't scale. This repository provides the tooling to **automate evidence collection, continuous control monitoring, and compliance gap reporting** across the most common regulatory frameworks.

Built for security engineers and GRC teams that want to move from spreadsheet-driven compliance to **code-driven, auditable, repeatable programs.**

Every script:
- Accepts a `--config <yaml>` file for environment-specific inputs
- Produces structured **JSON output** ready for SIEM ingestion or GRC platform import
- Ships with a self-contained **sample config** so it runs out of the box
- Uses the same `dataclass` / `Enum` pattern for consistency across tools

---

## Repository Structure

```
compliance-automation/
│
└── scripts/
    ├── soc2_control_scanner.py       # SOC 2 TSC automated control checks (CC6–CC9)
    ├── iso27001_gap_analyzer.py      # ISO 27001:2022 Annex A + clause gap analysis
    ├── pci_dss_scope_mapper.py       # PCI-DSS v4.0 CDE scope mapper + all 12 requirements
    ├── evidence_collector.py         # Automated evidence collection with SHA-256 manifest
    ├── access_review_automation.py   # Quarterly access review workflow & risk flagging
    └── vulnerability_compliance.py   # Vulnerability SLA compliance tracker & MTTR
```

---

## Scripts

### 1. `soc2_control_scanner.py` — SOC 2 Trust Services Criteria Scanner

Checks your environment configuration against 10 SOC 2 CC controls spanning logical access, system monitoring, vulnerability management, incident response, change management, and vendor risk.

**Controls covered**

| Control ID | TSC Category | Description |
|---|---|---|
| CC6.1-01 | CC6.1 | MFA enforced for privileged accounts |
| CC6.1-02 | CC6.1 | Encryption at rest for production data |
| CC6.2-01 | CC6.2 | Formal access provisioning & quarterly review |
| CC6.3-01 | CC6.3 | Access revocation SLA on termination |
| CC6.4-01 | CC6.4 | Least privilege / RBAC enforcement |
| CC7.2-01 | CC7.2 | SIEM & security monitoring |
| CC7.3-01 | CC7.3 | Vulnerability management & patch SLA |
| CC7.4-01 | CC7.4 | Incident response plan & testing |
| CC8.1-01 | CC8.1 | Change management process |
| CC9.1-01 | CC9.1 | Vendor / third-party risk management |

**Usage**

```bash
python3 soc2_control_scanner.py --config config.yaml --output soc2_report.json
```

**Sample output**

```
============================================================
SOC 2 COMPLIANCE SCAN REPORT
============================================================
Compliance Score:  90.0%
Controls Passed:   9/10
Warnings:          1
Critical Findings: 1
============================================================
Full report saved to soc2_report.json
```

**Config keys**

```yaml
iam:
  mfa_enforced_for_admins: true
  privileged_accounts_without_mfa: []
  formal_provisioning_process: true
  days_since_last_access_review: 45
  offboarding_sla_hours: 24
  avg_account_revocation_hours: 12
  rbac_implemented: true
  users_with_excessive_access: 3
  total_users: 150
monitoring:
  siem_enabled: true
  active_alert_rules: 87
  log_retention_days: 365
vulnerability_mgmt:
  scan_frequency_days: 7
  critical_patch_sla_days: 15
  overdue_critical_vulns: 0
incident_response:
  ir_plan_documented: true
  days_since_last_tabletop: 180
  incident_tracking_tool: Jira
change_management:
  formal_process_documented: true
  pct_changes_with_approval: 98
  prod_deploy_requires_review: true
vendor_risk:
  vendor_inventory_maintained: true
  pct_vendors_with_contracts: 100
  annual_vendor_review_conducted: true
```

---

### 2. `iso27001_gap_analyzer.py` — ISO 27001:2022 Gap Analyzer

Analyzes your control implementation against ISO 27001:2022 mandatory clauses (4–10) and Annex A controls across all four themes. Produces a maturity score, theme-by-theme breakdown, and prioritized remediation actions.

**Coverage**

| Theme | Controls Checked | Example Checks |
|---|---|---|
| Organizational | 7 | Context doc, SoA, risk register, ISMS policy, threat intel, asset inventory, data classification |
| People | 3 | Security awareness training, background screening, remote working controls |
| Physical | 1 | Physical security perimeter, CCTV, visitor logs |
| Technological | 3 | MDM / endpoint management, secure SDLC + app testing, network segmentation |

Status values: `IMPLEMENTED` | `PARTIAL` | `NOT_IMPLEMENTED` | `N/A`

Maturity score formula: `(implemented + partial × 0.5) / total × 100`

**Usage**

```bash
python3 iso27001_gap_analyzer.py --config config.yaml --output gap_report.json
```

**Sample output**

```
============================================================
ISO 27001:2022 GAP ANALYSIS REPORT
============================================================
Maturity Score:    92.9%
Implemented:       13/14
Partial:           1
Not Implemented:   0
Critical Gaps:     0
============================================================

Breakdown by Theme:
  Organizational       | OK 6  PARTIAL 1  GAP 0
  People               | OK 3  PARTIAL 0  GAP 0
  Physical             | OK 1  PARTIAL 0  GAP 0
  Technological        | OK 3  PARTIAL 0  GAP 0
```

---

### 3. `pci_dss_scope_mapper.py` — PCI-DSS v4.0 Scope Mapper

Maps your Cardholder Data Environment (CDE) components (IN_SCOPE / CONNECTED_TO / SEGMENTED) and validates all 12 PCI-DSS v4.0 requirements. Produces a scope diagram in JSON and a per-requirement compliance report.

**Scope classification**

Each CDE component is classified with:
- `stores_pan` / `transmits_pan` / `processes_pan` flags
- `IN_SCOPE` | `CONNECTED_TO` | `SEGMENTED` | `OUT_OF_SCOPE`
- Applied security controls list

**Requirements covered**

| Req | Title | Severity |
|---|---|---|
| 1 | Network security controls | Critical |
| 2 | Secure configurations | Critical |
| 3 | Protect stored account data | Critical |
| 4 | Protect cardholder data in transit | Critical |
| 5 | Anti-malware protection | High |
| 6 | Secure systems & software | Critical |
| 7 | Restrict access by need to know | Critical |
| 8 | Identify & authenticate users | Critical |
| 9 | Physical access controls | High |
| 10 | Logging & monitoring | Critical |
| 11 | Security testing | High |
| 12 | Security policies & program | High |

**Usage**

```bash
python3 pci_dss_scope_mapper.py --config config.yaml --output pci_report.json
```

**Sample output**

```
============================================================
PCI-DSS v4.0 COMPLIANCE REPORT
============================================================
Compliance Score:    83.3%
Requirements Met:    10/12
Individual Findings: 5
CDE Components:      3 (2 in-scope)
============================================================
```

---

### 4. `evidence_collector.py` — Automated Evidence Collector

Collects, SHA-256 hashes, timestamps, and catalogs compliance evidence artifacts from your environment. Produces a signed `EVIDENCE_MANIFEST.json` with full chain-of-custody metadata — audit-ready for SOC 2, ISO 27001, and PCI-DSS assessments.

**Evidence items collected**

| Evidence ID | Title | Frameworks | Type |
|---|---|---|---|
| EVD-IAM-001 | MFA Enforcement Policy Snapshot | SOC 2 / PCI-DSS | Config snapshot |
| EVD-IAM-002 | User Access List & Role Assignments | SOC 2 / ISO 27001 / PCI-DSS | Access list |
| EVD-IAM-003 | Privileged Account Access Review | SOC 2 / PCI-DSS | Access list |
| EVD-MON-001 | SIEM Configuration & Alert Rules | SOC 2 / ISO 27001 / PCI-DSS | Config snapshot |
| EVD-MON-002 | Log Retention Policy Evidence | SOC 2 / PCI-DSS | Config snapshot |
| EVD-VULN-001 | Vulnerability Scan Reports Summary | SOC 2 / PCI-DSS / ISO 27001 | Scan report |
| EVD-IR-001 | IR Plan & Tabletop Evidence | SOC 2 / ISO 27001 / PCI-DSS | Policy document |
| EVD-TRN-001 | Security Awareness Training Records | ISO 27001 / SOC 2 / PCI-DSS | Attestation |
| EVD-CRYPT-001 | Encryption Configuration | SOC 2 / PCI-DSS / ISO 27001 | Config snapshot |
| EVD-CHG-001 | Change Management Ticket Sample | SOC 2 / PCI-DSS | Ticket export |
| EVD-VR-001 | Vendor / TPSP Inventory & Contracts | SOC 2 / ISO 27001 / PCI-DSS | Access list |

**Usage**

```bash
python3 evidence_collector.py --config config.yaml --output-dir ./evidence_package
```

The output directory will contain one JSON artifact per evidence item plus `EVIDENCE_MANIFEST.json`:

```
evidence_package/
├── EVIDENCE_MANIFEST.json         ← signed index with package integrity hash
├── mfa_policy_snapshot.json
├── user_access_list.json
├── privileged_access_review.json
├── siem_configuration.json
├── log_retention_policy.json
├── vulnerability_scan_summary.json
├── ir_plan_evidence.json
├── security_training_records.json
├── encryption_configuration.json
├── change_management_evidence.json
└── vendor_risk_inventory.json
```

**Sample manifest summary**

```json
{
  "summary": {
    "total_evidence_items": 11,
    "collected": 10,
    "stale_or_partial": 1,
    "missing": 0,
    "collection_completeness_pct": 90.9
  },
  "manifest_metadata": {
    "package_integrity_hash": "cbabc4b9b1b32490..."
  }
}
```

---

### 5. `access_review_automation.py` — Quarterly Access Review Automation

Automates the full quarterly access review lifecycle: loads user/role data, applies risk-flagging heuristics, generates per-manager reviewer task packages, processes decisions, escalates overdue items, and produces a certification report.

**Risk flags applied automatically**

| Flag | Trigger |
|---|---|
| `stale_account` | No login in 90–180 days |
| `dormant` | No login in 180+ days |
| `terminated_with_access` | Terminated user with active roles/groups |
| `excess_privilege` | Non-privileged user assigned admin-tier roles |
| `no_mfa` | MFA not enabled on account |
| `admin_without_justification` | Privileged flag set but no justification field |
| `orphaned` | No manager assigned (non-service account) |

**Review decision states:** `CERTIFY` | `REVOKE` | `MODIFY` | `PENDING` | `ESCALATED`

**Usage**

```bash
python3 access_review_automation.py --config config.yaml --output review_report.json
```

**Sample output**

```
============================================================
ACCESS REVIEW REPORT — Q2 2026
============================================================
Total Users:        150
Completion:         87.3%
Certifications:     118
Revocations:        13
Pending:            19
High-Risk Accounts: 24
Without MFA:        8

Risk Flag Breakdown:
  stale_account                       11
  no_mfa                              8
  excess_privilege                    6
  terminated_with_access              3
  orphaned                            2
============================================================
```

**Config keys**

```yaml
review:
  period: Q2 2026
  due_date: 2026-07-01
  privileged_role_names: [admin, superuser, root, owner]

users:
  - id: U001
    username: alice.smith
    display_name: Alice Smith
    department: Engineering
    manager: bob.jones@company.com
    job_title: Senior Engineer
    last_login: "2026-06-01"
    mfa_enabled: true
    is_privileged: true
    privileged_justification: Cloud infrastructure owner
    roles: [cloud-admin, read-only-prod]
    groups: [engineering, aws-admins]

review_decisions:
  alice.smith:
    decision: CERTIFY
    notes: Access appropriate for role
```

---

### 6. `vulnerability_compliance.py` — Vulnerability SLA Compliance Tracker

Tracks open vulnerabilities against configurable SLA windows by CVSS severity, identifies breached and at-risk items, calculates per-severity compliance percentages, MTTR by severity, and team-level accountability metrics.

**Default SLA windows (configurable)**

| Severity | CVSS Range | Default SLA |
|---|---|---|
| Critical | 9.0 – 10.0 | 15 days |
| High | 7.0 – 8.9 | 30 days |
| Medium | 4.0 – 6.9 | 90 days |
| Low | 0.1 – 3.9 | 180 days |

**SLA status values:** `WITHIN_SLA` | `AT_RISK` (>75% elapsed) | `BREACHED` | `REMEDIATED` | `ACCEPTED_RISK` | `FALSE_POSITIVE`

**Usage**

```bash
python3 vulnerability_compliance.py --config config.yaml --output vuln_report.json
```

**Sample output**

```
============================================================
VULNERABILITY SLA COMPLIANCE REPORT
============================================================
Overall SLA Compliance: 71.4%
Total Vulnerabilities:  7
Open:                   6
SLA Breached:           2
At Risk (>75% elapsed): 0
Remediated:             1

Compliance by Severity:
  CRITICAL     [##########] 100.0%  (2/2 compliant, SLA: 15d)
  HIGH         [..........]   0.0%  (0/2 compliant, SLA: 30d)
  MEDIUM       [##########] 100.0%  (2/2 compliant, SLA: 90d)
  LOW          [##########] 100.0%  (1/1 compliant, SLA: 180d)

[!] SLA BREACHED -- 2 item(s):
  [HIGH] VULN-0002: SQL Injection in Admin API - 33d open (SLA: 30d) [Backend Engineering]
  [HIGH] VULN-0003: Unpatched OpenSSL (CVE-2025-XXXX) - 67d open (SLA: 30d) [Database Team]
============================================================
```

**Report sections**

- `executive_summary` — overall SLA %, open/breached/at-risk counts
- `compliance_by_severity` — per-severity compliance %, SLA days, breach counts
- `mean_time_to_remediate_days` — MTTR per severity for closed items
- `compliance_by_team` — breach/at-risk counts per owning team
- `sla_breached_items` — full details of every breached vulnerability
- `at_risk_items` — items >75% through their SLA window
- `all_vulnerabilities` — complete record set

---

## Quick Start

**Requirements:** Python 3.9+, no third-party dependencies for sample-config runs. Add `pyyaml` (`pip install pyyaml`) to use `--config` with YAML files.

```bash
# Run any script with its built-in sample config
python3 scripts/soc2_control_scanner.py
python3 scripts/iso27001_gap_analyzer.py
python3 scripts/pci_dss_scope_mapper.py
python3 scripts/evidence_collector.py
python3 scripts/access_review_automation.py
python3 scripts/vulnerability_compliance.py

# Use a custom config
python3 scripts/soc2_control_scanner.py --config my_env.yaml --output results/soc2.json
```

**Connecting to live systems**

Each script's data loading method is clearly marked for extension:

| Script | Method to extend | Replace with |
|---|---|---|
| `soc2_control_scanner.py` | `config` dict inputs | AWS Config, Okta API, SIEM API |
| `iso27001_gap_analyzer.py` | `config` dict inputs | GRC platform API, directory queries |
| `pci_dss_scope_mapper.py` | `_load_cde_components()` | CMDB / asset inventory API |
| `evidence_collector.py` | `collect_*()` methods | Live API calls per source system |
| `access_review_automation.py` | `_load_users()` | Okta, Azure AD, Google Workspace |
| `vulnerability_compliance.py` | `_load_vulnerabilities()` | Tenable, Qualys, Rapid7, Wiz |

---

## JSON Output Schema

All scripts produce JSON with the same top-level structure:

```json
{
  "<report>_metadata": {
    "timestamp": "2026-06-07T15:00:00+00:00",
    "tool_version": "2.0.0",
    "framework": "..."
  },
  "summary": { ... },
  "results / findings / user_review_details": [ ... ]
}
```

This makes it straightforward to ingest into Splunk, Elastic, Domo, or any GRC platform that accepts JSON.

---

## License

MIT License — free to use, adapt, and distribute with attribution.

---

<div align="center">
<i>Built by <a href="https://github.com/cyberzeshan">Zeshan Ahmad</a> · GRC Engineer & Cybersecurity SME</i>
</div>
