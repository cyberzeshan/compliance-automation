# 🤖 Compliance Automation

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![SOC2](https://img.shields.io/badge/SOC_2_Type_II-4A154B?style=flat-square&logoColor=white)
![ISO27001](https://img.shields.io/badge/ISO_27001%3A2022-0066CC?style=flat-square&logoColor=white)
![NIST](https://img.shields.io/badge/NIST_SP_800--53-003087?style=flat-square&logoColor=white)
![PCI DSS](https://img.shields.io/badge/PCI--DSS_v4-FF6B00?style=flat-square&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**Production-ready compliance automation: Python scanners, continuous monitoring pipelines, evidence collectors, and control checklists for SOC 2, ISO 27001, PCI-DSS, and NIST SP 800-53.**

</div>

---

## 📖 Overview

Manual compliance is expensive, inconsistent, and doesn't scale. This repository provides the tooling infrastructure to **automate evidence collection, continuous control monitoring, and compliance gap reporting** across the most common regulatory frameworks.

Built for security engineers and GRC teams that want to move from spreadsheet-driven compliance to **code-driven, auditable, repeatable programs.**

---

## 📂 Repository Structure

```
compliance-automation/
│
├── scripts/
│   ├── soc2_control_scanner.py          # SOC 2 TSC automated control checks
│   ├── iso27001_gap_analyzer.py         # ISO 27001 clause compliance checker
│   ├── pci_dss_scope_mapper.py          # PCI-DSS v4 cardholder data environment mapper
│   ├── evidence_collector.py            # Automated evidence collection & cataloging
│   ├── access_review_automation.py      # Quarterly access review workflow automation
│   └── vulnerability_compliance.py     # Vuln management SLA compliance tracker
│
├── checklists/
│   ├── soc2-type2-readiness-checklist.md     # 150-point SOC 2 readiness assessment
│   ├── iso27001-certification-checklist.md   # Clause & Annex A implementation checklist
│   ├── pci-dss-v4-gap-checklist.md           # PCI-DSS v4 requirement-by-requirement
│   └── hipaa-security-rule-checklist.md      # HIPAA Security Rule safeguard checklist
│
├── pipelines/
│   ├── continuous-compliance-monitor.yml  # GitHub Actions workflow for daily checks
│   ├── evidence-collection-pipeline.yml   # Automated evidence ingestion pipeline
│   └── compliance-report-generator.yml    # Scheduled compliance dashboard generation
│
└── reports/
    ├── compliance-dashboard-template.html  # HTML compliance status dashboard
    └── gap-analysis-report-template.md     # Executive gap analysis report format
```

---

## 🔧 Core Script: SOC 2 Control Scanner

```python
#!/usr/bin/env python3
"""
soc2_control_scanner.py
SOC 2 Trust Services Criteria — Automated Control Verification
Author: Zeshan Ahmad | github.com/cyberzeshan

Checks common SOC 2 CC controls against your environment configuration.
Requires: boto3 (AWS), python-ldap or graph SDK (AD/AAD), requests

Usage:
    python3 soc2_control_scanner.py --config config.yaml --output report.json
"""

import json
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class ControlStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "N/A"
    MANUAL_REVIEW = "MANUAL"


@dataclass
class ControlResult:
    control_id: str
    control_name: str
    tsc_category: str          # e.g. CC6.1, CC7.2
    status: ControlStatus
    evidence: str
    finding: Optional[str] = None
    remediation: Optional[str] = None
    severity: str = "Medium"   # Critical, High, Medium, Low
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class SOC2Scanner:
    """
    SOC 2 Trust Services Criteria automated control scanner.
    Extend check_* methods with your environment-specific logic.
    """

    def __init__(self, config: dict):
        self.config = config
        self.results: List[ControlResult] = []
        self.scan_timestamp = datetime.utcnow().isoformat()

    def check_cc61_logical_access_controls(self) -> ControlResult:
        """CC6.1 — Logical and physical access controls"""
        # Example: check if MFA is enforced for privileged accounts
        mfa_enforced = self.config.get("iam", {}).get("mfa_enforced_for_admins", False)
        privileged_accounts_without_mfa = self.config.get("iam", {}).get(
            "privileged_accounts_without_mfa", []
        )

        if mfa_enforced and not privileged_accounts_without_mfa:
            return ControlResult(
                control_id="CC6.1-01",
                control_name="MFA Enforced for Privileged Accounts",
                tsc_category="CC6.1",
                status=ControlStatus.PASS,
                evidence="MFA policy enforced; 0 privileged accounts without MFA",
                severity="Critical",
            )
        else:
            return ControlResult(
                control_id="CC6.1-01",
                control_name="MFA Enforced for Privileged Accounts",
                tsc_category="CC6.1",
                status=ControlStatus.FAIL,
                evidence=f"Accounts without MFA: {privileged_accounts_without_mfa}",
                finding="Privileged accounts do not have MFA enforced",
                remediation="Enable MFA requirement for all admin/privileged roles in IAM policy",
                severity="Critical",
            )

    def check_cc62_access_provisioning(self) -> ControlResult:
        """CC6.2 — Prior to issuing system credentials, authorized users are registered"""
        has_provisioning_process = self.config.get("iam", {}).get(
            "formal_provisioning_process", False
        )
        last_access_review_days = self.config.get("iam", {}).get(
            "days_since_last_access_review", 999
        )

        if has_provisioning_process and last_access_review_days <= 90:
            return ControlResult(
                control_id="CC6.2-01",
                control_name="Formal Access Provisioning & Quarterly Review",
                tsc_category="CC6.2",
                status=ControlStatus.PASS,
                evidence=f"Provisioning process documented; last review {last_access_review_days} days ago",
                severity="High",
            )
        else:
            gaps = []
            if not has_provisioning_process:
                gaps.append("No formal provisioning process documented")
            if last_access_review_days > 90:
                gaps.append(f"Access review overdue by {last_access_review_days - 90} days")
            return ControlResult(
                control_id="CC6.2-01",
                control_name="Formal Access Provisioning & Quarterly Review",
                tsc_category="CC6.2",
                status=ControlStatus.FAIL,
                evidence="; ".join(gaps),
                finding="Access provisioning controls are insufficient",
                remediation="Document provisioning process; schedule quarterly access reviews",
                severity="High",
            )

    def check_cc72_system_monitoring(self) -> ControlResult:
        """CC7.2 — The entity monitors system components for anomalies"""
        siem_enabled = self.config.get("monitoring", {}).get("siem_enabled", False)
        alert_rules_count = self.config.get("monitoring", {}).get("active_alert_rules", 0)
        log_retention_days = self.config.get("monitoring", {}).get("log_retention_days", 0)

        issues = []
        if not siem_enabled:
            issues.append("SIEM not enabled")
        if alert_rules_count < 20:
            issues.append(f"Only {alert_rules_count} alert rules active (recommended: 20+)")
        if log_retention_days < 365:
            issues.append(f"Log retention {log_retention_days} days (SOC 2 minimum: 365)")

        if not issues:
            return ControlResult(
                control_id="CC7.2-01",
                control_name="SIEM & Security Monitoring",
                tsc_category="CC7.2",
                status=ControlStatus.PASS,
                evidence=f"SIEM active; {alert_rules_count} rules; {log_retention_days}d retention",
                severity="High",
            )
        return ControlResult(
            control_id="CC7.2-01",
            control_name="SIEM & Security Monitoring",
            tsc_category="CC7.2",
            status=ControlStatus.FAIL,
            evidence="; ".join(issues),
            finding="Security monitoring gaps identified",
            remediation="Deploy SIEM, configure minimum 20 alert rules, set 365-day log retention",
            severity="High",
        )

    def run_all_checks(self) -> dict:
        """Execute all SOC 2 control checks and return structured report"""
        logger.info("Starting SOC 2 control scan...")

        checks = [
            self.check_cc61_logical_access_controls,
            self.check_cc62_access_provisioning,
            self.check_cc72_system_monitoring,
            # Add more check_* methods here
        ]

        for check in checks:
            try:
                result = check()
                self.results.append(result)
                status_symbol = "✅" if result.status == ControlStatus.PASS else "❌"
                logger.info(f"{status_symbol} {result.control_id}: {result.control_name} — {result.status.value}")
            except Exception as e:
                logger.error(f"Error running {check.__name__}: {e}")

        return self._generate_report()

    def _generate_report(self) -> dict:
        passed = sum(1 for r in self.results if r.status == ControlStatus.PASS)
        failed = sum(1 for r in self.results if r.status == ControlStatus.FAIL)
        total = len(self.results)
        compliance_pct = (passed / total * 100) if total > 0 else 0

        critical_findings = [
            r for r in self.results
            if r.status == ControlStatus.FAIL and r.severity == "Critical"
        ]

        return {
            "scan_metadata": {
                "timestamp": self.scan_timestamp,
                "scanner_version": "2.0.0",
                "framework": "SOC 2 Trust Services Criteria",
            },
            "summary": {
                "total_controls": total,
                "passed": passed,
                "failed": failed,
                "compliance_percentage": round(compliance_pct, 1),
                "critical_findings": len(critical_findings),
            },
            "results": [
                {
                    "control_id": r.control_id,
                    "control_name": r.control_name,
                    "tsc": r.tsc_category,
                    "status": r.status.value,
                    "severity": r.severity,
                    "evidence": r.evidence,
                    "finding": r.finding,
                    "remediation": r.remediation,
                    "timestamp": r.timestamp,
                }
                for r in self.results
            ],
        }


if __name__ == "__main__":
    # Sample configuration — replace with your environment data source
    sample_config = {
        "iam": {
            "mfa_enforced_for_admins": True,
            "privileged_accounts_without_mfa": [],
            "formal_provisioning_process": True,
            "days_since_last_access_review": 45,
        },
        "monitoring": {
            "siem_enabled": True,
            "active_alert_rules": 87,
            "log_retention_days": 365,
        },
    }

    scanner = SOC2Scanner(config=sample_config)
    report = scanner.run_all_checks()

    print("\n" + "="*60)
    print("SOC 2 COMPLIANCE SCAN REPORT")
    print("="*60)
    print(f"Compliance Score: {report['summary']['compliance_percentage']}%")
    print(f"Controls Passed:  {report['summary']['passed']}/{report['summary']['total_controls']}")
    print(f"Critical Findings: {report['summary']['critical_findings']}")
    print("="*60)

    # Output full report to JSON
    with open("soc2_scan_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\nFull report saved to soc2_scan_report.json")
```

---

## ✅ SOC 2 Type II Readiness Checklist (Excerpt)

### CC6 — Logical and Physical Access Controls

| # | Control | Status | Evidence Required | Auditor Notes |
|:---:|:---|:---:|:---|:---|
| 1 | MFA enforced for all user accounts | ☐ | IAM policy screenshot, MFA enforcement report | Critical — zero exceptions |
| 2 | MFA enforced for privileged/admin accounts | ☐ | Privileged account list + MFA status export | Must show 100% coverage |
| 3 | Unique user IDs — no shared accounts | ☐ | User directory export | Shared accounts are automatic finding |
| 4 | Formal access provisioning process documented | ☐ | Process document with approvals | Must include RBAC model |
| 5 | Quarterly access reviews completed | ☐ | Access review reports × 4 quarters | Show reviewer sign-off |
| 6 | Terminated user accounts disabled within 24hrs | ☐ | Offboarding tickets + AD/IdP timestamps | Automated preferred |
| 7 | Least privilege principle enforced | ☐ | Role definitions, access matrix | Evidence of RBAC review |
| 8 | Production access restricted to authorized personnel | ☐ | Production access list + job role mapping | Break-glass accounts documented |
| 9 | Physical access to data centers controlled | ☐ | Badge access logs, visitor policy | Applicable to on-prem/colo |
| 10 | Encryption at rest for all production data | ☐ | Encryption policy + technical configuration | Key management documented |

### CC7 — System Operations

| # | Control | Status | Evidence Required |
|:---:|:---|:---:|:---|
| 11 | SIEM deployed with 24/7 alerting | ☐ | SIEM architecture diagram, alert rules list |
| 12 | Security alerts reviewed and investigated | ☐ | Alert queue screenshots, ticket closure evidence |
| 13 | Log retention ≥ 12 months | ☐ | Logging configuration + retention policy |
| 14 | Vulnerability scanning — at least monthly | ☐ | 12 months of scan reports |
| 15 | Critical vulnerabilities patched within SLA | ☐ | Patch tracking report + SLA evidence |
| 16 | Incident response plan documented & tested | ☐ | IR plan + tabletop exercise after-action report |
| 17 | Change management process for production | ☐ | Change tickets with approvals (12-month sample) |

---

## 📄 License

MIT License — free to use, adapt, and distribute with attribution.

---

<div align="center">
<i>Built by <a href="https://github.com/cyberzeshan">Zeshan Ahmad</a> · GRC Engineer & Cybersecurity SME</i>
</div>
