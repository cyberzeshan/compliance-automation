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
import argparse
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
    tsc_category: str
    status: ControlStatus
    evidence: str
    finding: Optional[str] = None
    remediation: Optional[str] = None
    severity: str = "Medium"
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

    # ── CC6 Logical & Physical Access ────────────────────────────────────────

    def check_cc61_logical_access_controls(self) -> ControlResult:
        """CC6.1 — Logical and physical access controls"""
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

    def check_cc61_encryption_at_rest(self) -> ControlResult:
        """CC6.1 — Encryption at rest for production data"""
        encryption_enabled = self.config.get("data_protection", {}).get(
            "encryption_at_rest", False
        )
        unencrypted_stores = self.config.get("data_protection", {}).get(
            "unencrypted_data_stores", []
        )

        if encryption_enabled and not unencrypted_stores:
            return ControlResult(
                control_id="CC6.1-02",
                control_name="Encryption at Rest for Production Data",
                tsc_category="CC6.1",
                status=ControlStatus.PASS,
                evidence="Encryption at rest enabled; no unencrypted production data stores",
                severity="Critical",
            )
        return ControlResult(
            control_id="CC6.1-02",
            control_name="Encryption at Rest for Production Data",
            tsc_category="CC6.1",
            status=ControlStatus.FAIL,
            evidence=f"Unencrypted stores: {unencrypted_stores}",
            finding="Production data stores are not fully encrypted at rest",
            remediation="Enable encryption at rest on all production databases and storage",
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

    def check_cc63_offboarding(self) -> ControlResult:
        """CC6.3 — Access removed within SLA upon termination"""
        sla_hours = self.config.get("iam", {}).get("offboarding_sla_hours", 48)
        avg_revocation_hours = self.config.get("iam", {}).get(
            "avg_account_revocation_hours", 999
        )
        automated_offboarding = self.config.get("iam", {}).get(
            "automated_offboarding", False
        )

        if avg_revocation_hours <= sla_hours:
            return ControlResult(
                control_id="CC6.3-01",
                control_name="Access Revocation Within SLA on Termination",
                tsc_category="CC6.3",
                status=ControlStatus.PASS,
                evidence=(
                    f"Avg revocation: {avg_revocation_hours}h "
                    f"(SLA: {sla_hours}h); automated={automated_offboarding}"
                ),
                severity="High",
            )
        return ControlResult(
            control_id="CC6.3-01",
            control_name="Access Revocation Within SLA on Termination",
            tsc_category="CC6.3",
            status=ControlStatus.FAIL,
            evidence=f"Avg revocation: {avg_revocation_hours}h exceeds SLA of {sla_hours}h",
            finding="Offboarding process does not meet access revocation SLA",
            remediation="Automate account deprovisioning via HR-to-IdP integration",
            severity="High",
        )

    def check_cc64_least_privilege(self) -> ControlResult:
        """CC6.4 — Least privilege access principle"""
        rbac_implemented = self.config.get("iam", {}).get("rbac_implemented", False)
        users_with_excessive_access = self.config.get("iam", {}).get(
            "users_with_excessive_access", 0
        )
        total_users = self.config.get("iam", {}).get("total_users", 1)
        excess_pct = (users_with_excessive_access / total_users * 100) if total_users > 0 else 0

        if rbac_implemented and excess_pct < 5:
            return ControlResult(
                control_id="CC6.4-01",
                control_name="Least Privilege / RBAC Enforcement",
                tsc_category="CC6.4",
                status=ControlStatus.PASS,
                evidence=(
                    f"RBAC implemented; {users_with_excessive_access} users "
                    f"({excess_pct:.1f}%) flagged for excess access"
                ),
                severity="High",
            )
        return ControlResult(
            control_id="CC6.4-01",
            control_name="Least Privilege / RBAC Enforcement",
            tsc_category="CC6.4",
            status=ControlStatus.FAIL if not rbac_implemented else ControlStatus.WARNING,
            evidence=(
                f"RBAC={rbac_implemented}; "
                f"{users_with_excessive_access} users ({excess_pct:.1f}%) over-privileged"
            ),
            finding="Least privilege principle not consistently enforced",
            remediation="Implement RBAC, run entitlement review to right-size permissions",
            severity="High",
        )

    # ── CC7 System Operations ─────────────────────────────────────────────────

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
            issues.append(f"Log retention {log_retention_days} days (minimum: 365)")

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

    def check_cc73_vulnerability_management(self) -> ControlResult:
        """CC7.3 — Identified vulnerabilities are evaluated and remediated"""
        scan_frequency_days = self.config.get("vulnerability_mgmt", {}).get(
            "scan_frequency_days", 999
        )
        critical_sla_days = self.config.get("vulnerability_mgmt", {}).get(
            "critical_patch_sla_days", 999
        )
        overdue_criticals = self.config.get("vulnerability_mgmt", {}).get(
            "overdue_critical_vulns", 0
        )

        issues = []
        if scan_frequency_days > 30:
            issues.append(f"Scans run every {scan_frequency_days} days (max: 30)")
        if critical_sla_days > 30:
            issues.append(f"Critical patch SLA is {critical_sla_days} days (target: ≤30)")
        if overdue_criticals > 0:
            issues.append(f"{overdue_criticals} critical vulnerabilities past SLA")

        if not issues:
            return ControlResult(
                control_id="CC7.3-01",
                control_name="Vulnerability Management & Patch SLA",
                tsc_category="CC7.3",
                status=ControlStatus.PASS,
                evidence=(
                    f"Scans every {scan_frequency_days}d; "
                    f"critical SLA {critical_sla_days}d; 0 overdue criticals"
                ),
                severity="High",
            )
        return ControlResult(
            control_id="CC7.3-01",
            control_name="Vulnerability Management & Patch SLA",
            tsc_category="CC7.3",
            status=ControlStatus.FAIL,
            evidence="; ".join(issues),
            finding="Vulnerability management program has gaps",
            remediation="Monthly scanning minimum; 30-day SLA for criticals; track overdue items",
            severity="High",
        )

    def check_cc74_incident_response(self) -> ControlResult:
        """CC7.4 — Security incidents are identified, reported, and responded to"""
        ir_plan_documented = self.config.get("incident_response", {}).get(
            "ir_plan_documented", False
        )
        tabletop_conducted_days = self.config.get("incident_response", {}).get(
            "days_since_last_tabletop", 999
        )
        incident_tracking_tool = self.config.get("incident_response", {}).get(
            "incident_tracking_tool", ""
        )

        issues = []
        if not ir_plan_documented:
            issues.append("IR plan not documented")
        if tabletop_conducted_days > 365:
            issues.append(f"No tabletop exercise in {tabletop_conducted_days} days (annual required)")
        if not incident_tracking_tool:
            issues.append("No incident tracking tool configured")

        if not issues:
            return ControlResult(
                control_id="CC7.4-01",
                control_name="Incident Response Plan & Testing",
                tsc_category="CC7.4",
                status=ControlStatus.PASS,
                evidence=(
                    f"IR plan documented; last tabletop {tabletop_conducted_days}d ago; "
                    f"tracker: {incident_tracking_tool}"
                ),
                severity="High",
            )
        return ControlResult(
            control_id="CC7.4-01",
            control_name="Incident Response Plan & Testing",
            tsc_category="CC7.4",
            status=ControlStatus.FAIL,
            evidence="; ".join(issues),
            finding="Incident response program incomplete",
            remediation="Document IR plan, conduct annual tabletop, deploy incident tracker",
            severity="High",
        )

    # ── CC8 Change Management ─────────────────────────────────────────────────

    def check_cc81_change_management(self) -> ControlResult:
        """CC8.1 — Changes to system components are authorized and tested"""
        change_mgmt_process = self.config.get("change_management", {}).get(
            "formal_process_documented", False
        )
        changes_with_approval = self.config.get("change_management", {}).get(
            "pct_changes_with_approval", 0
        )
        prod_deploy_requires_review = self.config.get("change_management", {}).get(
            "prod_deploy_requires_review", False
        )

        issues = []
        if not change_mgmt_process:
            issues.append("Change management process not documented")
        if changes_with_approval < 95:
            issues.append(f"Only {changes_with_approval}% of changes have documented approval")
        if not prod_deploy_requires_review:
            issues.append("Production deployments do not require peer review")

        if not issues:
            return ControlResult(
                control_id="CC8.1-01",
                control_name="Change Management Process",
                tsc_category="CC8.1",
                status=ControlStatus.PASS,
                evidence=(
                    f"Process documented; {changes_with_approval}% approval rate; "
                    f"prod review required"
                ),
                severity="High",
            )
        return ControlResult(
            control_id="CC8.1-01",
            control_name="Change Management Process",
            tsc_category="CC8.1",
            status=ControlStatus.FAIL,
            evidence="; ".join(issues),
            finding="Change management controls have gaps",
            remediation="Document process, enforce approval workflows, require PR reviews for prod",
            severity="High",
        )

    # ── CC9 Risk Mitigation ───────────────────────────────────────────────────

    def check_cc91_vendor_risk(self) -> ControlResult:
        """CC9.1 — Entity identifies, selects, and develops risk mitigation activities"""
        vendor_inventory = self.config.get("vendor_risk", {}).get("vendor_inventory_maintained", False)
        vendors_with_baa_or_dpa = self.config.get("vendor_risk", {}).get(
            "pct_vendors_with_contracts", 0
        )
        annual_vendor_review = self.config.get("vendor_risk", {}).get(
            "annual_vendor_review_conducted", False
        )

        issues = []
        if not vendor_inventory:
            issues.append("No vendor/third-party inventory maintained")
        if vendors_with_baa_or_dpa < 100:
            issues.append(f"Only {vendors_with_baa_or_dpa}% of vendors have data processing agreements")
        if not annual_vendor_review:
            issues.append("Annual vendor risk review not conducted")

        if not issues:
            return ControlResult(
                control_id="CC9.1-01",
                control_name="Vendor / Third-Party Risk Management",
                tsc_category="CC9.1",
                status=ControlStatus.PASS,
                evidence=(
                    f"Inventory maintained; {vendors_with_baa_or_dpa}% vendors contracted; "
                    f"annual review complete"
                ),
                severity="Medium",
            )
        return ControlResult(
            control_id="CC9.1-01",
            control_name="Vendor / Third-Party Risk Management",
            tsc_category="CC9.1",
            status=ControlStatus.FAIL,
            evidence="; ".join(issues),
            finding="Vendor risk management program incomplete",
            remediation="Maintain vendor inventory, collect DPAs/BAAs, conduct annual reviews",
            severity="Medium",
        )

    # ── Runner & Report ───────────────────────────────────────────────────────

    def run_all_checks(self) -> dict:
        """Execute all SOC 2 control checks and return structured report"""
        logger.info("Starting SOC 2 control scan...")

        checks = [
            self.check_cc61_logical_access_controls,
            self.check_cc61_encryption_at_rest,
            self.check_cc62_access_provisioning,
            self.check_cc63_offboarding,
            self.check_cc64_least_privilege,
            self.check_cc72_system_monitoring,
            self.check_cc73_vulnerability_management,
            self.check_cc74_incident_response,
            self.check_cc81_change_management,
            self.check_cc91_vendor_risk,
        ]

        for check in checks:
            try:
                result = check()
                self.results.append(result)
                symbol = "✅" if result.status == ControlStatus.PASS else (
                    "⚠️" if result.status == ControlStatus.WARNING else "❌"
                )
                logger.info(
                    f"{symbol} {result.control_id}: {result.control_name} — {result.status.value}"
                )
            except Exception as e:
                logger.error(f"Error running {check.__name__}: {e}")

        return self._generate_report()

    def _generate_report(self) -> dict:
        passed = sum(1 for r in self.results if r.status == ControlStatus.PASS)
        failed = sum(1 for r in self.results if r.status == ControlStatus.FAIL)
        warnings = sum(1 for r in self.results if r.status == ControlStatus.WARNING)
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
                "warnings": warnings,
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


def _load_config(path: str) -> dict:
    import yaml  # pip install pyyaml
    with open(path) as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC 2 Trust Services Criteria scanner")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--output", default="soc2_scan_report.json", help="Output JSON path")
    args = parser.parse_args()

    if args.config:
        config = _load_config(args.config)
    else:
        # Sample config — replace with real environment data
        config = {
            "iam": {
                "mfa_enforced_for_admins": True,
                "privileged_accounts_without_mfa": [],
                "formal_provisioning_process": True,
                "days_since_last_access_review": 45,
                "offboarding_sla_hours": 24,
                "avg_account_revocation_hours": 12,
                "automated_offboarding": True,
                "rbac_implemented": True,
                "users_with_excessive_access": 3,
                "total_users": 150,
            },
            "data_protection": {
                "encryption_at_rest": True,
                "unencrypted_data_stores": [],
            },
            "monitoring": {
                "siem_enabled": True,
                "active_alert_rules": 87,
                "log_retention_days": 365,
            },
            "vulnerability_mgmt": {
                "scan_frequency_days": 7,
                "critical_patch_sla_days": 15,
                "overdue_critical_vulns": 0,
            },
            "incident_response": {
                "ir_plan_documented": True,
                "days_since_last_tabletop": 180,
                "incident_tracking_tool": "Jira",
            },
            "change_management": {
                "formal_process_documented": True,
                "pct_changes_with_approval": 98,
                "prod_deploy_requires_review": True,
            },
            "vendor_risk": {
                "vendor_inventory_maintained": True,
                "pct_vendors_with_contracts": 100,
                "annual_vendor_review_conducted": True,
            },
        }

    scanner = SOC2Scanner(config=config)
    report = scanner.run_all_checks()

    print("\n" + "=" * 60)
    print("SOC 2 COMPLIANCE SCAN REPORT")
    print("=" * 60)
    print(f"Compliance Score:  {report['summary']['compliance_percentage']}%")
    print(f"Controls Passed:   {report['summary']['passed']}/{report['summary']['total_controls']}")
    print(f"Warnings:          {report['summary']['warnings']}")
    print(f"Critical Findings: {report['summary']['critical_findings']}")
    print("=" * 60)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved to {args.output}")
