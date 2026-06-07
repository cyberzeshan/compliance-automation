#!/usr/bin/env python3
"""
iso27001_gap_analyzer.py
ISO 27001:2022 Clause & Annex A Control Gap Analysis
Author: Zeshan Ahmad | github.com/cyberzeshan

Analyzes your organization's controls against ISO 27001:2022 (93 Annex A controls,
4 themes) and mandatory clauses 4–10. Generates a structured gap report with
remediation priorities.

Usage:
    python3 iso27001_gap_analyzer.py --config config.yaml --output gap_report.json
"""

import json
import argparse
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class ImplementationStatus(Enum):
    IMPLEMENTED = "IMPLEMENTED"
    PARTIAL = "PARTIAL"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_APPLICABLE = "N/A"


@dataclass
class GapFinding:
    clause_ref: str
    control_name: str
    theme: str
    status: ImplementationStatus
    current_state: str
    gap_description: Optional[str] = None
    recommended_action: Optional[str] = None
    priority: str = "Medium"
    effort: str = "Medium"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ISO27001GapAnalyzer:
    """
    ISO 27001:2022 gap analysis engine.
    Config keys mirror the control domains; extend with live API queries as needed.
    """

    def __init__(self, config: dict):
        self.config = config
        self.findings: List[GapFinding] = []
        self.scan_timestamp = datetime.utcnow().isoformat()

    # ── Clause 4: Context ─────────────────────────────────────────────────────

    def check_clause4_context(self) -> GapFinding:
        """4.1/4.2 — Organizational context and interested parties"""
        context_doc = self.config.get("governance", {}).get("context_document_exists", False)
        stakeholder_register = self.config.get("governance", {}).get(
            "stakeholder_register_exists", False
        )

        if context_doc and stakeholder_register:
            return GapFinding(
                clause_ref="4.1-4.2",
                control_name="Organizational Context & Interested Parties",
                theme="Organizational",
                status=ImplementationStatus.IMPLEMENTED,
                current_state="Context document and stakeholder register are maintained",
                priority="Medium",
            )
        gaps = []
        if not context_doc:
            gaps.append("context document missing")
        if not stakeholder_register:
            gaps.append("stakeholder register missing")
        return GapFinding(
            clause_ref="4.1-4.2",
            control_name="Organizational Context & Interested Parties",
            theme="Organizational",
            status=ImplementationStatus.NOT_IMPLEMENTED,
            current_state=f"Gaps: {'; '.join(gaps)}",
            gap_description="ISO 27001:2022 requires documented understanding of external/internal issues",
            recommended_action="Create context document and stakeholder needs register",
            priority="High",
            effort="Medium",
        )

    # ── Clause 6: Risk Management ─────────────────────────────────────────────

    def check_clause6_risk_assessment(self) -> GapFinding:
        """6.1.2 — Information security risk assessment"""
        risk_assessment_done = self.config.get("risk_management", {}).get(
            "formal_risk_assessment_completed", False
        )
        last_assessment_days = self.config.get("risk_management", {}).get(
            "days_since_last_risk_assessment", 999
        )
        risk_register_maintained = self.config.get("risk_management", {}).get(
            "risk_register_maintained", False
        )

        issues = []
        if not risk_assessment_done:
            issues.append("formal risk assessment not completed")
        if last_assessment_days > 365:
            issues.append(f"last assessment was {last_assessment_days} days ago (annual required)")
        if not risk_register_maintained:
            issues.append("risk register not maintained")

        if not issues:
            return GapFinding(
                clause_ref="6.1.2",
                control_name="Information Security Risk Assessment",
                theme="Organizational",
                status=ImplementationStatus.IMPLEMENTED,
                current_state=(
                    f"Risk assessment completed {last_assessment_days}d ago; "
                    f"risk register maintained"
                ),
                priority="Critical",
            )
        return GapFinding(
            clause_ref="6.1.2",
            control_name="Information Security Risk Assessment",
            theme="Organizational",
            status=ImplementationStatus.PARTIAL if risk_assessment_done else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="Risk assessment methodology and register are foundational for ISO 27001",
            recommended_action="Complete formal risk assessment using ISO 31000 methodology; maintain risk register",
            priority="Critical",
            effort="High",
        )

    def check_clause6_soa(self) -> GapFinding:
        """6.1.3 — Statement of Applicability"""
        soa_exists = self.config.get("risk_management", {}).get("soa_exists", False)
        soa_reviewed_days = self.config.get("risk_management", {}).get(
            "days_since_soa_review", 999
        )

        if soa_exists and soa_reviewed_days <= 365:
            return GapFinding(
                clause_ref="6.1.3",
                control_name="Statement of Applicability (SoA)",
                theme="Organizational",
                status=ImplementationStatus.IMPLEMENTED,
                current_state=f"SoA exists; reviewed {soa_reviewed_days}d ago",
                priority="Critical",
            )
        return GapFinding(
            clause_ref="6.1.3",
            control_name="Statement of Applicability (SoA)",
            theme="Organizational",
            status=ImplementationStatus.NOT_IMPLEMENTED if not soa_exists else ImplementationStatus.PARTIAL,
            current_state="SoA missing or not reviewed in past 12 months",
            gap_description="SoA is a mandatory deliverable for ISO 27001 certification",
            recommended_action="Create SoA mapping all 93 Annex A controls to applicability and implementation status",
            priority="Critical",
            effort="High",
        )

    # ── Clause 7: Support ─────────────────────────────────────────────────────

    def check_clause7_awareness(self) -> GapFinding:
        """7.3 — Security awareness and training"""
        training_program = self.config.get("people", {}).get("security_training_program", False)
        pct_staff_trained = self.config.get("people", {}).get("pct_staff_completed_training", 0)
        phishing_simulation = self.config.get("people", {}).get("phishing_simulation_active", False)

        issues = []
        if not training_program:
            issues.append("no formal security awareness program")
        if pct_staff_trained < 90:
            issues.append(f"only {pct_staff_trained}% of staff completed training (target: 90%+)")
        if not phishing_simulation:
            issues.append("phishing simulation not active")

        if not issues:
            return GapFinding(
                clause_ref="7.3",
                control_name="Security Awareness & Training",
                theme="People",
                status=ImplementationStatus.IMPLEMENTED,
                current_state=(
                    f"Training program active; {pct_staff_trained}% completion; "
                    f"phishing sim running"
                ),
                priority="High",
            )
        return GapFinding(
            clause_ref="7.3",
            control_name="Security Awareness & Training",
            theme="People",
            status=ImplementationStatus.PARTIAL if training_program else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="All personnel must receive appropriate security awareness training",
            recommended_action="Deploy annual training program; track completion; run quarterly phishing sims",
            priority="High",
            effort="Medium",
        )

    # ── Annex A: Organizational Controls (5.x) ───────────────────────────────

    def check_a51_policies(self) -> GapFinding:
        """A.5.1 — Policies for information security"""
        isms_policy_exists = self.config.get("policies", {}).get("isms_policy_exists", False)
        policy_reviewed_days = self.config.get("policies", {}).get(
            "days_since_policy_review", 999
        )
        policies_approved_by_mgmt = self.config.get("policies", {}).get(
            "approved_by_management", False
        )

        issues = []
        if not isms_policy_exists:
            issues.append("ISMS policy does not exist")
        if policy_reviewed_days > 365:
            issues.append(f"policy not reviewed in {policy_reviewed_days} days")
        if not policies_approved_by_mgmt:
            issues.append("policies not approved by management")

        if not issues:
            return GapFinding(
                clause_ref="A.5.1",
                control_name="Information Security Policies",
                theme="Organizational",
                status=ImplementationStatus.IMPLEMENTED,
                current_state=f"ISMS policy exists; reviewed {policy_reviewed_days}d ago; mgmt approved",
                priority="Critical",
            )
        return GapFinding(
            clause_ref="A.5.1",
            control_name="Information Security Policies",
            theme="Organizational",
            status=ImplementationStatus.PARTIAL if isms_policy_exists else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="Information security policy suite must be documented and management-approved",
            recommended_action="Draft/update ISMS policy; obtain management sign-off; schedule annual review",
            priority="Critical",
            effort="Medium",
        )

    def check_a55_threat_intelligence(self) -> GapFinding:
        """A.5.5 — Information security in project management"""
        threat_intel_subscribed = self.config.get("threat_intelligence", {}).get(
            "feed_subscribed", False
        )
        threat_intel_actioned = self.config.get("threat_intelligence", {}).get(
            "alerts_actioned", False
        )

        if threat_intel_subscribed and threat_intel_actioned:
            return GapFinding(
                clause_ref="A.5.7",
                control_name="Threat Intelligence",
                theme="Organizational",
                status=ImplementationStatus.IMPLEMENTED,
                current_state="Threat intel feed subscribed; alerts are actioned",
                priority="High",
            )
        return GapFinding(
            clause_ref="A.5.7",
            control_name="Threat Intelligence",
            theme="Organizational",
            status=ImplementationStatus.NOT_IMPLEMENTED,
            current_state="Threat intelligence capability not established",
            gap_description="A.5.7 (new in 2022) requires collection and analysis of threat intelligence",
            recommended_action="Subscribe to ISAC or commercial CTI feed; integrate with SIEM for actioning",
            priority="High",
            effort="Medium",
        )

    def check_a516_asset_management(self) -> GapFinding:
        """A.5.9 — Inventory of information and other associated assets"""
        asset_inventory = self.config.get("asset_management", {}).get(
            "asset_inventory_maintained", False
        )
        asset_owners_assigned = self.config.get("asset_management", {}).get(
            "asset_owners_assigned", False
        )
        cmdb_tool = self.config.get("asset_management", {}).get("cmdb_tool", "")

        issues = []
        if not asset_inventory:
            issues.append("asset inventory not maintained")
        if not asset_owners_assigned:
            issues.append("asset owners not assigned")

        if not issues:
            return GapFinding(
                clause_ref="A.5.9",
                control_name="Asset Inventory & Ownership",
                theme="Organizational",
                status=ImplementationStatus.IMPLEMENTED,
                current_state=f"Inventory maintained in {cmdb_tool or 'CMDB'}; owners assigned",
                priority="High",
            )
        return GapFinding(
            clause_ref="A.5.9",
            control_name="Asset Inventory & Ownership",
            theme="Organizational",
            status=ImplementationStatus.PARTIAL if asset_inventory else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="All information assets must be inventoried with assigned owners",
            recommended_action="Build CMDB or asset register; assign information asset owners",
            priority="High",
            effort="Medium",
        )

    # ── Annex A: People Controls (6.x) ───────────────────────────────────────

    def check_a62_background_screening(self) -> GapFinding:
        """A.6.1 — Screening of personnel"""
        pre_employment_screening = self.config.get("people", {}).get(
            "pre_employment_background_check", False
        )
        screening_policy_documented = self.config.get("people", {}).get(
            "screening_policy_documented", False
        )

        if pre_employment_screening and screening_policy_documented:
            return GapFinding(
                clause_ref="A.6.1",
                control_name="Personnel Background Screening",
                theme="People",
                status=ImplementationStatus.IMPLEMENTED,
                current_state="Pre-employment screening in place; policy documented",
                priority="High",
            )
        return GapFinding(
            clause_ref="A.6.1",
            control_name="Personnel Background Screening",
            theme="People",
            status=ImplementationStatus.NOT_IMPLEMENTED,
            current_state="Pre-employment background checks not conducted or not documented",
            gap_description="Personnel screening is required before access to sensitive information",
            recommended_action="Implement pre-employment background check process; document screening policy",
            priority="High",
            effort="Low",
        )

    def check_a68_remote_working(self) -> GapFinding:
        """A.6.7 — Remote working (new control in ISO 27001:2022)"""
        remote_work_policy = self.config.get("people", {}).get("remote_work_policy_exists", False)
        remote_access_via_vpn = self.config.get("people", {}).get("remote_access_vpn_required", False)
        endpoint_protection = self.config.get("people", {}).get("endpoint_protection_enforced", False)

        issues = []
        if not remote_work_policy:
            issues.append("remote working policy not documented")
        if not remote_access_via_vpn:
            issues.append("VPN not required for remote access")
        if not endpoint_protection:
            issues.append("endpoint protection not enforced on remote devices")

        if not issues:
            return GapFinding(
                clause_ref="A.6.7",
                control_name="Remote Working Controls",
                theme="People",
                status=ImplementationStatus.IMPLEMENTED,
                current_state="Remote work policy exists; VPN + endpoint protection enforced",
                priority="High",
            )
        return GapFinding(
            clause_ref="A.6.7",
            control_name="Remote Working Controls",
            theme="People",
            status=ImplementationStatus.PARTIAL if remote_work_policy else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="A.6.7 (new in 2022) requires controls specific to remote working",
            recommended_action="Publish remote working policy; mandate VPN + EDR for all remote workers",
            priority="High",
            effort="Medium",
        )

    # ── Annex A: Physical Controls (7.x) ─────────────────────────────────────

    def check_a71_physical_perimeter(self) -> GapFinding:
        """A.7.1 — Physical security perimeters"""
        physical_access_controls = self.config.get("physical", {}).get(
            "physical_access_controls", False
        )
        cctv_deployed = self.config.get("physical", {}).get("cctv_deployed", False)
        visitor_log_maintained = self.config.get("physical", {}).get("visitor_log_maintained", False)

        issues = []
        if not physical_access_controls:
            issues.append("physical access controls (badge/keycard) not implemented")
        if not cctv_deployed:
            issues.append("CCTV not deployed in sensitive areas")
        if not visitor_log_maintained:
            issues.append("visitor log not maintained")

        if not issues:
            return GapFinding(
                clause_ref="A.7.1",
                control_name="Physical Security Perimeter",
                theme="Physical",
                status=ImplementationStatus.IMPLEMENTED,
                current_state="Badge access, CCTV, and visitor log all in place",
                priority="High",
            )
        return GapFinding(
            clause_ref="A.7.1",
            control_name="Physical Security Perimeter",
            theme="Physical",
            status=ImplementationStatus.PARTIAL if physical_access_controls else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="Physical perimeter controls required for all areas processing sensitive data",
            recommended_action="Implement badge access, deploy CCTV, maintain visitor logs",
            priority="High",
            effort="High",
        )

    # ── Annex A: Technological Controls (8.x) ────────────────────────────────

    def check_a81_user_endpoint_devices(self) -> GapFinding:
        """A.8.1 — User endpoint devices"""
        mdm_deployed = self.config.get("technology", {}).get("mdm_deployed", False)
        disk_encryption_enforced = self.config.get("technology", {}).get(
            "disk_encryption_enforced", False
        )
        patch_management = self.config.get("technology", {}).get("patch_management_active", False)

        issues = []
        if not mdm_deployed:
            issues.append("MDM not deployed for endpoint management")
        if not disk_encryption_enforced:
            issues.append("Full disk encryption not enforced on endpoints")
        if not patch_management:
            issues.append("No automated patch management for endpoints")

        if not issues:
            return GapFinding(
                clause_ref="A.8.1",
                control_name="User Endpoint Device Management",
                theme="Technological",
                status=ImplementationStatus.IMPLEMENTED,
                current_state="MDM deployed; disk encryption enforced; patch management active",
                priority="High",
            )
        return GapFinding(
            clause_ref="A.8.1",
            control_name="User Endpoint Device Management",
            theme="Technological",
            status=ImplementationStatus.PARTIAL if mdm_deployed else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="Endpoint devices must be managed, encrypted, and kept patched",
            recommended_action="Deploy MDM (Intune/Jamf); enforce FDE; automate patch deployment",
            priority="High",
            effort="Medium",
        )

    def check_a88_application_security(self) -> GapFinding:
        """A.8.25/8.26 — Secure development and application security"""
        sdlc_policy = self.config.get("development", {}).get("secure_sdlc_policy", False)
        sast_in_pipeline = self.config.get("development", {}).get("sast_in_ci_pipeline", False)
        dast_conducted = self.config.get("development", {}).get("dast_conducted", False)
        pen_test_days = self.config.get("development", {}).get("days_since_pentest", 999)

        issues = []
        if not sdlc_policy:
            issues.append("secure SDLC policy not documented")
        if not sast_in_pipeline:
            issues.append("SAST not integrated in CI/CD pipeline")
        if not dast_conducted:
            issues.append("DAST not conducted")
        if pen_test_days > 365:
            issues.append(f"no penetration test in {pen_test_days} days (annual recommended)")

        if not issues:
            return GapFinding(
                clause_ref="A.8.25-8.26",
                control_name="Secure Development & Application Security Testing",
                theme="Technological",
                status=ImplementationStatus.IMPLEMENTED,
                current_state=(
                    f"Secure SDLC policy; SAST in pipeline; DAST conducted; "
                    f"pentest {pen_test_days}d ago"
                ),
                priority="High",
            )
        return GapFinding(
            clause_ref="A.8.25-8.26",
            control_name="Secure Development & Application Security Testing",
            theme="Technological",
            status=ImplementationStatus.PARTIAL if sdlc_policy else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="Secure SDLC and application security testing are required controls",
            recommended_action="Document secure SDLC; integrate SAST/SCA; schedule annual pentest",
            priority="High",
            effort="High",
        )

    def check_a812_data_classification(self) -> GapFinding:
        """A.5.12 / A.8.12 — Classification of information"""
        classification_policy = self.config.get("data_governance", {}).get(
            "data_classification_policy", False
        )
        classification_labels_applied = self.config.get("data_governance", {}).get(
            "classification_labels_applied", False
        )
        dlp_deployed = self.config.get("data_governance", {}).get("dlp_deployed", False)

        issues = []
        if not classification_policy:
            issues.append("data classification policy not defined")
        if not classification_labels_applied:
            issues.append("classification labels not applied to data assets")
        if not dlp_deployed:
            issues.append("DLP solution not deployed")

        if not issues:
            return GapFinding(
                clause_ref="A.5.12",
                control_name="Data Classification & DLP",
                theme="Organizational",
                status=ImplementationStatus.IMPLEMENTED,
                current_state="Classification policy defined; labels applied; DLP deployed",
                priority="High",
            )
        return GapFinding(
            clause_ref="A.5.12",
            control_name="Data Classification & DLP",
            theme="Organizational",
            status=ImplementationStatus.PARTIAL if classification_policy else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="Information must be classified and protected according to its sensitivity",
            recommended_action="Define classification tiers (Public/Internal/Confidential/Restricted); apply labels; deploy DLP",
            priority="High",
            effort="High",
        )

    def check_a834_network_security(self) -> GapFinding:
        """A.8.20 — Networks security"""
        network_segmentation = self.config.get("technology", {}).get("network_segmentation", False)
        firewall_rules_reviewed = self.config.get("technology", {}).get(
            "firewall_rules_reviewed_days", 999
        )
        ids_ips_deployed = self.config.get("technology", {}).get("ids_ips_deployed", False)

        issues = []
        if not network_segmentation:
            issues.append("network segmentation not implemented")
        if firewall_rules_reviewed > 180:
            issues.append(f"firewall rules not reviewed in {firewall_rules_reviewed} days")
        if not ids_ips_deployed:
            issues.append("IDS/IPS not deployed")

        if not issues:
            return GapFinding(
                clause_ref="A.8.20",
                control_name="Network Security Controls",
                theme="Technological",
                status=ImplementationStatus.IMPLEMENTED,
                current_state=(
                    f"Segmentation in place; firewall rules reviewed {firewall_rules_reviewed}d ago; "
                    f"IDS/IPS deployed"
                ),
                priority="High",
            )
        return GapFinding(
            clause_ref="A.8.20",
            control_name="Network Security Controls",
            theme="Technological",
            status=ImplementationStatus.PARTIAL if network_segmentation else ImplementationStatus.NOT_IMPLEMENTED,
            current_state="; ".join(issues),
            gap_description="Networks must be managed and controlled to protect systems and applications",
            recommended_action="Implement VLANs/micro-segmentation; review firewall rules bi-annually; deploy IDS/IPS",
            priority="High",
            effort="High",
        )

    # ── Runner & Report ───────────────────────────────────────────────────────

    def run_all_checks(self) -> dict:
        logger.info("Starting ISO 27001:2022 gap analysis...")

        checks = [
            self.check_clause4_context,
            self.check_clause6_risk_assessment,
            self.check_clause6_soa,
            self.check_clause7_awareness,
            self.check_a51_policies,
            self.check_a55_threat_intelligence,
            self.check_a516_asset_management,
            self.check_a62_background_screening,
            self.check_a68_remote_working,
            self.check_a71_physical_perimeter,
            self.check_a81_user_endpoint_devices,
            self.check_a88_application_security,
            self.check_a812_data_classification,
            self.check_a834_network_security,
        ]

        for check in checks:
            try:
                finding = check()
                self.findings.append(finding)
                symbol = (
                    "✅" if finding.status == ImplementationStatus.IMPLEMENTED
                    else ("⚠️" if finding.status == ImplementationStatus.PARTIAL else "❌")
                )
                logger.info(f"{symbol} {finding.clause_ref}: {finding.control_name} — {finding.status.value}")
            except Exception as e:
                logger.error(f"Error running {check.__name__}: {e}")

        return self._generate_report()

    def _generate_report(self) -> dict:
        implemented = sum(1 for f in self.findings if f.status == ImplementationStatus.IMPLEMENTED)
        partial = sum(1 for f in self.findings if f.status == ImplementationStatus.PARTIAL)
        not_implemented = sum(1 for f in self.findings if f.status == ImplementationStatus.NOT_IMPLEMENTED)
        total = len(self.findings)
        maturity_pct = ((implemented + partial * 0.5) / total * 100) if total > 0 else 0

        by_theme: Dict[str, dict] = {}
        for f in self.findings:
            theme = f.theme
            if theme not in by_theme:
                by_theme[theme] = {"implemented": 0, "partial": 0, "not_implemented": 0}
            if f.status == ImplementationStatus.IMPLEMENTED:
                by_theme[theme]["implemented"] += 1
            elif f.status == ImplementationStatus.PARTIAL:
                by_theme[theme]["partial"] += 1
            else:
                by_theme[theme]["not_implemented"] += 1

        critical_gaps = [
            f for f in self.findings
            if f.status != ImplementationStatus.IMPLEMENTED and f.priority == "Critical"
        ]

        return {
            "scan_metadata": {
                "timestamp": self.scan_timestamp,
                "analyzer_version": "2.0.0",
                "framework": "ISO/IEC 27001:2022",
            },
            "summary": {
                "total_controls_checked": total,
                "implemented": implemented,
                "partial": partial,
                "not_implemented": not_implemented,
                "maturity_percentage": round(maturity_pct, 1),
                "critical_gaps": len(critical_gaps),
            },
            "by_theme": by_theme,
            "findings": [
                {
                    "clause_ref": f.clause_ref,
                    "control_name": f.control_name,
                    "theme": f.theme,
                    "status": f.status.value,
                    "priority": f.priority,
                    "effort": f.effort,
                    "current_state": f.current_state,
                    "gap_description": f.gap_description,
                    "recommended_action": f.recommended_action,
                    "timestamp": f.timestamp,
                }
                for f in self.findings
            ],
        }


def _load_config(path: str) -> dict:
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ISO 27001:2022 gap analyzer")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--output", default="iso27001_gap_report.json", help="Output JSON path")
    args = parser.parse_args()

    if args.config:
        config = _load_config(args.config)
    else:
        config = {
            "governance": {"context_document_exists": True, "stakeholder_register_exists": True},
            "risk_management": {
                "formal_risk_assessment_completed": True,
                "days_since_last_risk_assessment": 180,
                "risk_register_maintained": True,
                "soa_exists": True,
                "days_since_soa_review": 90,
            },
            "policies": {
                "isms_policy_exists": True,
                "days_since_policy_review": 200,
                "approved_by_management": True,
            },
            "people": {
                "security_training_program": True,
                "pct_staff_completed_training": 92,
                "phishing_simulation_active": True,
                "pre_employment_background_check": True,
                "screening_policy_documented": True,
                "remote_work_policy_exists": True,
                "remote_access_vpn_required": True,
                "endpoint_protection_enforced": True,
            },
            "physical": {
                "physical_access_controls": True,
                "cctv_deployed": True,
                "visitor_log_maintained": True,
            },
            "technology": {
                "mdm_deployed": True,
                "disk_encryption_enforced": True,
                "patch_management_active": True,
                "network_segmentation": True,
                "firewall_rules_reviewed_days": 90,
                "ids_ips_deployed": True,
            },
            "threat_intelligence": {"feed_subscribed": True, "alerts_actioned": True},
            "asset_management": {
                "asset_inventory_maintained": True,
                "asset_owners_assigned": True,
                "cmdb_tool": "ServiceNow",
            },
            "data_governance": {
                "data_classification_policy": True,
                "classification_labels_applied": False,
                "dlp_deployed": False,
            },
            "development": {
                "secure_sdlc_policy": True,
                "sast_in_ci_pipeline": True,
                "dast_conducted": True,
                "days_since_pentest": 200,
            },
        }

    analyzer = ISO27001GapAnalyzer(config=config)
    report = analyzer.run_all_checks()

    print("\n" + "=" * 60)
    print("ISO 27001:2022 GAP ANALYSIS REPORT")
    print("=" * 60)
    print(f"Maturity Score:    {report['summary']['maturity_percentage']}%")
    print(f"Implemented:       {report['summary']['implemented']}/{report['summary']['total_controls_checked']}")
    print(f"Partial:           {report['summary']['partial']}")
    print(f"Not Implemented:   {report['summary']['not_implemented']}")
    print(f"Critical Gaps:     {report['summary']['critical_gaps']}")
    print("=" * 60)
    print("\nBreakdown by Theme:")
    for theme, counts in report["by_theme"].items():
        print(f"  {theme:<20} | OK {counts['implemented']}  PARTIAL {counts['partial']}  GAP {counts['not_implemented']}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved to {args.output}")
