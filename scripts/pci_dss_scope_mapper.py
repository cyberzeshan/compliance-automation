#!/usr/bin/env python3
"""
pci_dss_scope_mapper.py
PCI-DSS v4.0 Cardholder Data Environment Scope Mapper & Control Checker
Author: Zeshan Ahmad | github.com/cyberzeshan

Maps your CDE (Cardholder Data Environment) components and validates controls
across all 12 PCI-DSS v4.0 requirements. Produces a scope diagram and gap report.

Usage:
    python3 pci_dss_scope_mapper.py --config config.yaml --output pci_report.json
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


class ComplianceStatus(Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    COMPENSATING_CONTROL = "COMPENSATING_CONTROL"
    NOT_APPLICABLE = "N/A"
    IN_PROGRESS = "IN_PROGRESS"


class ComponentType(Enum):
    IN_SCOPE = "IN_SCOPE"
    CONNECTED_TO = "CONNECTED_TO"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    SEGMENTED = "SEGMENTED"


@dataclass
class CDEComponent:
    component_id: str
    name: str
    component_type: str
    scope_classification: ComponentType
    stores_pan: bool
    transmits_pan: bool
    processes_pan: bool
    security_controls: List[str]
    notes: Optional[str] = None


@dataclass
class RequirementResult:
    req_number: str
    req_title: str
    status: ComplianceStatus
    evidence: str
    findings: List[str] = field(default_factory=list)
    remediations: List[str] = field(default_factory=list)
    severity: str = "High"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class PCIDSSv4ScopeMapper:
    """
    PCI-DSS v4.0 scope mapper and requirement checker.
    Covers all 12 requirements and CDE component classification.
    """

    def __init__(self, config: dict):
        self.config = config
        self.cde_components: List[CDEComponent] = []
        self.results: List[RequirementResult] = []
        self.scan_timestamp = datetime.utcnow().isoformat()
        self._load_cde_components()

    def _load_cde_components(self):
        """Parse CDE component inventory from config"""
        components = self.config.get("cde_components", [])
        for comp in components:
            self.cde_components.append(
                CDEComponent(
                    component_id=comp.get("id", "UNKNOWN"),
                    name=comp.get("name", ""),
                    component_type=comp.get("type", "server"),
                    scope_classification=ComponentType[comp.get("scope", "IN_SCOPE")],
                    stores_pan=comp.get("stores_pan", False),
                    transmits_pan=comp.get("transmits_pan", False),
                    processes_pan=comp.get("processes_pan", False),
                    security_controls=comp.get("controls", []),
                    notes=comp.get("notes"),
                )
            )
        logger.info(f"Loaded {len(self.cde_components)} CDE components")

    # ── Req 1: Network Security Controls ─────────────────────────────────────

    def check_req1_network_controls(self) -> RequirementResult:
        """Req 1 — Install and maintain network security controls"""
        firewall_deployed = self.config.get("network", {}).get("firewall_deployed", False)
        cde_segmented = self.config.get("network", {}).get("cde_segmented", False)
        inbound_rules_restrict = self.config.get("network", {}).get(
            "inbound_rules_restrict_to_necessary", False
        )
        network_diagram_exists = self.config.get("network", {}).get("network_diagram_current", False)

        findings = []
        if not firewall_deployed:
            findings.append("Firewall not deployed around CDE")
        if not cde_segmented:
            findings.append("CDE is not segmented from non-CDE networks")
        if not inbound_rules_restrict:
            findings.append("Inbound firewall rules not restricted to necessary traffic only")
        if not network_diagram_exists:
            findings.append("Current network diagram does not exist")

        if not findings:
            return RequirementResult(
                req_number="1",
                req_title="Network Security Controls",
                status=ComplianceStatus.COMPLIANT,
                evidence="Firewall deployed; CDE segmented; restrictive rules; current network diagram",
                severity="Critical",
            )
        return RequirementResult(
            req_number="1",
            req_title="Network Security Controls",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} gaps identified",
            findings=findings,
            remediations=[
                "Deploy stateful firewall between CDE and untrusted networks",
                "Implement network segmentation to isolate CDE",
                "Restrict all inbound/outbound traffic to documented business need",
                "Maintain and review network diagrams quarterly",
            ],
            severity="Critical",
        )

    # ── Req 2: Secure Configurations ─────────────────────────────────────────

    def check_req2_secure_config(self) -> RequirementResult:
        """Req 2 — Apply secure configurations to all system components"""
        hardening_standard = self.config.get("configuration", {}).get(
            "hardening_standard_documented", False
        )
        default_creds_changed = self.config.get("configuration", {}).get(
            "default_credentials_changed", False
        )
        config_baseline_enforced = self.config.get("configuration", {}).get(
            "config_baseline_enforced", False
        )

        findings = []
        if not hardening_standard:
            findings.append("No documented hardening standard (CIS/NIST benchmarks)")
        if not default_creds_changed:
            findings.append("Default vendor credentials not confirmed as changed")
        if not config_baseline_enforced:
            findings.append("Configuration baseline not automatically enforced")

        if not findings:
            return RequirementResult(
                req_number="2",
                req_title="Secure Configurations",
                status=ComplianceStatus.COMPLIANT,
                evidence="Hardening standard documented; defaults changed; baseline enforced",
                severity="Critical",
            )
        return RequirementResult(
            req_number="2",
            req_title="Secure Configurations",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} gaps identified",
            findings=findings,
            remediations=[
                "Adopt CIS Benchmarks or equivalent hardening standards",
                "Audit and change all default credentials on CDE systems",
                "Deploy configuration management (Ansible/Chef/Puppet) to enforce baselines",
            ],
            severity="Critical",
        )

    # ── Req 3: Protect Stored Account Data ────────────────────────────────────

    def check_req3_protect_stored_pan(self) -> RequirementResult:
        """Req 3 — Protect stored account data"""
        pan_storage_minimized = self.config.get("data_protection", {}).get(
            "pan_storage_minimized", False
        )
        pan_encrypted_at_rest = self.config.get("data_protection", {}).get(
            "pan_encrypted_at_rest", False
        )
        truncation_or_masking = self.config.get("data_protection", {}).get(
            "pan_truncated_or_masked", False
        )
        key_management_documented = self.config.get("data_protection", {}).get(
            "key_management_documented", False
        )
        sad_not_stored = self.config.get("data_protection", {}).get(
            "sensitive_auth_data_not_stored_post_auth", True
        )

        findings = []
        if not pan_storage_minimized:
            findings.append("PAN storage not minimized to business necessity")
        if not pan_encrypted_at_rest:
            findings.append("PAN not encrypted at rest (AES-256 or equivalent required)")
        if not truncation_or_masking:
            findings.append("PAN not truncated/masked in non-payment contexts")
        if not key_management_documented:
            findings.append("Cryptographic key management procedures not documented")
        if not sad_not_stored:
            findings.append("Sensitive authentication data may be stored post-authorization")

        if not findings:
            return RequirementResult(
                req_number="3",
                req_title="Protect Stored Account Data",
                status=ComplianceStatus.COMPLIANT,
                evidence="PAN minimized, encrypted, masked; key management documented; no SAD stored",
                severity="Critical",
            )
        return RequirementResult(
            req_number="3",
            req_title="Protect Stored Account Data",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} critical data protection gaps",
            findings=findings,
            remediations=[
                "Map all locations storing PAN and purge unnecessary storage",
                "Encrypt all PAN at rest using AES-256 or equivalent",
                "Implement PAN masking in all displays/logs",
                "Document key management lifecycle (generation, rotation, destruction)",
                "Confirm SAD (CVV, full track data, PINs) not stored post-authorization",
            ],
            severity="Critical",
        )

    # ── Req 4: Protect Cardholder Data in Transit ─────────────────────────────

    def check_req4_protect_data_transit(self) -> RequirementResult:
        """Req 4 — Protect cardholder data with strong cryptography during transmission"""
        tls_enforced = self.config.get("data_protection", {}).get("tls_1_2_or_higher_enforced", False)
        weak_protocols_disabled = self.config.get("data_protection", {}).get(
            "weak_protocols_disabled", False
        )
        certificate_management = self.config.get("data_protection", {}).get(
            "certificate_management_process", False
        )

        findings = []
        if not tls_enforced:
            findings.append("TLS 1.2+ not enforced for all PAN transmissions")
        if not weak_protocols_disabled:
            findings.append("Weak/insecure protocols (SSL, TLS 1.0/1.1) not disabled")
        if not certificate_management:
            findings.append("No certificate management/rotation process")

        if not findings:
            return RequirementResult(
                req_number="4",
                req_title="Protect Cardholder Data in Transit",
                status=ComplianceStatus.COMPLIANT,
                evidence="TLS 1.2+ enforced; weak protocols disabled; cert management in place",
                severity="Critical",
            )
        return RequirementResult(
            req_number="4",
            req_title="Protect Cardholder Data in Transit",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} transit encryption gaps",
            findings=findings,
            remediations=[
                "Enforce TLS 1.2+ (prefer 1.3) on all endpoints handling PAN",
                "Disable SSL, TLS 1.0, TLS 1.1, and weak cipher suites",
                "Implement certificate lifecycle management with auto-renewal",
            ],
            severity="Critical",
        )

    # ── Req 5: Malware Protection ─────────────────────────────────────────────

    def check_req5_malware_protection(self) -> RequirementResult:
        """Req 5 — Protect all systems against malware"""
        av_deployed_all_systems = self.config.get("endpoint_security", {}).get(
            "av_deployed_all_systems", False
        )
        av_sigs_auto_update = self.config.get("endpoint_security", {}).get(
            "av_signatures_auto_updated", False
        )
        edr_deployed = self.config.get("endpoint_security", {}).get("edr_deployed", False)
        av_logs_reviewed = self.config.get("endpoint_security", {}).get(
            "av_logs_centrally_reviewed", False
        )

        findings = []
        if not av_deployed_all_systems:
            findings.append("Anti-malware not deployed on all CDE systems")
        if not av_sigs_auto_update:
            findings.append("AV signatures not set to auto-update")
        if not av_logs_reviewed:
            findings.append("AV/EDR logs not centrally reviewed")

        if not findings:
            return RequirementResult(
                req_number="5",
                req_title="Anti-Malware Protection",
                status=ComplianceStatus.COMPLIANT,
                evidence=f"AV/EDR deployed; auto-updates enabled; logs reviewed {'(EDR active)' if edr_deployed else ''}",
                severity="High",
            )
        return RequirementResult(
            req_number="5",
            req_title="Anti-Malware Protection",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} anti-malware gaps",
            findings=findings,
            remediations=[
                "Deploy AV/EDR on all in-scope systems including servers",
                "Configure automatic signature updates",
                "Forward AV/EDR logs to SIEM for centralized review",
            ],
            severity="High",
        )

    # ── Req 6: Secure Systems & Software ─────────────────────────────────────

    def check_req6_secure_software(self) -> RequirementResult:
        """Req 6 — Develop and maintain secure systems and software"""
        patch_critical_within_sla = self.config.get("patch_management", {}).get(
            "critical_patches_within_30_days", False
        )
        secure_coding_standard = self.config.get("development", {}).get(
            "secure_coding_standard", False
        )
        web_app_protected = self.config.get("development", {}).get(
            "waf_or_code_review_for_public_apps", False
        )
        change_control_process = self.config.get("change_management", {}).get(
            "formal_process_documented", False
        )

        findings = []
        if not patch_critical_within_sla:
            findings.append("Critical security patches not applied within 30 days")
        if not secure_coding_standard:
            findings.append("Secure coding standards not established (OWASP Top 10 recommended)")
        if not web_app_protected:
            findings.append("Public-facing web applications not protected by WAF or reviewed via code audit")
        if not change_control_process:
            findings.append("Formal change control process not documented")

        if not findings:
            return RequirementResult(
                req_number="6",
                req_title="Secure Systems & Software",
                status=ComplianceStatus.COMPLIANT,
                evidence="Patches applied within SLA; secure coding; WAF/review; change control",
                severity="Critical",
            )
        return RequirementResult(
            req_number="6",
            req_title="Secure Systems & Software",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} software security gaps",
            findings=findings,
            remediations=[
                "Apply critical/high patches within 30 days on all in-scope systems",
                "Adopt OWASP ASVS or equivalent secure coding standard",
                "Deploy WAF for all public-facing payment applications",
                "Enforce peer review + security testing in change process",
            ],
            severity="Critical",
        )

    # ── Req 7: Access Control ─────────────────────────────────────────────────

    def check_req7_access_control(self) -> RequirementResult:
        """Req 7 — Restrict access to system components by business need"""
        least_privilege = self.config.get("iam", {}).get("least_privilege_enforced", False)
        access_matrix_documented = self.config.get("iam", {}).get("access_matrix_documented", False)
        quarterly_review = self.config.get("iam", {}).get("days_since_last_access_review", 999) <= 90

        findings = []
        if not least_privilege:
            findings.append("Least privilege not enforced on CDE systems")
        if not access_matrix_documented:
            findings.append("Access control matrix not documented")
        if not quarterly_review:
            findings.append("Access review not completed within last 90 days")

        if not findings:
            return RequirementResult(
                req_number="7",
                req_title="Restrict Access by Need to Know",
                status=ComplianceStatus.COMPLIANT,
                evidence="Least privilege enforced; access matrix documented; quarterly review done",
                severity="Critical",
            )
        return RequirementResult(
            req_number="7",
            req_title="Restrict Access by Need to Know",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} access control gaps",
            findings=findings,
            remediations=[
                "Implement RBAC with least-privilege for all CDE access",
                "Document and maintain an access control matrix",
                "Conduct and document quarterly access reviews",
            ],
            severity="Critical",
        )

    # ── Req 8: Identify & Authenticate ───────────────────────────────────────

    def check_req8_authentication(self) -> RequirementResult:
        """Req 8 — Identify users and authenticate access to system components"""
        mfa_for_remote = self.config.get("iam", {}).get("mfa_for_remote_access", False)
        mfa_for_cde = self.config.get("iam", {}).get("mfa_for_cde_access", False)
        password_policy_compliant = self.config.get("iam", {}).get(
            "password_policy_pci_compliant", False
        )
        no_shared_accounts = self.config.get("iam", {}).get("no_shared_accounts_in_cde", False)

        findings = []
        if not mfa_for_remote:
            findings.append("MFA not required for all remote access into CDE")
        if not mfa_for_cde:
            findings.append("MFA not enforced for all user access to CDE (required by PCI v4)")
        if not password_policy_compliant:
            findings.append("Password policy does not meet PCI v4 requirements (min 12 chars, complexity)")
        if not no_shared_accounts:
            findings.append("Shared/group accounts exist in the CDE")

        if not findings:
            return RequirementResult(
                req_number="8",
                req_title="Identify & Authenticate Users",
                status=ComplianceStatus.COMPLIANT,
                evidence="MFA enforced for remote + CDE access; compliant password policy; no shared accounts",
                severity="Critical",
            )
        return RequirementResult(
            req_number="8",
            req_title="Identify & Authenticate Users",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} authentication gaps",
            findings=findings,
            remediations=[
                "Enforce MFA for all remote access and all CDE access (PCI v4 requirement)",
                "Update password policy: min 12 chars, complexity, 90-day max age",
                "Eliminate all shared accounts; assign unique IDs to all users",
            ],
            severity="Critical",
        )

    # ── Req 9: Physical Access ────────────────────────────────────────────────

    def check_req9_physical_access(self) -> RequirementResult:
        """Req 9 — Restrict physical access to cardholder data"""
        physical_access_logs = self.config.get("physical", {}).get(
            "physical_access_logs_maintained", False
        )
        media_inventory = self.config.get("physical", {}).get(
            "physical_media_inventory_maintained", False
        )
        media_destruction_process = self.config.get("physical", {}).get(
            "media_destruction_documented", False
        )
        pos_device_inspection = self.config.get("physical", {}).get(
            "pos_device_anti_tampering_inspections", False
        )

        findings = []
        if not physical_access_logs:
            findings.append("Physical access logs for CDE areas not maintained")
        if not media_inventory:
            findings.append("Physical media containing CHD not inventoried")
        if not media_destruction_process:
            findings.append("Secure media destruction process not documented")
        if not pos_device_inspection:
            findings.append("POS device anti-tampering inspections not conducted")

        if not findings:
            return RequirementResult(
                req_number="9",
                req_title="Physical Access Controls",
                status=ComplianceStatus.COMPLIANT,
                evidence="Access logs; media inventory; secure destruction; POS inspections all in place",
                severity="High",
            )
        return RequirementResult(
            req_number="9",
            req_title="Physical Access Controls",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} physical control gaps",
            findings=findings,
            remediations=[
                "Maintain physical access logs for all CDE areas (badge + visitor)",
                "Inventory all physical media containing CHD",
                "Document secure media destruction procedures (cross-cut shred / degauss)",
                "Inspect POS devices regularly for tampering; document inspections",
            ],
            severity="High",
        )

    # ── Req 10: Logging & Monitoring ──────────────────────────────────────────

    def check_req10_logging_monitoring(self) -> RequirementResult:
        """Req 10 — Log and monitor all access to system components and cardholder data"""
        audit_logs_all_components = self.config.get("monitoring", {}).get(
            "audit_logs_on_all_cde_components", False
        )
        log_retention_days = self.config.get("monitoring", {}).get("log_retention_days", 0)
        logs_reviewed_daily = self.config.get("monitoring", {}).get("logs_reviewed_daily", False)
        time_sync = self.config.get("monitoring", {}).get("ntp_time_synchronization", False)

        findings = []
        if not audit_logs_all_components:
            findings.append("Audit logging not enabled on all CDE system components")
        if log_retention_days < 365:
            findings.append(f"Log retention is {log_retention_days} days (minimum: 365, online: 90)")
        if not logs_reviewed_daily:
            findings.append("Security event logs not reviewed at least daily")
        if not time_sync:
            findings.append("NTP time synchronization not configured on all CDE components")

        if not findings:
            return RequirementResult(
                req_number="10",
                req_title="Logging & Monitoring",
                status=ComplianceStatus.COMPLIANT,
                evidence=f"Logs on all components; {log_retention_days}d retention; daily review; NTP sync",
                severity="Critical",
            )
        return RequirementResult(
            req_number="10",
            req_title="Logging & Monitoring",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} logging/monitoring gaps",
            findings=findings,
            remediations=[
                "Enable audit logging on all CDE components (user actions, system events, failed auths)",
                "Retain logs 12 months total, with 90 days immediately available",
                "Configure SIEM alerting for daily automated review",
                "Configure NTP on all CDE system components",
            ],
            severity="Critical",
        )

    # ── Req 11: Security Testing ──────────────────────────────────────────────

    def check_req11_security_testing(self) -> RequirementResult:
        """Req 11 — Test security of systems and networks regularly"""
        quarterly_vuln_scans = self.config.get("security_testing", {}).get(
            "quarterly_internal_vuln_scans", False
        )
        quarterly_external_scans = self.config.get("security_testing", {}).get(
            "quarterly_external_scans_by_asv", False
        )
        annual_pentest = self.config.get("security_testing", {}).get(
            "days_since_annual_pentest", 999
        ) <= 365
        ids_deployed = self.config.get("monitoring", {}).get("ids_ips_deployed", False)

        findings = []
        if not quarterly_vuln_scans:
            findings.append("Quarterly internal vulnerability scans not performed")
        if not quarterly_external_scans:
            findings.append("Quarterly external scans by approved scanning vendor (ASV) not performed")
        if not annual_pentest:
            findings.append("Annual penetration test of CDE not completed in past 12 months")
        if not ids_deployed:
            findings.append("IDS/IPS not deployed on CDE network perimeter")

        if not findings:
            return RequirementResult(
                req_number="11",
                req_title="Security Testing",
                status=ComplianceStatus.COMPLIANT,
                evidence="Quarterly internal + ASV scans; annual pentest; IDS/IPS deployed",
                severity="High",
            )
        return RequirementResult(
            req_number="11",
            req_title="Security Testing",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} testing gaps",
            findings=findings,
            remediations=[
                "Schedule quarterly internal vulnerability scans of CDE",
                "Engage an ASV for quarterly external scans",
                "Conduct annual internal + external penetration test of CDE",
                "Deploy IDS/IPS with alerting at CDE network boundary",
            ],
            severity="High",
        )

    # ── Req 12: Policies & Security Program ───────────────────────────────────

    def check_req12_security_program(self) -> RequirementResult:
        """Req 12 — Support information security with organizational policies and programs"""
        isms_policy_exists = self.config.get("governance", {}).get("security_policy_exists", False)
        risk_assessment_annual = self.config.get("risk_management", {}).get(
            "days_since_last_risk_assessment", 999
        ) <= 365
        incident_response_plan = self.config.get("incident_response", {}).get(
            "ir_plan_documented", False
        )
        tpsp_program = self.config.get("vendor_risk", {}).get(
            "tpsp_program_documented", False
        )

        findings = []
        if not isms_policy_exists:
            findings.append("Information security policy not documented")
        if not risk_assessment_annual:
            findings.append("Annual risk assessment not completed")
        if not incident_response_plan:
            findings.append("Incident response plan not documented")
        if not tpsp_program:
            findings.append("Third-party service provider (TPSP) security program not documented")

        if not findings:
            return RequirementResult(
                req_number="12",
                req_title="Security Policies & Program",
                status=ComplianceStatus.COMPLIANT,
                evidence="Security policy; annual RA; IR plan; TPSP program all in place",
                severity="High",
            )
        return RequirementResult(
            req_number="12",
            req_title="Security Policies & Program",
            status=ComplianceStatus.NON_COMPLIANT,
            evidence=f"{len(findings)} program gaps",
            findings=findings,
            remediations=[
                "Document and publish comprehensive information security policy",
                "Conduct and document annual targeted risk analysis",
                "Develop, test, and maintain an incident response plan",
                "Document TPSP responsibilities and maintain a service provider inventory",
            ],
            severity="High",
        )

    # ── Scope Summary ─────────────────────────────────────────────────────────

    def _build_scope_summary(self) -> dict:
        in_scope = [c for c in self.cde_components if c.scope_classification == ComponentType.IN_SCOPE]
        connected = [c for c in self.cde_components if c.scope_classification == ComponentType.CONNECTED_TO]
        segmented = [c for c in self.cde_components if c.scope_classification == ComponentType.SEGMENTED]

        return {
            "total_components": len(self.cde_components),
            "in_scope_count": len(in_scope),
            "connected_to_count": len(connected),
            "segmented_count": len(segmented),
            "components": [
                {
                    "id": c.component_id,
                    "name": c.name,
                    "type": c.component_type,
                    "scope": c.scope_classification.value,
                    "stores_pan": c.stores_pan,
                    "transmits_pan": c.transmits_pan,
                    "processes_pan": c.processes_pan,
                    "controls": c.security_controls,
                    "notes": c.notes,
                }
                for c in self.cde_components
            ],
        }

    # ── Runner & Report ───────────────────────────────────────────────────────

    def run_all_checks(self) -> dict:
        logger.info("Starting PCI-DSS v4.0 scope mapping and requirement checks...")

        checks = [
            self.check_req1_network_controls,
            self.check_req2_secure_config,
            self.check_req3_protect_stored_pan,
            self.check_req4_protect_data_transit,
            self.check_req5_malware_protection,
            self.check_req6_secure_software,
            self.check_req7_access_control,
            self.check_req8_authentication,
            self.check_req9_physical_access,
            self.check_req10_logging_monitoring,
            self.check_req11_security_testing,
            self.check_req12_security_program,
        ]

        for check in checks:
            try:
                result = check()
                self.results.append(result)
                symbol = "✅" if result.status == ComplianceStatus.COMPLIANT else "❌"
                logger.info(f"{symbol} Req {result.req_number}: {result.req_title} — {result.status.value}")
            except Exception as e:
                logger.error(f"Error running {check.__name__}: {e}")

        return self._generate_report()

    def _generate_report(self) -> dict:
        compliant = sum(1 for r in self.results if r.status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for r in self.results if r.status == ComplianceStatus.NON_COMPLIANT)
        total = len(self.results)
        compliance_pct = (compliant / total * 100) if total > 0 else 0

        all_findings = []
        for r in self.results:
            for f in r.findings:
                all_findings.append({"requirement": r.req_number, "finding": f, "severity": r.severity})

        return {
            "scan_metadata": {
                "timestamp": self.scan_timestamp,
                "scanner_version": "2.0.0",
                "framework": "PCI-DSS v4.0",
            },
            "scope": self._build_scope_summary(),
            "summary": {
                "requirements_checked": total,
                "compliant": compliant,
                "non_compliant": non_compliant,
                "compliance_percentage": round(compliance_pct, 1),
                "total_individual_findings": len(all_findings),
            },
            "requirements": [
                {
                    "req_number": r.req_number,
                    "req_title": r.req_title,
                    "status": r.status.value,
                    "severity": r.severity,
                    "evidence": r.evidence,
                    "findings": r.findings,
                    "remediations": r.remediations,
                    "timestamp": r.timestamp,
                }
                for r in self.results
            ],
            "all_findings": all_findings,
        }


def _load_config(path: str) -> dict:
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCI-DSS v4.0 scope mapper and compliance checker")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--output", default="pci_dss_report.json", help="Output JSON path")
    args = parser.parse_args()

    if args.config:
        config = _load_config(args.config)
    else:
        config = {
            "cde_components": [
                {
                    "id": "WEB-01",
                    "name": "Payment Web Application",
                    "type": "web_server",
                    "scope": "IN_SCOPE",
                    "stores_pan": False,
                    "transmits_pan": True,
                    "processes_pan": True,
                    "controls": ["WAF", "TLS1.3", "SAST"],
                },
                {
                    "id": "DB-01",
                    "name": "Cardholder Database",
                    "type": "database",
                    "scope": "IN_SCOPE",
                    "stores_pan": True,
                    "transmits_pan": False,
                    "processes_pan": True,
                    "controls": ["AES-256", "access_logging", "least_privilege"],
                },
                {
                    "id": "CORP-01",
                    "name": "Corporate Network",
                    "type": "network_segment",
                    "scope": "CONNECTED_TO",
                    "stores_pan": False,
                    "transmits_pan": False,
                    "processes_pan": False,
                    "controls": ["firewall", "vlans"],
                },
            ],
            "network": {
                "firewall_deployed": True,
                "cde_segmented": True,
                "inbound_rules_restrict_to_necessary": True,
                "network_diagram_current": True,
            },
            "configuration": {
                "hardening_standard_documented": True,
                "default_credentials_changed": True,
                "config_baseline_enforced": True,
            },
            "data_protection": {
                "pan_storage_minimized": True,
                "pan_encrypted_at_rest": True,
                "pan_truncated_or_masked": True,
                "key_management_documented": True,
                "sensitive_auth_data_not_stored_post_auth": True,
                "tls_1_2_or_higher_enforced": True,
                "weak_protocols_disabled": True,
                "certificate_management_process": True,
            },
            "endpoint_security": {
                "av_deployed_all_systems": True,
                "av_signatures_auto_updated": True,
                "edr_deployed": True,
                "av_logs_centrally_reviewed": True,
            },
            "patch_management": {"critical_patches_within_30_days": True},
            "development": {
                "secure_coding_standard": True,
                "waf_or_code_review_for_public_apps": True,
            },
            "change_management": {"formal_process_documented": True},
            "iam": {
                "least_privilege_enforced": True,
                "access_matrix_documented": True,
                "days_since_last_access_review": 45,
                "mfa_for_remote_access": True,
                "mfa_for_cde_access": True,
                "password_policy_pci_compliant": True,
                "no_shared_accounts_in_cde": True,
            },
            "physical": {
                "physical_access_logs_maintained": True,
                "physical_media_inventory_maintained": True,
                "media_destruction_documented": True,
                "pos_device_anti_tampering_inspections": True,
            },
            "monitoring": {
                "audit_logs_on_all_cde_components": True,
                "log_retention_days": 365,
                "logs_reviewed_daily": True,
                "ntp_time_synchronization": True,
                "ids_ips_deployed": True,
            },
            "security_testing": {
                "quarterly_internal_vuln_scans": True,
                "quarterly_external_scans_by_asv": True,
                "days_since_annual_pentest": 180,
            },
            "governance": {"security_policy_exists": True},
            "risk_management": {"days_since_last_risk_assessment": 180},
            "incident_response": {"ir_plan_documented": True},
            "vendor_risk": {"tpsp_program_documented": True},
        }

    mapper = PCIDSSv4ScopeMapper(config=config)
    report = mapper.run_all_checks()

    print("\n" + "=" * 60)
    print("PCI-DSS v4.0 COMPLIANCE REPORT")
    print("=" * 60)
    print(f"Compliance Score:    {report['summary']['compliance_percentage']}%")
    print(f"Requirements Met:    {report['summary']['compliant']}/{report['summary']['requirements_checked']}")
    print(f"Individual Findings: {report['summary']['total_individual_findings']}")
    print(f"CDE Components:      {report['scope']['total_components']} "
          f"({report['scope']['in_scope_count']} in-scope)")
    print("=" * 60)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved to {args.output}")
