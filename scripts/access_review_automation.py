#!/usr/bin/env python3
"""
access_review_automation.py
Quarterly Access Review Workflow Automation
Author: Zeshan Ahmad | github.com/cyberzeshan

Automates the quarterly access review process:
  1. Pulls user/role/group data from config or directory API
  2. Identifies stale accounts, dormant users, and over-privileged assignments
  3. Generates reviewer task packages per department/manager
  4. Tracks review completion and escalation
  5. Produces certification report with sign-off evidence

Usage:
    python3 access_review_automation.py --config config.yaml --output review_report.json
"""

import json
import argparse
import logging
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

STALE_ACCOUNT_DAYS = 90
PRIVILEGED_REVIEW_DAYS = 30
MAX_DAYS_WITHOUT_REVIEW = 90


class AccountStatus(Enum):
    ACTIVE = "ACTIVE"
    STALE = "STALE"
    DORMANT = "DORMANT"
    TERMINATED = "TERMINATED"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"


class ReviewDecision(Enum):
    CERTIFY = "CERTIFY"
    REVOKE = "REVOKE"
    MODIFY = "MODIFY"
    PENDING = "PENDING"
    ESCALATED = "ESCALATED"


class RiskFlag(Enum):
    STALE_ACCOUNT = "stale_account"
    EXCESS_PRIVILEGE = "excess_privilege"
    NO_MFA = "no_mfa"
    DORMANT = "dormant"
    ORPHANED = "orphaned"
    ADMIN_WITHOUT_JUSTIFICATION = "admin_without_justification"
    TERMINATED_WITH_ACCESS = "terminated_with_access"


@dataclass
class UserAccessRecord:
    user_id: str
    username: str
    display_name: str
    department: str
    manager: str
    job_title: str
    account_status: AccountStatus
    roles: List[str]
    groups: List[str]
    last_login: Optional[str]
    days_since_login: int
    mfa_enabled: bool
    is_privileged: bool
    account_created: Optional[str] = None
    risk_flags: List[RiskFlag] = field(default_factory=list)
    review_decision: ReviewDecision = ReviewDecision.PENDING
    reviewer_notes: Optional[str] = None


@dataclass
class ReviewTask:
    task_id: str
    reviewer_email: str
    department: str
    users_to_review: List[str]
    due_date: str
    high_risk_count: int
    status: str = "OPEN"
    completed_at: Optional[str] = None


class AccessReviewAutomation:
    """
    Automates quarterly access reviews with risk-flagging and reporting.
    Extend _load_users() to pull from your identity provider (Okta, Azure AD, etc.).
    """

    def __init__(self, config: dict):
        self.config = config
        self.users: List[UserAccessRecord] = []
        self.review_tasks: List[ReviewTask] = []
        self.review_timestamp = datetime.now(timezone.utc).isoformat()
        self.review_period = config.get("review", {}).get("period", "Q2 2026")
        self.review_due_date = config.get("review", {}).get("due_date", "")
        self._load_users()

    # ── Data Loading ──────────────────────────────────────────────────────────

    def _load_users(self):
        """Load user records from config. Replace with live IdP API call."""
        raw_users = self.config.get("users", [])
        for u in raw_users:
            last_login = u.get("last_login")
            days_since = self._days_since(last_login) if last_login else 999

            status = AccountStatus.ACTIVE
            if u.get("terminated"):
                status = AccountStatus.TERMINATED
            elif u.get("is_service_account"):
                status = AccountStatus.SERVICE_ACCOUNT
            elif days_since >= STALE_ACCOUNT_DAYS:
                status = AccountStatus.STALE if days_since < 180 else AccountStatus.DORMANT

            record = UserAccessRecord(
                user_id=u.get("id", ""),
                username=u.get("username", ""),
                display_name=u.get("display_name", ""),
                department=u.get("department", "Unknown"),
                manager=u.get("manager", ""),
                job_title=u.get("job_title", ""),
                account_status=status,
                roles=u.get("roles", []),
                groups=u.get("groups", []),
                last_login=last_login,
                days_since_login=days_since,
                mfa_enabled=u.get("mfa_enabled", False),
                is_privileged=u.get("is_privileged", False),
                account_created=u.get("account_created"),
            )
            self._apply_risk_flags(record, u)
            self.users.append(record)

        logger.info(f"Loaded {len(self.users)} user records for review")

    @staticmethod
    def _days_since(date_str: str) -> int:
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except (ValueError, TypeError):
            return 999

    def _apply_risk_flags(self, record: UserAccessRecord, raw: dict):
        """Flag accounts that require special attention in the access review"""
        if record.account_status in (AccountStatus.STALE, AccountStatus.DORMANT):
            record.risk_flags.append(RiskFlag.STALE_ACCOUNT if record.account_status == AccountStatus.STALE
                                     else RiskFlag.DORMANT)

        if record.is_privileged and not raw.get("privileged_justification"):
            record.risk_flags.append(RiskFlag.ADMIN_WITHOUT_JUSTIFICATION)

        if not record.mfa_enabled:
            record.risk_flags.append(RiskFlag.NO_MFA)

        privileged_roles = self.config.get("review", {}).get("privileged_role_names", ["admin", "superuser"])
        non_job_roles = [
            r for r in record.roles
            if any(priv in r.lower() for priv in privileged_roles)
            and not record.is_privileged
        ]
        if non_job_roles:
            record.risk_flags.append(RiskFlag.EXCESS_PRIVILEGE)

        if record.account_status == AccountStatus.TERMINATED and (record.roles or record.groups):
            record.risk_flags.append(RiskFlag.TERMINATED_WITH_ACCESS)

        if not record.manager and record.account_status != AccountStatus.SERVICE_ACCOUNT:
            record.risk_flags.append(RiskFlag.ORPHANED)

    # ── Review Logic ──────────────────────────────────────────────────────────

    def auto_revoke_terminated(self):
        """Automatically flag terminated users with remaining access for revocation"""
        count = 0
        for user in self.users:
            if RiskFlag.TERMINATED_WITH_ACCESS in user.risk_flags:
                user.review_decision = ReviewDecision.REVOKE
                user.reviewer_notes = "Auto-flagged: terminated account with active access"
                count += 1
        if count:
            logger.warning(f"Auto-flagged {count} terminated accounts for access revocation")

    def generate_reviewer_tasks(self):
        """Group users by manager/department and create reviewer task packages"""
        by_reviewer: Dict[str, List[UserAccessRecord]] = {}

        for user in self.users:
            reviewer = user.manager or "unassigned@company.com"
            by_reviewer.setdefault(reviewer, []).append(user)

        due = self.review_due_date or (
            datetime.now(timezone.utc) + timedelta(days=14)
        ).strftime("%Y-%m-%d")

        for idx, (reviewer_email, users) in enumerate(by_reviewer.items(), 1):
            high_risk = sum(1 for u in users if u.risk_flags)
            task = ReviewTask(
                task_id=f"REVIEW-{self.review_period.replace(' ', '-')}-{idx:03d}",
                reviewer_email=reviewer_email,
                department=users[0].department if users else "Unknown",
                users_to_review=[u.username for u in users],
                due_date=due,
                high_risk_count=high_risk,
            )
            # Mark tasks with only terminated/auto-revoked users as complete
            if all(u.review_decision != ReviewDecision.PENDING for u in users):
                task.status = "COMPLETE"
                task.completed_at = self.review_timestamp
            self.review_tasks.append(task)

        logger.info(f"Generated {len(self.review_tasks)} reviewer task packages")

    def apply_simulated_completions(self):
        """
        Apply reviewer decisions from config (simulates completed reviews).
        In production, this reads from your GRC ticketing system or review portal.
        """
        decisions = self.config.get("review_decisions", {})
        for user in self.users:
            if user.username in decisions:
                entry = decisions[user.username]
                user.review_decision = ReviewDecision[entry.get("decision", "PENDING").upper()]
                user.reviewer_notes = entry.get("notes", "")

    def escalate_overdue(self):
        """Escalate pending tasks past the due date"""
        now = datetime.now(timezone.utc)
        escalated = 0
        for task in self.review_tasks:
            if task.status == "OPEN" and task.due_date:
                try:
                    due_dt = datetime.fromisoformat(task.due_date).replace(tzinfo=timezone.utc)
                    if now > due_dt:
                        task.status = "ESCALATED"
                        for username in task.users_to_review:
                            for user in self.users:
                                if user.username == username and user.review_decision == ReviewDecision.PENDING:
                                    user.review_decision = ReviewDecision.ESCALATED
                        escalated += 1
                except ValueError:
                    pass
        if escalated:
            logger.warning(f"Escalated {escalated} overdue review tasks")

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _build_statistics(self) -> dict:
        total = len(self.users)
        by_status: Dict[str, int] = {}
        by_decision: Dict[str, int] = {}
        risk_flag_counts: Dict[str, int] = {}

        for user in self.users:
            status_key = user.account_status.value
            by_status[status_key] = by_status.get(status_key, 0) + 1

            decision_key = user.review_decision.value
            by_decision[decision_key] = by_decision.get(decision_key, 0) + 1

            for flag in user.risk_flags:
                risk_flag_counts[flag.value] = risk_flag_counts.get(flag.value, 0) + 1

        certified = by_decision.get("CERTIFY", 0)
        revoked = by_decision.get("REVOKE", 0)
        pending = by_decision.get("PENDING", 0)
        completion_pct = ((total - pending) / total * 100) if total > 0 else 0

        return {
            "total_users": total,
            "by_account_status": by_status,
            "by_review_decision": by_decision,
            "risk_flag_breakdown": risk_flag_counts,
            "high_risk_accounts": sum(1 for u in self.users if u.risk_flags),
            "privileged_accounts": sum(1 for u in self.users if u.is_privileged),
            "accounts_without_mfa": sum(1 for u in self.users if not u.mfa_enabled),
            "completion_percentage": round(completion_pct, 1),
            "certifications": certified,
            "revocations": revoked,
            "pending_reviews": pending,
        }

    # ── Runner & Report ───────────────────────────────────────────────────────

    def run(self) -> dict:
        logger.info(f"Starting access review for period: {self.review_period}")

        self.auto_revoke_terminated()
        self.apply_simulated_completions()
        self.generate_reviewer_tasks()
        self.escalate_overdue()

        stats = self._build_statistics()

        logger.info(
            f"Review complete — {stats['completion_percentage']}% done; "
            f"{stats['revocations']} revocations; {stats['high_risk_accounts']} high-risk accounts"
        )

        return {
            "report_metadata": {
                "review_timestamp": self.review_timestamp,
                "review_period": self.review_period,
                "due_date": self.review_due_date,
                "tool_version": "2.0.0",
                "framework_alignment": ["SOC 2 CC6.2-CC6.3", "ISO 27001 A.5.15", "PCI-DSS Req 7-8"],
            },
            "statistics": stats,
            "reviewer_tasks": [
                {
                    "task_id": t.task_id,
                    "reviewer": t.reviewer_email,
                    "department": t.department,
                    "users_count": len(t.users_to_review),
                    "high_risk_count": t.high_risk_count,
                    "status": t.status,
                    "due_date": t.due_date,
                    "completed_at": t.completed_at,
                }
                for t in self.review_tasks
            ],
            "user_review_details": [
                {
                    "user_id": u.user_id,
                    "username": u.username,
                    "display_name": u.display_name,
                    "department": u.department,
                    "manager": u.manager,
                    "job_title": u.job_title,
                    "account_status": u.account_status.value,
                    "roles": u.roles,
                    "days_since_login": u.days_since_login,
                    "mfa_enabled": u.mfa_enabled,
                    "is_privileged": u.is_privileged,
                    "risk_flags": [f.value for f in u.risk_flags],
                    "review_decision": u.review_decision.value,
                    "reviewer_notes": u.reviewer_notes,
                }
                for u in self.users
            ],
        }


def _load_config(path: str) -> dict:
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Quarterly access review automation")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument("--output", default="access_review_report.json", help="Output JSON path")
    args = parser.parse_args()

    if args.config:
        config = _load_config(args.config)
    else:
        config = {
            "review": {
                "period": "Q2 2026",
                "due_date": "2026-07-01",
                "privileged_role_names": ["admin", "superuser", "root", "owner"],
            },
            "users": [
                {
                    "id": "U001",
                    "username": "alice.smith",
                    "display_name": "Alice Smith",
                    "department": "Engineering",
                    "manager": "bob.jones@company.com",
                    "job_title": "Senior Engineer",
                    "last_login": "2026-06-01",
                    "mfa_enabled": True,
                    "is_privileged": True,
                    "privileged_justification": "Cloud infrastructure owner",
                    "roles": ["cloud-admin", "read-only-prod"],
                    "groups": ["engineering", "aws-admins"],
                    "account_created": "2022-03-15",
                },
                {
                    "id": "U002",
                    "username": "charlie.brown",
                    "display_name": "Charlie Brown",
                    "department": "Finance",
                    "manager": "diana.prince@company.com",
                    "job_title": "Financial Analyst",
                    "last_login": "2025-09-01",  # stale
                    "mfa_enabled": False,
                    "is_privileged": False,
                    "roles": ["finance-read", "admin"],  # suspicious admin role
                    "groups": ["finance"],
                    "account_created": "2021-07-01",
                },
                {
                    "id": "U003",
                    "username": "eve.terminated",
                    "display_name": "Eve Terminated",
                    "department": "HR",
                    "manager": "",
                    "job_title": "HR Manager (terminated)",
                    "last_login": "2025-11-15",
                    "mfa_enabled": False,
                    "is_privileged": False,
                    "terminated": True,
                    "roles": ["hr-admin", "read-only"],
                    "groups": ["hr-team"],
                    "account_created": "2019-02-01",
                },
                {
                    "id": "SVC001",
                    "username": "svc-monitoring",
                    "display_name": "Monitoring Service Account",
                    "department": "IT Operations",
                    "manager": "ops-team@company.com",
                    "job_title": "Service Account",
                    "last_login": "2026-06-07",
                    "mfa_enabled": False,
                    "is_privileged": False,
                    "is_service_account": True,
                    "roles": ["read-only-logs"],
                    "groups": ["service-accounts"],
                    "account_created": "2023-01-10",
                },
            ],
            "review_decisions": {
                "alice.smith": {"decision": "CERTIFY", "notes": "Access appropriate for role"},
            },
        }

    automation = AccessReviewAutomation(config=config)
    report = automation.run()

    print("\n" + "=" * 60)
    print(f"ACCESS REVIEW REPORT — {report['report_metadata']['review_period']}")
    print("=" * 60)
    stats = report["statistics"]
    print(f"Total Users:        {stats['total_users']}")
    print(f"Completion:         {stats['completion_percentage']}%")
    print(f"Certifications:     {stats['certifications']}")
    print(f"Revocations:        {stats['revocations']}")
    print(f"Pending:            {stats['pending_reviews']}")
    print(f"High-Risk Accounts: {stats['high_risk_accounts']}")
    print(f"Without MFA:        {stats['accounts_without_mfa']}")
    print("\nRisk Flag Breakdown:")
    for flag, count in stats["risk_flag_breakdown"].items():
        print(f"  {flag:<35} {count}")
    print("=" * 60)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull report saved to {args.output}")
