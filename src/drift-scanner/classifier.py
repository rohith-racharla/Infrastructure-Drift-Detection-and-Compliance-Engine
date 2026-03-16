"""
=======================
Drift Classifier Module
=======================
Classifies infrastructure drift into three severity levels:

- **cosmetic**: Tag changes, descriptions, metadata-only modifications
- **functional**: Security group rules, subnet associations, instance config changes
- **critical**: IAM policies, KMS keys, encryption settings, public access changes

The classification drives notification urgency and remediation priority.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class DriftSeverity(str, Enum):
    """Severity levels for infrastructure drift."""
    COSMETIC = "cosmetic"
    FUNCTIONAL = "functional"
    CRITICAL = "critical"

    @property
    def priority(self) -> int:
        """Numeric priority for comparison (higher = more severe)."""
        return {"cosmetic": 1, "functional": 2, "critical": 3}[self.value]

    def __lt__(self, other: "DriftSeverity") -> bool:
        return self.priority < other.priority


@dataclass
class DriftClassification:
    """Result of classifying a single drifted resource."""
    severity: DriftSeverity
    resource_type: str
    resource_address: str
    changed_attributes: list[str] = field(default_factory=list)
    reason: str = ""
    action: str = ""  # "create", "update", "delete", "replace"
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        return {
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_address": self.resource_address,
            "changed_attributes": self.changed_attributes,
            "reason": self.reason,
            "action": self.action,
            "before": self.before,
            "after": self.after,
        }


# ====================
# Classification Rules
# ====================
# Maps resource types and attribute patterns to severity levels.
# The classifier checks in order: critical → functional → cosmetic.
# If no rule matches, defaults to FUNCTIONAL.

# Attributes that always indicate CRITICAL drift
CRITICAL_ATTRIBUTES: dict[str, list[str]] = {
    # IAM resources — any change is critical
    "aws_iam_role": ["*"],
    "aws_iam_policy": ["*"],
    "aws_iam_role_policy": ["*"],
    "aws_iam_role_policy_attachment": ["*"],
    "aws_iam_user": ["*"],
    "aws_iam_user_policy": ["*"],
    "aws_iam_group_policy": ["*"],
    "aws_iam_instance_profile": ["*"],
    # KMS — encryption changes are critical
    "aws_kms_key": ["*"],
    "aws_kms_alias": ["*"],
    # S3 public access and encryption
    "aws_s3_bucket_public_access_block": ["*"],
    "aws_s3_bucket_server_side_encryption_configuration": ["*"],
    "aws_s3_bucket_policy": ["*"],
    # RDS encryption and public access
    "aws_db_instance": [
        "publicly_accessible",
        "storage_encrypted",
        "iam_database_authentication_enabled",
    ],
}

# Attributes that indicate FUNCTIONAL drift
FUNCTIONAL_ATTRIBUTES: dict[str, list[str]] = {
    # Security group rule changes
    "aws_security_group": ["ingress", "egress"],
    "aws_security_group_rule": ["*"],
    "aws_vpc_security_group_ingress_rule": ["*"],
    "aws_vpc_security_group_egress_rule": ["*"],
    # Network changes
    "aws_subnet": ["cidr_block", "availability_zone", "map_public_ip_on_launch"],
    "aws_route_table": ["route"],
    "aws_route": ["*"],
    "aws_network_acl": ["*"],
    "aws_network_acl_rule": ["*"],
    # EC2 instance configuration
    "aws_instance": [
        "instance_type",
        "ami",
        "subnet_id",
        "vpc_security_group_ids",
        "user_data",
        "iam_instance_profile",
        "monitoring",
        "metadata_options",
    ],
    # VPC changes
    "aws_vpc": ["cidr_block", "enable_dns_support", "enable_dns_hostnames"],
    # Load balancer changes
    "aws_lb": ["internal", "subnets", "security_groups"],
    "aws_lb_listener": ["*"],
    "aws_lb_target_group": ["*"],
}

# Attributes that indicate COSMETIC drift
COSMETIC_ATTRIBUTES: dict[str, list[str]] = {
    # Tag-only changes across all resource types
    "*": ["tags", "tags_all"],
    # Description changes
    "aws_security_group": ["description"],
    "aws_iam_role": ["description"],
    # Name changes (non-functional)
    "aws_vpc": ["tags"],
    "aws_subnet": ["tags"],
    "aws_instance": ["tags"],
}


class DriftClassifier:
    """
    Classifies Terraform plan resource changes by severity.

    Usage:
        classifier = DriftClassifier()
        classification = classifier.classify(resource_change)
        # or classify a full plan:
        results = classifier.classify_plan(plan_json)
    """

    def __init__(
        self,
        critical_rules: dict[str, list[str]] | None = None,
        functional_rules: dict[str, list[str]] | None = None,
        cosmetic_rules: dict[str, list[str]] | None = None,
    ):
        """
        Initialize with optional custom classification rules.

        Args:
            critical_rules: Override critical attribute mappings
            functional_rules: Override functional attribute mappings
            cosmetic_rules: Override cosmetic attribute mappings
        """
        self.critical_rules = critical_rules or CRITICAL_ATTRIBUTES
        self.functional_rules = functional_rules or FUNCTIONAL_ATTRIBUTES
        self.cosmetic_rules = cosmetic_rules or COSMETIC_ATTRIBUTES

    def classify(self, resource_change: dict) -> DriftClassification:
        """
        Classify a single resource change from terraform plan JSON.

        Args:
            resource_change: A resource_change object from the plan JSON.
                Expected keys: type, address, change.actions, change.before,
                change.after

        Returns:
            DriftClassification with severity, details, and context.
        """
        resource_type = resource_change.get("type", "unknown")
        resource_address = resource_change.get("address", "unknown")
        change = resource_change.get("change", {})
        actions = change.get("actions", [])
        before = change.get("before") or {}
        after = change.get("after") or {}

        # Determine the primary action
        action = self._determine_action(actions)

        # Find changed attributes
        changed_attrs = self._find_changed_attributes(before, after)

        # Classify based on resource type and changed attributes
        severity, reason = self._determine_severity(
            resource_type, changed_attrs, action
        )

        return DriftClassification(
            severity=severity,
            resource_type=resource_type,
            resource_address=resource_address,
            changed_attributes=changed_attrs,
            reason=reason,
            action=action,
            before={k: before.get(k) for k in changed_attrs if k in before},
            after={k: after.get(k) for k in changed_attrs if k in after},
        )

    def classify_plan(self, plan_json: dict) -> list[DriftClassification]:
        """
        Classify all resource changes in a terraform plan JSON output.

        Args:
            plan_json: Full terraform plan JSON (from `terraform plan -json`
                       or `terraform show -json <planfile>`)

        Returns:
            List of DriftClassification objects, sorted by severity (highest first).
        """
        results = []

        resource_changes = plan_json.get("resource_changes", [])
        for rc in resource_changes:
            change = rc.get("change", {})
            actions = change.get("actions", [])

            # Skip no-op changes
            if actions == ["no-op"] or actions == ["read"]:
                continue

            classification = self.classify(rc)
            results.append(classification)
            logger.info(
                "Classified %s as %s: %s",
                classification.resource_address,
                classification.severity.value,
                classification.reason,
            )

        # Sort by severity (critical first)
        results.sort(key=lambda c: c.severity.priority, reverse=True)
        return results

    def _determine_action(self, actions: list[str]) -> str:
        """Map terraform plan actions to a single action string."""
        if not actions:
            return "unknown"
        if "delete" in actions and "create" in actions:
            return "replace"
        if "delete" in actions:
            return "delete"
        if "create" in actions:
            return "create"
        if "update" in actions:
            return "update"
        return actions[0]

    def _find_changed_attributes(
        self, before: dict, after: dict
    ) -> list[str]:
        """Find attributes that differ between before and after states."""
        changed = []
        all_keys = set(list(before.keys()) + list(after.keys()))

        for key in sorted(all_keys):
            before_val = before.get(key)
            after_val = after.get(key)
            if before_val != after_val:
                changed.append(key)

        return changed

    def _determine_severity(
        self, resource_type: str, changed_attrs: list[str], action: str
    ) -> tuple[DriftSeverity, str]:
        """
        Determine the drift severity based on resource type, changed
        attributes, and action.

        Returns:
            Tuple of (severity, reason_string)
        """
        # Resource deletion or replacement is always at least functional
        if action in ("delete", "replace"):
            # Check if it's a critical resource type
            if resource_type in self.critical_rules:
                return (
                    DriftSeverity.CRITICAL,
                    f"{action} of critical resource type {resource_type}",
                )
            return (
                DriftSeverity.FUNCTIONAL,
                f"{action} of resource {resource_type}",
            )

        # Resource creation — check if it's a critical type
        if action == "create":
            if resource_type in self.critical_rules:
                return (
                    DriftSeverity.CRITICAL,
                    f"Unexpected creation of critical resource type {resource_type}",
                )
            return (
                DriftSeverity.FUNCTIONAL,
                f"Unexpected creation of resource {resource_type}",
            )

        # For updates, check changed attributes against rules
        # Check CRITICAL rules first
        severity, reason = self._check_rules(
            resource_type, changed_attrs, self.critical_rules, DriftSeverity.CRITICAL
        )
        if severity:
            return severity, reason

        # Check FUNCTIONAL rules
        severity, reason = self._check_rules(
            resource_type, changed_attrs, self.functional_rules, DriftSeverity.FUNCTIONAL
        )
        if severity:
            return severity, reason

        # Check if ALL changed attributes are cosmetic
        if self._all_cosmetic(resource_type, changed_attrs):
            return (
                DriftSeverity.COSMETIC,
                f"Cosmetic changes only: {', '.join(changed_attrs)}",
            )

        # Default to FUNCTIONAL for unrecognized changes
        return (
            DriftSeverity.FUNCTIONAL,
            f"Unclassified attribute changes in {resource_type}: "
            f"{', '.join(changed_attrs)}",
        )

    def _check_rules(
        self,
        resource_type: str,
        changed_attrs: list[str],
        rules: dict[str, list[str]],
        severity: DriftSeverity,
    ) -> tuple[DriftSeverity | None, str]:
        """Check if any changed attributes match the given rule set."""
        if resource_type not in rules:
            return None, ""

        rule_attrs = rules[resource_type]

        # Wildcard — any change to this resource type matches
        if "*" in rule_attrs:
            return (
                severity,
                f"{severity.value} resource type {resource_type} was modified: "
                f"{', '.join(changed_attrs)}",
            )

        # Check specific attributes
        matched = [attr for attr in changed_attrs if attr in rule_attrs]
        if matched:
            return (
                severity,
                f"{severity.value} attributes changed in {resource_type}: "
                f"{', '.join(matched)}",
            )

        return None, ""

    def _all_cosmetic(self, resource_type: str, changed_attrs: list[str]) -> bool:
        """Check if all changed attributes are cosmetic."""
        if not changed_attrs:
            return True

        # Get cosmetic attrs for this resource type + wildcard
        cosmetic_attrs = set(self.cosmetic_rules.get("*", []))
        cosmetic_attrs.update(self.cosmetic_rules.get(resource_type, []))

        return all(attr in cosmetic_attrs for attr in changed_attrs)


def get_severity_summary(classifications: list[DriftClassification]) -> dict:
    """
    Generate a summary of drift classifications by severity.

    Returns:
        Dict with counts and details per severity level.
    """
    summary = {
        "total": len(classifications),
        "critical": 0,
        "functional": 0,
        "cosmetic": 0,
        "by_resource_type": {},
        "by_action": {},
    }

    for c in classifications:
        summary[c.severity.value] += 1

        # Count by resource type
        if c.resource_type not in summary["by_resource_type"]:
            summary["by_resource_type"][c.resource_type] = 0
        summary["by_resource_type"][c.resource_type] += 1

        # Count by action
        if c.action not in summary["by_action"]:
            summary["by_action"][c.action] = 0
        summary["by_action"][c.action] += 1

    return summary
