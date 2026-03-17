"""
=====================
AWS API Drift Auditor
=====================
Detects unmanaged resources that ``terraform plan`` cannot see.

While ``terraform plan`` only detects changes to resources already in
the Terraform state, this module queries AWS APIs directly to discover
resources that were created *outside* of Terraform.

Currently supports:
- **Security Group rules** added via the AWS Console / CLI
- **IAM inline policies** and **managed policy attachments** added outside
  Terraform

Each auditor reads the local ``terraform.tfstate`` file to know which
resources Terraform manages, queries the live AWS API, and flags any
discrepancies as ``DriftClassification`` objects that feed directly
into the existing reporting pipeline.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from classifier import DriftClassification, DriftSeverity

logger = logging.getLogger("drift-scanner")

# Ports that are considered sensitive when open to the internet
SENSITIVE_PORTS = {22, 3306, 3389, 5432, 1433, 27017, 6379, 9200, 5601}


# ======================
# Terraform State Reader
# ======================

class TerraformStateReader:
    """
    Reads the local terraform.tfstate file and extracts
    the resources Terraform currently manages.
    """

    def __init__(self, tf_working_dir: str):
        self.tf_working_dir = tf_working_dir
        self._state: dict | None = None

    def load(self) -> dict:
        """Load and return the Terraform state JSON."""
        if self._state is not None:
            return self._state

        state_path = Path(self.tf_working_dir) / "terraform.tfstate"
        if not state_path.exists():
            logger.warning("No terraform.tfstate found at %s", state_path)
            return {"resources": []}

        with open(state_path) as f:
            self._state = json.load(f)

        return self._state

    def get_resources_by_type(self, resource_type: str) -> list[dict]:
        """Return all managed resources of a given type."""
        state = self.load()
        return [
            r for r in state.get("resources", [])
            if r.get("type") == resource_type and r.get("mode") == "managed"
        ]

    def get_security_groups(self) -> list[dict]:
        """
        Return all managed security groups with their IDs and
        known ingress/egress rules from the state.
        """
        sgs = self.get_resources_by_type("aws_security_group")
        results = []
        for sg in sgs:
            for instance in sg.get("instances", []):
                attrs = instance.get("attributes", {})
                results.append({
                    "name": sg.get("name", "unknown"),
                    "id": attrs.get("id", ""),
                    "ingress": attrs.get("ingress", []),
                    "egress": attrs.get("egress", []),
                })
        return results

    def get_iam_roles(self) -> list[dict]:
        """
        Return all managed IAM roles with their known inline
        policies and managed policy ARNs from the state.
        """
        roles = self.get_resources_by_type("aws_iam_role")
        # Also collect inline policies and managed attachments from
        # dedicated resources
        inline_policies = self.get_resources_by_type("aws_iam_role_policy")
        managed_attachments = self.get_resources_by_type(
            "aws_iam_role_policy_attachment"
        )

        results = []
        for role in roles:
            for instance in role.get("instances", []):
                attrs = instance.get("attributes", {})
                role_name = attrs.get("name", "")

                # Collect inline policy names from the role's own state
                known_inline = set()
                for ip in attrs.get("inline_policy", []):
                    if ip.get("name"):
                        known_inline.add(ip["name"])

                # Also collect from dedicated aws_iam_role_policy resources
                for ip_resource in inline_policies:
                    for ip_inst in ip_resource.get("instances", []):
                        ip_attrs = ip_inst.get("attributes", {})
                        if ip_attrs.get("role") == role_name:
                            known_inline.add(ip_attrs.get("name", ""))

                # Collect managed policy ARNs from the role's own state
                known_managed = set(attrs.get("managed_policy_arns", []))

                # Also collect from dedicated aws_iam_role_policy_attachment
                for ma_resource in managed_attachments:
                    for ma_inst in ma_resource.get("instances", []):
                        ma_attrs = ma_inst.get("attributes", {})
                        if ma_attrs.get("role") == role_name:
                            known_managed.add(
                                ma_attrs.get("policy_arn", "")
                            )

                results.append({
                    "name": role_name,
                    "arn": attrs.get("arn", ""),
                    "known_inline_policies": known_inline,
                    "known_managed_policy_arns": known_managed,
                })

        return results


# ======================
# Security Group Auditor
# ======================

class SecurityGroupAuditor:
    """
    Queries the AWS EC2 API for live security group rules
    and compares them against the Terraform state to detect
    unmanaged rules.
    """

    def __init__(self, region: str = "us-east-1"):
        self.ec2 = boto3.client("ec2", region_name=region)

    def audit(
        self, state_reader: TerraformStateReader
    ) -> list[DriftClassification]:
        """
        Compare live SG rules against Terraform state.

        Returns:
            List of DriftClassification for each unmanaged rule found.
        """
        classifications = []
        managed_sgs = state_reader.get_security_groups()

        if not managed_sgs:
            logger.info("No managed security groups found in state")
            return classifications

        for sg_info in managed_sgs:
            sg_id = sg_info["id"]
            if not sg_id:
                continue

            try:
                live_rules = self._get_live_rules(sg_id)
            except ClientError as e:
                logger.warning(
                    "Failed to query SG rules for %s: %s", sg_id, e
                )
                continue

            # Find live ingress rules not in Terraform state
            state_ingress = sg_info.get("ingress", [])
            unmanaged_ingress = self._find_unmanaged_rules(
                live_rules["ingress"], state_ingress
            )

            for rule in unmanaged_ingress:
                severity = self._classify_rule_severity(rule)
                classifications.append(
                    DriftClassification(
                        severity=severity,
                        resource_type="aws_security_group_rule",
                        resource_address=(
                            f"aws_security_group.{sg_info['name']}"
                            f" (unmanaged ingress rule)"
                        ),
                        changed_attributes=["ingress_rule"],
                        reason=self._build_rule_reason(rule, severity),
                        action="create",
                        before={},
                        after={
                            "security_group_id": sg_id,
                            "type": "ingress",
                            "protocol": rule.get("protocol", "tcp"),
                            "from_port": rule.get("from_port", 0),
                            "to_port": rule.get("to_port", 0),
                            "cidr_blocks": rule.get("cidr_blocks", []),
                        },
                    )
                )

        logger.info(
            "SG audit complete: %d unmanaged rules found",
            len(classifications),
        )
        return classifications

    def _get_live_rules(self, sg_id: str) -> dict:
        """Fetch all live rules for a security group from AWS."""
        response = self.ec2.describe_security_group_rules(
            Filters=[
                {"Name": "group-id", "Values": [sg_id]},
            ]
        )

        ingress = []
        egress = []

        for rule in response.get("SecurityGroupRules", []):
            normalized = {
                "rule_id": rule.get("SecurityGroupRuleId", ""),
                "protocol": rule.get("IpProtocol", "-1"),
                "from_port": rule.get("FromPort", 0),
                "to_port": rule.get("ToPort", 0),
                "cidr_blocks": [],
                "security_groups": [],
                "description": rule.get("Description", ""),
            }

            if rule.get("CidrIpv4"):
                normalized["cidr_blocks"].append(rule["CidrIpv4"])
            if rule.get("CidrIpv6"):
                normalized["cidr_blocks"].append(rule["CidrIpv6"])
            if rule.get("ReferencedGroupInfo", {}).get("GroupId"):
                normalized["security_groups"].append(
                    rule["ReferencedGroupInfo"]["GroupId"]
                )

            if rule.get("IsEgress"):
                egress.append(normalized)
            else:
                ingress.append(normalized)

        return {"ingress": ingress, "egress": egress}

    def _find_unmanaged_rules(
        self,
        live_rules: list[dict],
        state_rules: list[dict],
    ) -> list[dict]:
        """
        Compare live rules against state rules.
        Returns rules that exist in AWS but not in the Terraform state.
        """
        unmanaged = []

        for live_rule in live_rules:
            if not self._rule_exists_in_state(live_rule, state_rules):
                unmanaged.append(live_rule)

        return unmanaged

    def _rule_exists_in_state(
        self, live_rule: dict, state_rules: list[dict]
    ) -> bool:
        """
        Check if a live rule matches any rule in the Terraform state.
        Matching is based on protocol, ports, and CIDR/SG source.
        """
        live_proto = self._normalize_protocol(live_rule.get("protocol", ""))
        live_from = live_rule.get("from_port", 0)
        live_to = live_rule.get("to_port", 0)
        live_cidrs = set(live_rule.get("cidr_blocks", []))
        live_sgs = set(live_rule.get("security_groups", []))

        for state_rule in state_rules:
            state_proto = self._normalize_protocol(
                state_rule.get("protocol", "")
            )
            state_from = state_rule.get("from_port", 0)
            state_to = state_rule.get("to_port", 0)
            state_cidrs = set(state_rule.get("cidr_blocks", []))
            state_sgs = set(state_rule.get("security_groups", []))

            if (
                live_proto == state_proto
                and live_from == state_from
                and live_to == state_to
                and live_cidrs == state_cidrs
                and live_sgs == state_sgs
            ):
                return True

        return False

    def _normalize_protocol(self, protocol: str) -> str:
        """Normalize protocol representations (-1 == all, 6 == tcp, etc.)."""
        mapping = {"6": "tcp", "17": "udp", "1": "icmp", "-1": "-1"}
        return mapping.get(str(protocol), str(protocol))

    def _classify_rule_severity(self, rule: dict) -> DriftSeverity:
        """
        Classify rule severity based on port and CIDR scope.
        Opening sensitive ports to 0.0.0.0/0 is CRITICAL.
        """
        cidrs = rule.get("cidr_blocks", [])
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)

        is_open_to_world = "0.0.0.0/0" in cidrs or "::/0" in cidrs

        if is_open_to_world:
            # Check if any sensitive port is in the range
            for port in SENSITIVE_PORTS:
                if from_port <= port <= to_port:
                    return DriftSeverity.CRITICAL

        return DriftSeverity.FUNCTIONAL

    def _build_rule_reason(
        self, rule: dict, severity: DriftSeverity
    ) -> str:
        """Build a human-readable reason string for the drift."""
        proto = rule.get("protocol", "tcp")
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 0)
        cidrs = rule.get("cidr_blocks", [])
        cidr_str = ", ".join(cidrs) if cidrs else "unknown source"

        port_str = (
            str(from_port) if from_port == to_port
            else f"{from_port}-{to_port}"
        )

        if severity == DriftSeverity.CRITICAL:
            return (
                f"UNMANAGED RULE: {proto.upper()} port {port_str} open to "
                f"{cidr_str} — not in Terraform state"
            )
        return (
            f"Unmanaged ingress rule: {proto.upper()} port {port_str} "
            f"from {cidr_str} — not in Terraform state"
        )


# ===========
# IAM Auditor
# ===========

class IAMAuditor:
    """
    Queries the AWS IAM API for live role policies
    and compares them against the Terraform state to detect
    unmanaged inline policies and managed policy attachments.
    """

    def __init__(self, region: str = "us-east-1"):
        self.iam = boto3.client("iam", region_name=region)

    def audit(
        self, state_reader: TerraformStateReader
    ) -> list[DriftClassification]:
        """
        Compare live IAM policies against Terraform state.

        Returns:
            List of DriftClassification for each unmanaged policy found.
        """
        classifications = []
        managed_roles = state_reader.get_iam_roles()

        if not managed_roles:
            logger.info("No managed IAM roles found in state")
            return classifications

        for role_info in managed_roles:
            role_name = role_info["name"]
            if not role_name:
                continue

            # Audit inline policies
            classifications.extend(
                self._audit_inline_policies(role_info)
            )

            # Audit managed policy attachments
            classifications.extend(
                self._audit_managed_policies(role_info)
            )

        logger.info(
            "IAM audit complete: %d unmanaged policies found",
            len(classifications),
        )
        return classifications

    def _audit_inline_policies(
        self, role_info: dict
    ) -> list[DriftClassification]:
        """Find inline policies not tracked by Terraform."""
        role_name = role_info["name"]
        known_inline = role_info["known_inline_policies"]
        classifications = []

        try:
            response = self.iam.list_role_policies(RoleName=role_name)
            live_policies = set(response.get("PolicyNames", []))
        except ClientError as e:
            logger.warning(
                "Failed to list inline policies for %s: %s", role_name, e
            )
            return classifications

        unmanaged = live_policies - known_inline

        for policy_name in unmanaged:
            # Fetch the policy document for context
            policy_doc = {}
            try:
                resp = self.iam.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                policy_doc = resp.get("PolicyDocument", {})
            except ClientError:
                pass

            classifications.append(
                DriftClassification(
                    severity=DriftSeverity.CRITICAL,
                    resource_type="aws_iam_role_policy",
                    resource_address=(
                        f"aws_iam_role.{role_name}"
                        f" (unmanaged inline policy)"
                    ),
                    changed_attributes=["inline_policy"],
                    reason=(
                        f"UNMANAGED INLINE POLICY '{policy_name}' "
                        f"on role '{role_name}' — not in Terraform state"
                    ),
                    action="create",
                    before={},
                    after={
                        "role": role_name,
                        "policy_name": policy_name,
                        "policy_document": policy_doc,
                    },
                )
            )

        return classifications

    def _audit_managed_policies(
        self, role_info: dict
    ) -> list[DriftClassification]:
        """Find managed policy attachments not tracked by Terraform."""
        role_name = role_info["name"]
        known_managed = role_info["known_managed_policy_arns"]
        classifications = []

        try:
            response = self.iam.list_attached_role_policies(
                RoleName=role_name
            )
            live_attachments = {
                p["PolicyArn"]
                for p in response.get("AttachedPolicies", [])
            }
        except ClientError as e:
            logger.warning(
                "Failed to list managed policies for %s: %s", role_name, e
            )
            return classifications

        unmanaged = live_attachments - known_managed

        for policy_arn in unmanaged:
            # Extract the policy name from the ARN for readability
            policy_name = policy_arn.split("/")[-1]

            severity = DriftSeverity.CRITICAL
            reason = (
                f"UNMANAGED POLICY ATTACHMENT '{policy_name}' "
                f"on role '{role_name}' — not in Terraform state"
            )

            # Especially dangerous if it's admin access
            if "AdministratorAccess" in policy_name:
                reason = (
                    f"EXTREMELY CRITICAL: '{policy_name}' attached to "
                    f"role '{role_name}' — grants full AWS access, "
                    f"not in Terraform state"
                )

            classifications.append(
                DriftClassification(
                    severity=severity,
                    resource_type="aws_iam_role_policy_attachment",
                    resource_address=(
                        f"aws_iam_role.{role_name}"
                        f" (unmanaged managed policy)"
                    ),
                    changed_attributes=["managed_policy_attachment"],
                    reason=reason,
                    action="create",
                    before={},
                    after={
                        "role": role_name,
                        "policy_arn": policy_arn,
                        "policy_name": policy_name,
                    },
                )
            )

        return classifications


# ============
# Orchestrator
# ============

def run_aws_audit(
    tf_working_dir: str,
    region: str = "us-east-1",
) -> list[DriftClassification]:
    """
    Run all AWS API auditors and return combined classifications.

    Args:
        tf_working_dir: Path to the Terraform working directory
                        containing terraform.tfstate
        region: AWS region to query

    Returns:
        Combined list of DriftClassification from all auditors.
    """
    logger.info("Starting AWS API audit (SG + IAM)...")

    state_reader = TerraformStateReader(tf_working_dir)
    state = state_reader.load()

    if not state.get("resources"):
        logger.warning(
            "Terraform state has no resources — skipping AWS audit"
        )
        return []

    classifications = []

    # Run Security Group audit
    try:
        sg_auditor = SecurityGroupAuditor(region=region)
        sg_results = sg_auditor.audit(state_reader)
        classifications.extend(sg_results)
    except Exception as e:
        logger.error("Security Group audit failed (continuing): %s", e)

    # Run IAM audit
    try:
        iam_auditor = IAMAuditor(region=region)
        iam_results = iam_auditor.audit(state_reader)
        classifications.extend(iam_results)
    except Exception as e:
        logger.error("IAM audit failed (continuing): %s", e)

    logger.info(
        "AWS API audit complete: %d unmanaged resources found",
        len(classifications),
    )

    return classifications
