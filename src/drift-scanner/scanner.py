"""
====================
Drift Scanner Module
====================
The main entry point for the Infrastructure Drift Detection Engine.

This module can run as:
1. An AWS Lambda handler (triggered by EventBridge every 6 hours)
2. A standalone CLI script (for local development and testing)

Flow:
1. Pull Terraform state configuration from S3 / local
2. Execute `terraform plan -json` in a sandboxed environment
3. Parse the JSON plan output to extract resource changes
4. Classify each change using the DriftClassifier
5. Generate and store reports using the DriftReporter
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from classifier import DriftClassifier, DriftClassification, get_severity_summary
from reporter import DriftReporter
from aws_auditor import run_aws_audit

# Configure logging
logger = logging.getLogger("drift-scanner")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)


# =============
# Configuration
# =============

class ScannerConfig:
    """Scanner configuration from environment variables."""

    def __init__(self):
        self.environment = os.environ.get("ENVIRONMENT", "dev")
        self.aws_region = os.environ.get("AWS_REGION", "us-east-1")

        # Terraform state location
        self.state_bucket = os.environ.get(
            "TF_STATE_BUCKET", "drift-engine-terraform-state"
        )
        self.state_key = os.environ.get(
            "TF_STATE_KEY", "sample-infra/terraform.tfstate"
        )

        # Terraform working directory (in Docker container)
        self.tf_working_dir = os.environ.get(
            "TF_WORKING_DIR", "/opt/terraform/sample-infra"
        )

        # Report storage
        self.reports_bucket = os.environ.get(
            "DRIFT_REPORTS_BUCKET", "drift-engine-drift-reports"
        )
        self.history_table = os.environ.get(
            "DRIFT_HISTORY_TABLE", "drift-engine-drift-history"
        )

        # Notification settings
        self.sns_topic_arn = os.environ.get("SNS_TOPIC_ARN", "")
        self.notify_on_severity = os.environ.get(
            "NOTIFY_ON_SEVERITY", "functional,critical"
        ).split(",")

    def to_dict(self) -> dict:
        """Serialize config for logging."""
        return {
            "environment": self.environment,
            "aws_region": self.aws_region,
            "state_bucket": self.state_bucket,
            "state_key": self.state_key,
            "reports_bucket": self.reports_bucket,
            "history_table": self.history_table,
        }


# ========================
# Terraform Plan Execution
# ========================

class TerraformRunner:
    """Executes Terraform commands and parses plan output."""

    def __init__(self, working_dir: str, state_bucket: str = "", state_key: str = ""):
        self.working_dir = working_dir
        self.state_bucket = state_bucket
        self.state_key = state_key

    def init(self) -> bool:
        """
        Run `terraform init` with the configured backend.

        Returns:
            True if init succeeded, False otherwise.
        """
        cmd = ["terraform", "init", "-no-color", "-input=false"]

        # Configure S3 backend if state bucket is specified
        if self.state_bucket:
            cmd.extend([
                f"-backend-config=bucket={self.state_bucket}",
                f"-backend-config=key={self.state_key}",
                "-backend-config=encrypt=true",
            ])

        logger.info("Running terraform init in %s", self.working_dir)
        result = self._run_command(cmd)

        if result["returncode"] != 0:
            logger.error("terraform init failed: %s", result["stderr"])
            return False

        logger.info("terraform init succeeded")
        return True

    def plan(self) -> dict | None:
        """
        Run `terraform plan -json` and parse the output.

        Returns:
            Parsed JSON plan output, or None if plan failed.
        """
        # Create a temp file for the plan output
        with tempfile.NamedTemporaryFile(
            suffix=".tfplan", delete=False, dir=self.working_dir
        ) as plan_file:
            plan_path = plan_file.name

        try:
            # Run terraform plan
            plan_cmd = [
                "terraform", "plan",
                "-no-color",
                "-input=false",
                "-detailed-exitcode",
                f"-out={plan_path}",
            ]
            logger.info("Running terraform plan...")
            plan_result = self._run_command(plan_cmd)

            # Exit codes: 0 = no changes, 1 = error, 2 = changes present
            if plan_result["returncode"] == 1:
                logger.error("terraform plan failed: %s", plan_result["stderr"])
                return None

            if plan_result["returncode"] == 0:
                logger.info("No changes detected — infrastructure matches state")
                return {"resource_changes": []}

            # Exit code 2 — changes detected, convert plan to JSON
            show_cmd = [
                "terraform", "show",
                "-json",
                "-no-color",
                plan_path,
            ]
            logger.info("Converting plan to JSON...")
            show_result = self._run_command(show_cmd)

            if show_result["returncode"] != 0:
                logger.error(
                    "terraform show -json failed: %s", show_result["stderr"]
                )
                return None

            plan_json = json.loads(show_result["stdout"])
            logger.info(
                "Plan parsed: %d resource changes",
                len(plan_json.get("resource_changes", [])),
            )
            return plan_json

        finally:
            # Clean up the plan file
            if os.path.exists(plan_path):
                os.unlink(plan_path)

    def _run_command(self, cmd: list[str]) -> dict:
        """Execute a command and capture output."""
        try:
            result = subprocess.run(
                cmd,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
                timeout=300,  # 5-minute timeout
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            logger.error("Command timed out after 300s: %s", " ".join(cmd))
            return {"returncode": 1, "stdout": "", "stderr": "Command timed out"}
        except FileNotFoundError:
            logger.error("Command not found: %s", cmd[0])
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": f"Command not found: {cmd[0]}",
            }


# ============
# Notification
# ============

def send_notification(
    config: ScannerConfig,
    report: dict,
    classifications: list[DriftClassification],
) -> None:
    """
    Send drift notification via SNS if severity thresholds are met.

    Args:
        config: Scanner configuration
        report: Generated report dict
        classifications: List of drift classifications
    """
    if not config.sns_topic_arn:
        logger.info("No SNS topic configured — skipping notification")
        return

    # Check if any drift matches notification severity threshold
    should_notify = any(
        c.severity.value in config.notify_on_severity for c in classifications
    )

    if not should_notify:
        logger.info("No drift matching notification threshold — skipping")
        return

    summary = report["summary"]
    subject = (
        f"[Infrastructure Drift Detection and Compliance Engine] Drift Detected — "
        f"{summary['critical']} Critical, "
        f"{summary['functional']} Functional, "
        f"{summary['cosmetic']} Cosmetic"
    )

    message = (
        f"Infrastructure Drift Report\n"
        f"{'=' * 40}\n\n"
        f"Scan ID: {report['scan_id']}\n"
        f"Environment: {config.environment}\n"
        f"Region: {config.aws_region}\n"
        f"Timestamp: {report['timestamp']}\n\n"
        f"Summary:\n"
        f"  Total Drifted Resources: {summary['total']}\n"
        f"  Critical: {summary['critical']}\n"
        f"  Functional: {summary['functional']}\n"
        f"  Cosmetic: {summary['cosmetic']}\n"
        f"  Compliance Score: {report['compliance_score']}/100\n\n"
        f"View the full report in S3:\n"
        f"  s3://{config.reports_bucket}/reports/\n"
    )

    try:
        sns = boto3.client("sns", region_name=config.aws_region)
        sns.publish(
            TopicArn=config.sns_topic_arn,
            Subject=subject[:100],  # SNS subject max 100 chars
            Message=message,
        )
        logger.info("Notification sent to %s", config.sns_topic_arn)
    except ClientError as e:
        logger.error("Failed to send notification: %s", e)


# =======================
# Main Scan Orchestration
# =======================

def run_scan(
    config: ScannerConfig,
    plan_json: dict | None = None,
) -> dict:
    """
    Execute a full drift scan: plan → classify → report → store → notify.

    Args:
        config: Scanner configuration
        plan_json: Pre-parsed plan JSON (for testing). If None, runs
                   terraform plan.

    Returns:
        Scan result dictionary with report and classifications.
    """
    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    logger.info("Starting drift scan: %s", scan_id)
    logger.info("Config: %s", json.dumps(config.to_dict()))

    # Step 1: Run Terraform plan (or use provided plan JSON)
    if plan_json is None:
        runner = TerraformRunner(
            working_dir=config.tf_working_dir,
            state_bucket=config.state_bucket,
            state_key=config.state_key,
        )

        if not runner.init():
            raise RuntimeError("Terraform init failed")

        plan_json = runner.plan()
        if plan_json is None:
            raise RuntimeError("Terraform plan failed")

    # Step 2: Classify drift from Terraform plan
    classifier = DriftClassifier()
    classifications = classifier.classify_plan(plan_json)

    logger.info(
        "Terraform plan classification: %d drifted resources",
        len(classifications),
    )

    # Step 2.5: Run AWS API audit for unmanaged resources
    try:
        api_classifications = run_aws_audit(
            tf_working_dir=config.tf_working_dir,
            region=config.aws_region,
        )
        classifications.extend(api_classifications)
        if api_classifications:
            logger.info(
                "AWS API audit found %d additional unmanaged resources",
                len(api_classifications),
            )
    except Exception as e:
        logger.error("AWS API audit failed (continuing): %s", e)

    # Re-sort by severity (critical first) after merging
    classifications.sort(
        key=lambda c: c.severity.priority, reverse=True
    )

    summary = get_severity_summary(classifications)
    logger.info(
        "Classification complete: %d total (%d critical, %d functional, %d cosmetic)",
        summary["total"],
        summary["critical"],
        summary["functional"],
        summary["cosmetic"],
    )

    # Step 3: Generate report
    reporter = DriftReporter(
        s3_bucket=config.reports_bucket,
        dynamodb_table=config.history_table,
        environment=config.environment,
        region=config.aws_region,
    )
    report = reporter.generate_report(
        scan_id=scan_id,
        classifications=classifications,
        metadata={
            "trigger": os.environ.get("TRIGGER", "manual"),
            "state_bucket": config.state_bucket,
            "state_key": config.state_key,
        },
    )

    # Step 4: Store report
    try:
        storage_result = reporter.store_report(report)
        logger.info("Report stored: %s", json.dumps(storage_result))
    except Exception as e:
        logger.error("Failed to store report (continuing): %s", e)
        storage_result = {"error": str(e)}

    # Step 5: Send notifications
    send_notification(config, report, classifications)

    return {
        "scan_id": scan_id,
        "summary": summary,
        "compliance_score": report["compliance_score"],
        "classifications": [c.to_dict() for c in classifications],
        "storage": storage_result,
    }


# ==============
# Lambda Handler
# ==============

def lambda_handler(event: dict, context: Any) -> dict:
    """
    AWS Lambda entry point. Triggered by EventBridge on schedule.

    Args:
        event: EventBridge event payload
        context: Lambda context object

    Returns:
        Scan result summary.
    """
    logger.info("Lambda invoked with event: %s", json.dumps(event))

    config = ScannerConfig()

    try:
        result = run_scan(config)

        return {
            "statusCode": 200,
            "body": {
                "scan_id": result["scan_id"],
                "summary": result["summary"],
                "compliance_score": result["compliance_score"],
            },
        }
    except Exception as e:
        logger.exception("Scan failed: %s", e)
        return {
            "statusCode": 500,
            "body": {"error": str(e)},
        }


# ===============
# CLI Entry Point
# ===============

def main():
    """CLI entry point for local development and testing."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Infrastructure Drift Detection and Compliance Engine Drift Scanner — detect infrastructure drift"
    )
    parser.add_argument(
        "--plan-file",
        help="Path to a pre-generated terraform plan JSON file (skips terraform plan)",
    )
    parser.add_argument(
        "--tf-dir",
        default=".",
        help="Terraform working directory (default: current directory)",
    )
    parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Directory to save local reports (default: ./reports)",
    )
    parser.add_argument(
        "--environment",
        default="dev",
        help="Environment name (default: dev)",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Save reports locally only (skip S3/DynamoDB)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Load plan from file if provided
    plan_json = None
    if args.plan_file:
        logger.info("Loading plan from file: %s", args.plan_file)
        with open(args.plan_file) as f:
            plan_json = json.load(f)

    # Configure
    config = ScannerConfig()
    config.environment = args.environment
    config.tf_working_dir = args.tf_dir

    if args.local_only or plan_json is not None:
        # Local mode — classify and generate reports without AWS
        scan_id = f"local-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

        if plan_json is None:
            runner = TerraformRunner(working_dir=args.tf_dir)
            if not runner.init():
                logger.error("Terraform init failed")
                sys.exit(1)
            plan_json = runner.plan()
            if plan_json is None:
                logger.error("Terraform plan failed")
                sys.exit(1)

        classifier = DriftClassifier()
        classifications = classifier.classify_plan(plan_json)

        reporter = DriftReporter(environment=args.environment)
        result = reporter.generate_local_report(
            scan_id=scan_id,
            classifications=classifications,
            output_dir=args.output_dir,
        )

        summary = get_severity_summary(classifications)
        print(f"\n{'=' * 60}")
        print(f"  Drift Scan Complete: {scan_id}")
        print(f"{'=' * 60}")
        print(f"  Total Drifted Resources: {summary['total']}")
        print(f"  Critical:   {summary['critical']}")
        print(f"  Functional: {summary['functional']}")
        print(f"  Cosmetic:   {summary['cosmetic']}")
        print(f"  Compliance Score: {result['report']['compliance_score']}/100")
        print(f"\n  Reports saved to: {args.output_dir}/")
        print(f"    - {result['json_path']}")
        print(f"    - {result['markdown_path']}")
        print(f"{'=' * 60}\n")
    else:
        # Full mode — run scan with AWS integration
        result = run_scan(config, plan_json=plan_json)
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
