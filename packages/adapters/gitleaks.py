"""Gitleaks adapter for secrets scanning."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from packages.adapters.base import AdapterResult, BaseAdapter
from packages.core.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    Patch,
    ScanType,
)

logger = logging.getLogger(__name__)

# Common secret patterns and their risk levels
SECRET_PATTERNS = {
    "aws": {"severity": FindingSeverity.CRITICAL, "description": "AWS credentials"},
    "github": {"severity": FindingSeverity.HIGH, "description": "GitHub token"},
    "private-key": {"severity": FindingSeverity.CRITICAL, "description": "Private key"},
    "password": {"severity": FindingSeverity.HIGH, "description": "Password"},
    "api-key": {"severity": FindingSeverity.HIGH, "description": "API key"},
    "secret": {"severity": FindingSeverity.HIGH, "description": "Secret"},
    "token": {"severity": FindingSeverity.HIGH, "description": "Token"},
    "jwt": {"severity": FindingSeverity.HIGH, "description": "JWT token"},
    "database": {"severity": FindingSeverity.HIGH, "description": "Database credential"},
    "slack": {"severity": FindingSeverity.MEDIUM, "description": "Slack token"},
    "stripe": {"severity": FindingSeverity.CRITICAL, "description": "Stripe key"},
    "sendgrid": {"severity": FindingSeverity.MEDIUM, "description": "SendGrid key"},
    "twilio": {"severity": FindingSeverity.MEDIUM, "description": "Twilio credential"},
    "mailgun": {"severity": FindingSeverity.MEDIUM, "description": "Mailgun key"},
    "npm": {"severity": FindingSeverity.HIGH, "description": "NPM token"},
    "pypi": {"severity": FindingSeverity.HIGH, "description": "PyPI token"},
    "nuget": {"severity": FindingSeverity.HIGH, "description": "NuGet key"},
    "docker": {"severity": FindingSeverity.HIGH, "description": "Docker credential"},
    "azure": {"severity": FindingSeverity.CRITICAL, "description": "Azure credential"},
    "gcp": {"severity": FindingSeverity.CRITICAL, "description": "GCP credential"},
    "google": {"severity": FindingSeverity.HIGH, "description": "Google credential"},
    "firebase": {"severity": FindingSeverity.HIGH, "description": "Firebase credential"},
}


class GitleaksAdapter(BaseAdapter):
    """Adapter for gitleaks secrets scanner."""

    name = "gitleaks"
    tool_name = "gitleaks"
    scan_types = [ScanType.SECRETS]
    required_binaries = ["gitleaks"]

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """Run gitleaks scan on the target path."""
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="gitleaks is not installed",
            )

        start_time = time.time()

        # Build command
        cmd = [
            self.get_tool_path(),
            "detect",
            "--source",
            str(target_path),
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--no-git",  # Scan files, not git history
        ]

        # Add custom config if specified
        config_path = self.config.get("config_path")
        if config_path:
            cmd.extend(["--config", config_path])

        # Add baseline if specified
        baseline_path = self.config.get("baseline_path")
        if baseline_path:
            cmd.extend(["--baseline-path", baseline_path])

        try:
            return_code, stdout, stderr = await self.run_command(
                cmd,
                cwd=target_path,
                timeout=kwargs.get("timeout", 300),
            )

            duration = time.time() - start_time
            version = await self.get_version()

            # gitleaks returns 1 if leaks found, 0 if clean
            if return_code not in (0, 1):
                return AdapterResult(
                    success=False,
                    error_message=f"gitleaks failed: {stderr}",
                    duration_seconds=duration,
                    tool_version=version,
                )

            # Parse output
            raw_output = stdout if isinstance(stdout, dict) else {"raw": stdout}
            findings = self.parse_output(stdout if isinstance(stdout, list) else [])

            return AdapterResult(
                success=True,
                findings=findings,
                raw_output=raw_output,
                duration_seconds=duration,
                tool_version=version,
            )

        except TimeoutError as e:
            return AdapterResult(success=False, error_message=str(e))
        except Exception as e:
            logger.exception(f"gitleaks scan failed: {e}")
            return AdapterResult(success=False, error_message=str(e))

    def parse_output(self, raw_output: Any) -> list[Finding]:
        """Parse gitleaks JSON output into findings."""
        findings = []

        if not isinstance(raw_output, list):
            return findings

        for item in raw_output:
            try:
                finding = self._parse_finding(item)
                if finding:
                    finding.fingerprint = self.generate_fingerprint(finding)
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse gitleaks finding: {e}")

        return findings

    def _parse_finding(self, item: dict[str, Any]) -> Finding | None:
        """Parse a single gitleaks finding."""
        rule_id = item.get("RuleID", "unknown")
        file_path = item.get("File", "")
        line_number = item.get("StartLine", 0)
        secret = item.get("Secret", "")
        match = item.get("Match", "")

        # Determine severity based on rule
        severity = FindingSeverity.HIGH  # Default for secrets
        description_suffix = "Hardcoded secret"

        rule_lower = rule_id.lower()
        for pattern, info in SECRET_PATTERNS.items():
            if pattern in rule_lower:
                severity = info["severity"]
                description_suffix = info["description"]
                break

        # Check if in high-risk location
        if file_path:
            path_lower = file_path.lower()
            if any(
                p in path_lower for p in ["public", "static", "dist", "build", "frontend", "client"]
            ):
                severity = FindingSeverity.CRITICAL
                description_suffix += " (exposed in public directory)"

        # Mask the secret for display
        masked_secret = self._mask_secret(secret) if secret else match[:50] + "..."

        evidence = Evidence(
            tool=self.name,
            file_path=file_path,
            line_start=line_number,
            line_end=item.get("EndLine", line_number),
            snippet=masked_secret,
            raw_output=item,
        )

        # Generate patch suggestion
        patch = None
        if file_path and secret:
            patch = Patch(
                file_path=file_path,
                diff=self._generate_secret_removal_diff(file_path, line_number, match),
                description="Remove hardcoded secret and use environment variable",
            )

        return Finding(
            title=f"{description_suffix} detected: {rule_id}",
            severity=severity,
            category=FindingCategory.SECRETS,
            confidence=FindingConfidence.HIGH,
            description=(
                f"A potential {description_suffix.lower()} was found in the codebase. "
                f"Rule: {rule_id}. "
                "Hardcoded secrets can lead to unauthorized access if the code is exposed."
            ),
            evidence=evidence,
            impact=(
                "If this secret is valid and exposed, attackers could gain unauthorized access "
                "to the associated service or resource. This could lead to data breaches, "
                "account takeover, or financial loss."
            ),
            attack_scenario=(
                "1. Attacker finds repository (via public repo, leaked code, or insider access)\n"
                "2. Attacker extracts the secret\n"
                "3. Attacker uses the secret to access the associated service\n"
                "4. Attacker exfiltrates data or escalates access"
            ),
            recommendation=(
                "1. Immediately rotate this secret/credential\n"
                "2. Remove the secret from the codebase and all git history\n"
                "3. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, "
                "HashiCorp Vault)\n"
                "4. Add the file pattern to .gitignore if applicable\n"
                "5. Review access logs for the associated service for unauthorized access"
            ),
            patch=patch,
            references=[
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://github.com/gitleaks/gitleaks",
            ],
            cwe_id="CWE-798",
        )

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _generate_secret_removal_diff(
        self, file_path: str, line_number: int, match: str
    ) -> str:
        """Generate a diff suggesting environment variable usage."""
        env_var_name = "SECRET_VALUE"  # Generic placeholder
        return f"""--- a/{file_path}
+++ b/{file_path}
@@ -{line_number},1 +{line_number},1 @@
-{match}
+os.environ.get("{env_var_name}")  # TODO: Set {env_var_name} in environment
"""
