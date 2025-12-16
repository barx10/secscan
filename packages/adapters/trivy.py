"""Trivy adapter for container and misconfiguration scanning."""

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
from packages.core.scoring import map_tool_severity

logger = logging.getLogger(__name__)


class TrivyAdapter(BaseAdapter):
    """Adapter for Trivy vulnerability and misconfiguration scanner."""

    name = "trivy"
    tool_name = "trivy"
    scan_types = [ScanType.CONFIG, ScanType.DEPS]
    required_binaries = ["trivy"]

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """Run trivy scan on the target path."""
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="trivy is not installed",
            )

        start_time = time.time()

        # Determine scan type based on target
        scan_type = kwargs.get("scan_type", "fs")  # fs, config, or image

        # Build command
        cmd = [
            "trivy",
            scan_type,
            "--format",
            "json",
            "--severity",
            self.config.get("severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"),
        ]

        # Add scanners based on config
        scanners = self.config.get("scanners", ["vuln", "misconfig", "secret"])
        if scanners:
            cmd.extend(["--scanners", ",".join(scanners)])

        # Skip update if configured (useful for CI)
        if self.config.get("skip_update", False):
            cmd.append("--skip-db-update")

        # Add ignore file if specified
        ignore_file = self.config.get("ignore_file")
        if ignore_file:
            cmd.extend(["--ignorefile", ignore_file])

        # Add target path
        cmd.append(str(target_path))

        try:
            return_code, stdout, stderr = await self.run_command(
                cmd,
                cwd=target_path,
                timeout=kwargs.get("timeout", 600),
            )

            duration = time.time() - start_time
            version = await self.get_version()

            raw_output = stdout if isinstance(stdout, dict) else {}
            findings = self.parse_output(raw_output)

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
            logger.exception(f"trivy scan failed: {e}")
            return AdapterResult(success=False, error_message=str(e))

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """Parse trivy JSON output into findings."""
        findings = []

        results = raw_output.get("Results", [])
        for result in results:
            target = result.get("Target", "")

            # Parse vulnerabilities
            vulnerabilities = result.get("Vulnerabilities", [])
            for vuln in vulnerabilities:
                try:
                    finding = self._parse_vulnerability(vuln, target)
                    if finding:
                        finding.fingerprint = self.generate_fingerprint(finding)
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse trivy vulnerability: {e}")

            # Parse misconfigurations
            misconfigs = result.get("Misconfigurations", [])
            for misconfig in misconfigs:
                try:
                    finding = self._parse_misconfiguration(misconfig, target)
                    if finding:
                        finding.fingerprint = self.generate_fingerprint(finding)
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse trivy misconfiguration: {e}")

            # Parse secrets
            secrets = result.get("Secrets", [])
            for secret in secrets:
                try:
                    finding = self._parse_secret(secret, target)
                    if finding:
                        finding.fingerprint = self.generate_fingerprint(finding)
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse trivy secret: {e}")

        return findings

    def _parse_vulnerability(self, vuln: dict[str, Any], target: str) -> Finding | None:
        """Parse a vulnerability finding from trivy."""
        vuln_id = vuln.get("VulnerabilityID", "")
        pkg_name = vuln.get("PkgName", "")
        installed_version = vuln.get("InstalledVersion", "")
        fixed_version = vuln.get("FixedVersion", "")
        severity_str = vuln.get("Severity", "UNKNOWN")
        title = vuln.get("Title", f"Vulnerability in {pkg_name}")
        description = vuln.get("Description", "")

        severity = map_tool_severity("trivy", severity_str)

        # Get CVSS score if available
        cvss = vuln.get("CVSS", {})
        cvss_score = None
        for source, data in cvss.items():
            if "V3Score" in data:
                cvss_score = data["V3Score"]
                break

        evidence = Evidence(
            tool=self.name,
            file_path=target,
            line_start=None,
            line_end=None,
            snippet=f"Package: {pkg_name}@{installed_version}",
            raw_output=vuln,
        )

        # Generate patch recommendation
        patch = None
        if fixed_version:
            patch = Patch(
                file_path=target,
                diff=f"Update {pkg_name} from {installed_version} to {fixed_version}",
                description=f"Upgrade {pkg_name} to version {fixed_version} or later",
            )

        # Build references
        references = []
        if vuln.get("PrimaryURL"):
            references.append(vuln["PrimaryURL"])
        for ref in vuln.get("References", [])[:5]:  # Limit references
            if ref not in references:
                references.append(ref)

        # Determine confidence
        confidence = FindingConfidence.HIGH
        if not fixed_version:
            confidence = FindingConfidence.MEDIUM

        return Finding(
            title=f"{vuln_id}: {title[:100]}",
            severity=severity,
            category=FindingCategory.DEPS,
            confidence=confidence,
            description=description[:1000] if description else f"Vulnerability {vuln_id} in {pkg_name}",
            evidence=evidence,
            impact=(
                f"This vulnerability in {pkg_name} could be exploited to compromise the application. "
                f"CVSS Score: {cvss_score or 'N/A'}"
            ),
            attack_scenario=(
                f"1. Attacker identifies vulnerable {pkg_name} version\n"
                f"2. Attacker exploits {vuln_id}\n"
                f"3. Impact depends on vulnerability type (see CVE details)"
            ),
            recommendation=(
                f"Upgrade {pkg_name} to version {fixed_version}" if fixed_version
                else f"Monitor for fixes to {vuln_id} and upgrade when available"
            ),
            patch=patch,
            references=references,
            cve_id=vuln_id if vuln_id.startswith("CVE") else None,
        )

    def _parse_misconfiguration(self, misconfig: dict[str, Any], target: str) -> Finding | None:
        """Parse a misconfiguration finding from trivy."""
        misconfig_id = misconfig.get("ID", "")
        avd_id = misconfig.get("AVDID", "")
        title = misconfig.get("Title", "Misconfiguration detected")
        description = misconfig.get("Description", "")
        message = misconfig.get("Message", "")
        severity_str = misconfig.get("Severity", "MEDIUM")
        resolution = misconfig.get("Resolution", "")

        severity = map_tool_severity("trivy", severity_str)

        # Get cause info
        cause_metadata = misconfig.get("CauseMetadata", {})
        start_line = cause_metadata.get("StartLine")
        end_line = cause_metadata.get("EndLine")
        code = cause_metadata.get("Code", {})

        # Build snippet from code
        snippet = ""
        lines = code.get("Lines", [])
        if lines:
            snippet = "\n".join(
                f"{line.get('Number', '')}: {line.get('Content', '')}"
                for line in lines[:5]
            )

        evidence = Evidence(
            tool=self.name,
            file_path=cause_metadata.get("Resource", target),
            line_start=start_line,
            line_end=end_line,
            snippet=snippet or message,
            raw_output=misconfig,
        )

        # Build references
        references = []
        if misconfig.get("PrimaryURL"):
            references.append(misconfig["PrimaryURL"])
        for ref in misconfig.get("References", [])[:3]:
            references.append(ref)

        return Finding(
            title=f"{avd_id or misconfig_id}: {title}",
            severity=severity,
            category=FindingCategory.CONFIG,
            confidence=FindingConfidence.HIGH,
            description=f"{description}\n\n{message}" if message else description,
            evidence=evidence,
            impact="Misconfigurations can lead to security vulnerabilities, data exposure, or service disruption.",
            attack_scenario="Attack scenarios vary based on the specific misconfiguration. Review the finding details.",
            recommendation=resolution or "Review and fix the configuration according to security best practices.",
            patch=None,
            references=references,
        )

    def _parse_secret(self, secret: dict[str, Any], target: str) -> Finding | None:
        """Parse a secret finding from trivy."""
        rule_id = secret.get("RuleID", "")
        category = secret.get("Category", "")
        title = secret.get("Title", "Secret detected")
        severity_str = secret.get("Severity", "HIGH")
        match = secret.get("Match", "")

        severity = map_tool_severity("trivy", severity_str)

        # Always treat secrets as at least HIGH
        if severity in [FindingSeverity.LOW, FindingSeverity.MEDIUM]:
            severity = FindingSeverity.HIGH

        evidence = Evidence(
            tool=self.name,
            file_path=target,
            line_start=secret.get("StartLine"),
            line_end=secret.get("EndLine"),
            snippet=self._mask_secret(match),
            raw_output=secret,
        )

        return Finding(
            title=f"Secret detected: {title}",
            severity=severity,
            category=FindingCategory.SECRETS,
            confidence=FindingConfidence.HIGH,
            description=f"A {category} secret was detected in {target}. Hardcoded secrets pose significant security risks.",
            evidence=evidence,
            impact="Exposed secrets can lead to unauthorized access, data breaches, and account compromise.",
            attack_scenario=(
                "1. Attacker discovers secret in code\n"
                "2. Attacker uses secret to access associated service\n"
                "3. Attacker escalates access or exfiltrates data"
            ),
            recommendation=(
                "1. Rotate the secret immediately\n"
                "2. Remove from code and git history\n"
                "3. Use environment variables or secrets manager\n"
                "4. Audit access logs for the service"
            ),
            patch=None,
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
            ],
            cwe_id="CWE-798",
        )

    def _mask_secret(self, secret: str) -> str:
        """Mask a secret for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * min(len(secret) - 8, 20) + secret[-4:]
