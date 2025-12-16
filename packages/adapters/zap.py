"""ZAP adapter for web application scanning."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packages.adapters.base import AdapterResult, BaseAdapter
from packages.core.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    ScanType,
)
from packages.core.scoring import map_tool_severity

logger = logging.getLogger(__name__)

# ZAP risk levels mapping
ZAP_RISK_MAP = {
    "0": FindingSeverity.INFO,
    "1": FindingSeverity.LOW,
    "2": FindingSeverity.MEDIUM,
    "3": FindingSeverity.HIGH,
}

# ZAP confidence levels mapping
ZAP_CONFIDENCE_MAP = {
    "0": FindingConfidence.LOW,  # False Positive
    "1": FindingConfidence.LOW,
    "2": FindingConfidence.MEDIUM,
    "3": FindingConfidence.HIGH,
    "4": FindingConfidence.HIGH,  # User Confirmed
}

# High-risk alert types that should be escalated
HIGH_RISK_ALERTS = [
    "sql injection",
    "cross site scripting",
    "xss",
    "remote code execution",
    "command injection",
    "path traversal",
    "server side request forgery",
    "ssrf",
    "xml external entity",
    "xxe",
    "insecure direct object",
    "authentication bypass",
    "session fixation",
    "open redirect",
]


class ZapAdapter(BaseAdapter):
    """Adapter for OWASP ZAP web scanner."""

    name = "zap"
    tool_name = "zap-baseline"
    scan_types = [ScanType.WEB]
    required_binaries = ["zap-baseline.py"]  # From ZAP Docker or local install

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Alternative: use zap-cli or zap.sh
        self.zap_command = config.get("zap_command", "zap-baseline.py") if config else "zap-baseline.py"

    def is_available(self) -> bool:
        """Check if ZAP is available."""
        import shutil

        # Check multiple possible ZAP commands
        possible_commands = [
            "zap-baseline.py",
            "zap.sh",
            "zap-cli",
            "/zap/zap-baseline.py",  # Docker path
        ]

        for cmd in possible_commands:
            if shutil.which(cmd):
                self.zap_command = cmd
                return True

        return False

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """
        Run ZAP baseline scan on the target URL.

        Note: For ZAP, target_path is expected to be a URL string.
        """
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="ZAP is not installed. Install OWASP ZAP or use the Docker image.",
            )

        start_time = time.time()

        # Target should be a URL
        target_url = kwargs.get("url", str(target_path))

        # Validate URL
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return AdapterResult(
                    success=False,
                    error_message=f"Invalid URL: {target_url}",
                )
        except Exception as e:
            return AdapterResult(
                success=False,
                error_message=f"URL parsing failed: {e}",
            )

        # Build command
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        cmd = [
            self.zap_command,
            "-t",
            target_url,
            "-J",
            report_path,  # JSON report
        ]

        # Add custom rules file if specified
        rules_file = self.config.get("rules_file")
        if rules_file:
            cmd.extend(["-c", rules_file])

        # Add authentication if specified
        if self.config.get("auth_loginurl"):
            cmd.extend(["-l", self.config["auth_loginurl"]])
        if self.config.get("auth_username"):
            cmd.extend(["-u", self.config["auth_username"]])
        if self.config.get("auth_password"):
            cmd.extend(["-p", self.config["auth_password"]])

        # Add ajax spider for JS-heavy sites
        if self.config.get("ajax_spider", False):
            cmd.append("-j")

        # Minutes to spider
        minutes = self.config.get("minutes", 1)
        cmd.extend(["-m", str(minutes)])

        try:
            return_code, stdout, stderr = await self.run_command(
                cmd,
                cwd=None,
                timeout=kwargs.get("timeout", 900),  # 15 min default for web scans
                capture_json=False,
            )

            duration = time.time() - start_time
            version = await self.get_version()

            # Read the JSON report
            import json

            try:
                with open(report_path) as f:
                    raw_output = json.load(f)
            except Exception as e:
                logger.warning(f"Could not read ZAP report: {e}")
                raw_output = {}

            # Clean up temp file
            try:
                Path(report_path).unlink()
            except Exception:
                pass

            # ZAP returns 0 for pass, 1 for warnings, 2 for errors, 3 for fail
            if return_code > 2:
                return AdapterResult(
                    success=False,
                    error_message=f"ZAP scan failed with code {return_code}: {stderr}",
                    duration_seconds=duration,
                    tool_version=version,
                )

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
            logger.exception(f"ZAP scan failed: {e}")
            return AdapterResult(success=False, error_message=str(e))

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """Parse ZAP JSON output into findings."""
        findings = []

        site = raw_output.get("site", [])
        if isinstance(site, list):
            for s in site:
                alerts = s.get("alerts", [])
                for alert in alerts:
                    try:
                        finding = self._parse_alert(alert, s.get("@name", ""))
                        if finding:
                            finding.fingerprint = self.generate_fingerprint(finding)
                            findings.append(finding)
                    except Exception as e:
                        logger.warning(f"Failed to parse ZAP alert: {e}")
        elif isinstance(site, dict):
            alerts = site.get("alerts", [])
            for alert in alerts:
                try:
                    finding = self._parse_alert(alert, site.get("@name", ""))
                    if finding:
                        finding.fingerprint = self.generate_fingerprint(finding)
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse ZAP alert: {e}")

        return findings

    def _parse_alert(self, alert: dict[str, Any], site_name: str) -> Finding | None:
        """Parse a single ZAP alert into a Finding."""
        alert_name = alert.get("name", "Unknown Alert")
        risk_code = str(alert.get("riskcode", "2"))
        confidence_code = str(alert.get("confidence", "2"))
        description = alert.get("desc", "")
        solution = alert.get("solution", "")
        reference = alert.get("reference", "")
        cwe_id = alert.get("cweid", "")
        wasc_id = alert.get("wascid", "")

        # Get severity
        severity = ZAP_RISK_MAP.get(risk_code, FindingSeverity.MEDIUM)

        # Escalate high-risk alerts
        alert_lower = alert_name.lower()
        if any(pattern in alert_lower for pattern in HIGH_RISK_ALERTS):
            if severity == FindingSeverity.MEDIUM:
                severity = FindingSeverity.HIGH
            elif severity == FindingSeverity.LOW:
                severity = FindingSeverity.MEDIUM

        # Get confidence
        confidence = ZAP_CONFIDENCE_MAP.get(confidence_code, FindingConfidence.MEDIUM)

        # Get affected URLs
        instances = alert.get("instances", [])
        urls = []
        evidence_parts = []
        for instance in instances[:5]:  # Limit instances
            uri = instance.get("uri", "")
            method = instance.get("method", "")
            param = instance.get("param", "")
            evidence = instance.get("evidence", "")

            if uri:
                urls.append(uri)
            if evidence:
                evidence_parts.append(f"{method} {uri}\nParam: {param}\nEvidence: {evidence[:200]}")

        evidence_obj = Evidence(
            tool=self.name,
            file_path=urls[0] if urls else site_name,
            line_start=None,
            line_end=None,
            snippet="\n---\n".join(evidence_parts[:3]) if evidence_parts else None,
            raw_output=alert,
        )

        # Build references
        references = []
        if cwe_id:
            references.append(f"https://cwe.mitre.org/data/definitions/{cwe_id}.html")
        if wasc_id:
            references.append(f"http://projects.webappsec.org/w/page/{wasc_id}")
        if reference:
            # Parse reference HTML/text for URLs
            import re

            urls_in_ref = re.findall(r'https?://[^\s<>"]+', reference)
            references.extend(urls_in_ref[:3])

        # Build impact
        impact = self._get_impact(alert_name, severity)

        # Build attack scenario
        attack_scenario = self._get_attack_scenario(alert_name, instances)

        return Finding(
            title=alert_name,
            severity=severity,
            category=FindingCategory.WEB,
            confidence=confidence,
            description=self._clean_html(description),
            evidence=evidence_obj,
            impact=impact,
            attack_scenario=attack_scenario,
            recommendation=self._clean_html(solution) or "Review and fix according to security best practices.",
            patch=None,  # Web findings don't typically have patches
            references=references,
            cwe_id=f"CWE-{cwe_id}" if cwe_id else None,
        )

    def _clean_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        import re

        clean = re.sub(r"<[^>]+>", "", text)
        clean = clean.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        return clean.strip()

    def _get_impact(self, alert_name: str, severity: FindingSeverity) -> str:
        """Get impact description based on alert type."""
        alert_lower = alert_name.lower()

        if "sql injection" in alert_lower:
            return "SQL injection can allow attackers to read, modify, or delete database data, bypass authentication, or execute commands."
        elif "cross site scripting" in alert_lower or "xss" in alert_lower:
            return "XSS can allow attackers to steal session cookies, capture credentials, or perform actions as the victim."
        elif "csrf" in alert_lower:
            return "CSRF can allow attackers to perform unauthorized actions on behalf of authenticated users."
        elif "clickjacking" in alert_lower or "x-frame-options" in alert_lower:
            return "Clickjacking can trick users into clicking hidden elements, potentially leading to unauthorized actions."
        elif "ssl" in alert_lower or "tls" in alert_lower or "https" in alert_lower:
            return "SSL/TLS issues can allow attackers to intercept or modify traffic between users and the server."
        elif "header" in alert_lower:
            return "Missing or misconfigured security headers can expose the application to various attacks."

        return f"This {severity.value} severity issue could impact the security of the application and its users."

    def _get_attack_scenario(self, alert_name: str, instances: list) -> str:
        """Generate attack scenario based on alert type."""
        alert_lower = alert_name.lower()

        if "sql injection" in alert_lower:
            return (
                "1. Attacker identifies vulnerable parameter\n"
                "2. Attacker crafts SQL injection payload\n"
                "3. Database executes malicious query\n"
                "4. Attacker extracts or modifies data"
            )
        elif "xss" in alert_lower or "cross site scripting" in alert_lower:
            return (
                "1. Attacker injects malicious script\n"
                "2. Victim visits page with injected script\n"
                "3. Script executes in victim's browser\n"
                "4. Attacker steals session or performs actions"
            )
        elif "csrf" in alert_lower:
            return (
                "1. Attacker creates malicious page\n"
                "2. Victim visits attacker's page while logged in\n"
                "3. Hidden request sent to vulnerable site\n"
                "4. Action performed as victim"
            )

        # Generic scenario
        url = instances[0].get("uri", "target URL") if instances else "target URL"
        return f"1. Attacker identifies vulnerable endpoint: {url[:50]}\n2. Attacker exploits the vulnerability\n3. Impact depends on specific vulnerability type"
