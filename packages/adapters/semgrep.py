"""Semgrep adapter for SAST scanning."""

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

# Semgrep rule categories mapped to our categories
CATEGORY_MAP = {
    "security": FindingCategory.SAST,
    "correctness": FindingCategory.SAST,
    "best-practice": FindingCategory.CONFIG,
    "performance": FindingCategory.SAST,
    "maintainability": FindingCategory.SAST,
}

# High-risk rule patterns
HIGH_RISK_RULES = [
    "sql-injection",
    "xss",
    "command-injection",
    "code-injection",
    "ssrf",
    "path-traversal",
    "open-redirect",
    "xxe",
    "deserialization",
    "hardcoded-secret",
    "jwt-",
    "auth-",
    "insecure-",
    "dangerous-",
]


class SemgrepAdapter(BaseAdapter):
    """Adapter for Semgrep SAST scanner."""

    name = "semgrep"
    tool_name = "semgrep"
    scan_types = [ScanType.SAST]
    required_binaries = ["semgrep"]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Default to auto config which uses language detection
        self.rulesets = config.get("rulesets", ["auto"]) if config else ["auto"]

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """Run semgrep scan on the target path."""
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="semgrep is not installed",
            )

        start_time = time.time()

        # Build command
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--no-git-ignore",  # Scan everything
        ]

        # Add rulesets
        for ruleset in self.rulesets:
            cmd.extend(["--config", ruleset])

        # Add severity filter if specified
        severity_filter = self.config.get("severity")
        if severity_filter:
            cmd.extend(["--severity", severity_filter])

        # Add exclude patterns
        exclude_patterns = self.config.get(
            "exclude",
            ["**/node_modules/**", "**/venv/**", "**/.git/**", "**/dist/**"],
        )
        for pattern in exclude_patterns:
            cmd.extend(["--exclude", pattern])

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

            # Semgrep returns non-zero on findings, but we still want to process them
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
            logger.exception(f"semgrep scan failed: {e}")
            return AdapterResult(success=False, error_message=str(e))

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """Parse semgrep JSON output into findings."""
        findings = []

        results = raw_output.get("results", [])
        for item in results:
            try:
                finding = self._parse_finding(item)
                if finding:
                    finding.fingerprint = self.generate_fingerprint(finding)
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse semgrep finding: {e}")

        return findings

    def _parse_finding(self, item: dict[str, Any]) -> Finding | None:
        """Parse a single semgrep finding."""
        check_id = item.get("check_id", "unknown")
        path = item.get("path", "")
        start = item.get("start", {})
        end = item.get("end", {})
        extra = item.get("extra", {})

        # Get severity
        severity_str = extra.get("severity", "WARNING")
        severity = map_tool_severity("semgrep", severity_str)

        # Boost severity for high-risk rules
        check_lower = check_id.lower()
        if any(pattern in check_lower for pattern in HIGH_RISK_RULES):
            if severity == FindingSeverity.MEDIUM:
                severity = FindingSeverity.HIGH
            elif severity == FindingSeverity.LOW:
                severity = FindingSeverity.MEDIUM

        # Get message and metadata
        message = extra.get("message", "Security issue detected")
        metadata = extra.get("metadata", {})

        # Determine category
        category = FindingCategory.SAST
        semgrep_category = metadata.get("category", "security")
        if semgrep_category in CATEGORY_MAP:
            category = CATEGORY_MAP[semgrep_category]

        # Get code snippet
        lines = extra.get("lines", "")

        # Determine confidence
        confidence = FindingConfidence.MEDIUM
        if metadata.get("confidence") == "HIGH":
            confidence = FindingConfidence.HIGH
        elif metadata.get("confidence") == "LOW":
            confidence = FindingConfidence.LOW

        evidence = Evidence(
            tool=self.name,
            file_path=path,
            line_start=start.get("line"),
            line_end=end.get("line"),
            snippet=lines[:500] if lines else None,  # Limit snippet size
            raw_output=item,
        )

        # Build references
        references = []
        if metadata.get("cwe"):
            cwe_list = metadata["cwe"]
            if isinstance(cwe_list, list):
                for cwe in cwe_list:
                    references.append(f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html")
        if metadata.get("owasp"):
            references.append("https://owasp.org/Top10/")
        if metadata.get("references"):
            refs = metadata["references"]
            if isinstance(refs, list):
                references.extend(refs)

        # Get CWE ID
        cwe_id = None
        if metadata.get("cwe"):
            cwe_list = metadata["cwe"]
            if isinstance(cwe_list, list) and cwe_list:
                cwe_id = cwe_list[0]

        # Generate patch if fix is available
        patch = None
        fix = extra.get("fix")
        if fix and path:
            patch = Patch(
                file_path=path,
                diff=self._generate_fix_diff(path, start.get("line", 0), lines, fix),
                description="Apply suggested fix from semgrep",
            )

        # Build impact description
        impact = metadata.get("impact", "")
        if not impact:
            impact = self._generate_impact(check_id, severity)

        # Build attack scenario
        attack_scenario = self._generate_attack_scenario(check_id, message)

        # Build recommendation
        recommendation = extra.get("fix_regex", "") or metadata.get("remediation", "")
        if not recommendation:
            recommendation = self._generate_recommendation(check_id, message)

        return Finding(
            title=f"{check_id.split('.')[-1].replace('-', ' ').title()}",
            severity=severity,
            category=category,
            confidence=confidence,
            description=message,
            evidence=evidence,
            impact=impact,
            attack_scenario=attack_scenario,
            recommendation=recommendation,
            patch=patch,
            references=references,
            cwe_id=cwe_id,
        )

    def _generate_fix_diff(
        self, path: str, line_number: int, original: str, fix: str
    ) -> str:
        """Generate a diff for the fix."""
        return f"""--- a/{path}
+++ b/{path}
@@ -{line_number},1 +{line_number},1 @@
-{original.strip()}
+{fix.strip()}
"""

    def _generate_impact(self, check_id: str, severity: FindingSeverity) -> str:
        """Generate impact description based on rule ID."""
        check_lower = check_id.lower()

        if "sql-injection" in check_lower:
            return (
                "SQL injection can allow attackers to read, modify, or delete database contents, "
                "bypass authentication, and in some cases execute commands on the database server."
            )
        elif "xss" in check_lower:
            return (
                "Cross-site scripting (XSS) can allow attackers to steal session cookies, "
                "capture credentials, redirect users to malicious sites, or deface the application."
            )
        elif "command-injection" in check_lower or "code-injection" in check_lower:
            return (
                "Command/code injection can allow attackers to execute arbitrary commands or code "
                "on the server, leading to complete system compromise."
            )
        elif "ssrf" in check_lower:
            return (
                "Server-side request forgery (SSRF) can allow attackers to access internal services, "
                "read local files, or pivot to attack other systems in the network."
            )
        elif "path-traversal" in check_lower:
            return (
                "Path traversal can allow attackers to read or write arbitrary files on the server, "
                "potentially leading to credential theft or code execution."
            )

        # Default based on severity
        severity_impacts = {
            FindingSeverity.CRITICAL: "This vulnerability could lead to complete system compromise.",
            FindingSeverity.HIGH: "This vulnerability could lead to significant data exposure or access control bypass.",
            FindingSeverity.MEDIUM: "This vulnerability could lead to limited security impact.",
            FindingSeverity.LOW: "This vulnerability has minimal direct security impact.",
            FindingSeverity.INFO: "This is an informational finding with no direct security impact.",
        }
        return severity_impacts.get(severity, "Security impact varies based on context.")

    def _generate_attack_scenario(self, check_id: str, message: str) -> str:
        """Generate attack scenario based on rule ID."""
        check_lower = check_id.lower()

        if "sql-injection" in check_lower:
            return (
                "1. Attacker identifies input field that's used in SQL query\n"
                "2. Attacker crafts malicious input (e.g., ' OR '1'='1)\n"
                "3. Application executes modified SQL query\n"
                "4. Attacker extracts data or bypasses authentication"
            )
        elif "xss" in check_lower:
            return (
                "1. Attacker crafts malicious input containing JavaScript\n"
                "2. Application renders input without proper encoding\n"
                "3. Victim's browser executes attacker's script\n"
                "4. Attacker steals session token or performs actions as victim"
            )
        elif "command-injection" in check_lower:
            return (
                "1. Attacker identifies input used in system command\n"
                "2. Attacker injects shell metacharacters (e.g., ; && |)\n"
                "3. Server executes attacker's commands\n"
                "4. Attacker gains shell access or exfiltrates data"
            )

        return f"Attack scenario depends on the specific context. Issue: {message[:200]}"

    def _generate_recommendation(self, check_id: str, message: str) -> str:
        """Generate recommendation based on rule ID."""
        check_lower = check_id.lower()

        if "sql-injection" in check_lower:
            return (
                "1. Use parameterized queries or prepared statements\n"
                "2. Use an ORM that handles escaping automatically\n"
                "3. Validate and sanitize all user input\n"
                "4. Apply principle of least privilege to database accounts"
            )
        elif "xss" in check_lower:
            return (
                "1. Encode output based on context (HTML, JS, URL, CSS)\n"
                "2. Use a templating engine with auto-escaping\n"
                "3. Implement Content-Security-Policy headers\n"
                "4. Validate and sanitize user input"
            )
        elif "command-injection" in check_lower:
            return (
                "1. Avoid shell commands with user input entirely\n"
                "2. Use language-native APIs instead of shell commands\n"
                "3. If shell is required, use allowlists for permitted values\n"
                "4. Never use string concatenation for command building"
            )
        elif "hardcoded" in check_lower or "secret" in check_lower:
            return (
                "1. Remove hardcoded credentials from code\n"
                "2. Use environment variables or secrets managers\n"
                "3. Rotate any exposed credentials immediately\n"
                "4. Review git history for exposed secrets"
            )

        return f"Review the code and apply secure coding practices. Refer to the rule documentation for specific guidance."
