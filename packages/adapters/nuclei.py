"""Nuclei adapter for web application scanning."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
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

logger = logging.getLogger(__name__)

# Nuclei severity mapping
NUCLEI_SEVERITY_MAP = {
    "info": FindingSeverity.INFO,
    "low": FindingSeverity.LOW,
    "medium": FindingSeverity.MEDIUM,
    "high": FindingSeverity.HIGH,
    "critical": FindingSeverity.CRITICAL,
}


class NucleiAdapter(BaseAdapter):
    """Adapter for Nuclei web scanner."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize Nuclei adapter."""
        super().__init__(config)
        self.nuclei_command = self.config.get("nuclei_command", "nuclei")

    @property
    def name(self) -> str:
        """Get adapter name."""
        return "nuclei"

    @property
    def scan_types(self) -> list[ScanType]:
        """Get supported scan types."""
        return [ScanType.WEB]

    @property
    def tool_name(self) -> str:
        """Get tool display name."""
        return "Nuclei"

    @property
    def required_binaries(self) -> list[str]:
        """Get required binary names."""
        return ["nuclei"]

    def is_available(self) -> bool:
        """Check if Nuclei is installed."""
        return shutil.which(self.nuclei_command) is not None

    async def get_version(self) -> str | None:
        """Get Nuclei version."""
        cmd = [self.nuclei_command, "-version"]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            # Nuclei writes version info to stdout
            output = stdout.decode().strip()
            
            # Output format: "[INF] Nuclei Engine Version: v3.6.1"
            for line in output.split('\n'):
                if "Nuclei Engine Version:" in line:
                    # Extract version like "v3.6.1"
                    version = line.split(":")[-1].strip().lstrip('v')
                    return version
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not get Nuclei version: {e}")
            return None

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """
        Run Nuclei scan on the target URL.

        Args:
            target_path: Not used for Nuclei (URL-based)
            **kwargs: Must contain 'url' with target URL

        Returns:
            AdapterResult with findings
        """
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="Nuclei is not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            )

        start_time = time.time()

        # Get target URL
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

        with tempfile.NamedTemporaryFile(mode='w', suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        # Nuclei command with JSON output
        cmd = [
            self.nuclei_command,
            "-u", target_url,
            "-json",
            "-o", report_path,
            "-silent",  # Suppress banner
            "-stats",   # Show statistics
        ]

        # Add severity filter if configured
        severity = self.config.get("severity", ["critical", "high", "medium", "low", "info"])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        # Add tags if configured (e.g., cve, owasp, exposure)
        tags = self.config.get("tags", [])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        # Add rate limit to avoid overwhelming target
        rate_limit = self.config.get("rate_limit", 150)
        cmd.extend(["-rate-limit", str(rate_limit)])

        logger.info(f"Running Nuclei scan on {target_url}")
        logger.debug(f"Command: {' '.join(cmd)}")

        try:
            # Run Nuclei
            timeout = kwargs.get("timeout", 600)
            returncode, stdout, stderr = await self.run_command(
                cmd, timeout=timeout
            )

            # Parse results
            findings = []
            
            try:
                with open(report_path, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                result = json.loads(line)
                                finding = self._parse_nuclei_result(result, target_url)
                                if finding:
                                    findings.append(finding)
                            except json.JSONDecodeError:
                                logger.debug(f"Could not parse line: {line[:100]}")
                                continue
            except FileNotFoundError:
                logger.warning(f"Nuclei report file not found: {report_path}")

            # Clean up temp file
            try:
                Path(report_path).unlink()
            except Exception:
                pass

            duration = time.time() - start_time
            version = await self.get_version()

            return AdapterResult(
                success=True,
                findings=findings,
                duration_seconds=duration,
                tool_version=version,
            )

        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return AdapterResult(
                success=False,
                error_message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _parse_nuclei_result(self, result: dict[str, Any], target_url: str) -> Finding | None:
        """Parse a Nuclei JSON result into a Finding."""
        try:
            info = result.get("info", {})
            template_id = result.get("template-id", "unknown")
            name = info.get("name", template_id)
            severity = info.get("severity", "info").lower()
            description = info.get("description", "")
            
            # Get matched URL and extract
            matched_at = result.get("matched-at", target_url)
            extracted = result.get("extracted-results", [])
            
            # Build evidence snippet
            snippet_parts = []
            if extracted:
                snippet_parts.append("Extracted data:")
                snippet_parts.extend(f"  - {item}" for item in extracted[:5])
            
            matcher_name = result.get("matcher-name", "")
            if matcher_name:
                snippet_parts.append(f"Matcher: {matcher_name}")
            
            snippet = "\n".join(snippet_parts) if snippet_parts else matched_at

            # Map severity
            finding_severity = NUCLEI_SEVERITY_MAP.get(
                severity, FindingSeverity.INFO
            )

            # Determine category based on tags
            tags = info.get("tags", [])
            category = FindingCategory.WEB
            
            # Build references
            references = []
            if "reference" in info:
                refs = info["reference"]
                if isinstance(refs, str):
                    references = [refs]
                elif isinstance(refs, list):
                    references = refs

            # CVE references
            cve_id = result.get("cve-id")
            if cve_id:
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

            # Build recommendation
            remediation = info.get("remediation", "")
            if not remediation:
                remediation = f"Review and fix the vulnerability identified by template: {template_id}"

            finding = Finding(
                title=name,
                severity=finding_severity,
                category=category,
                confidence=FindingConfidence.HIGH,  # Nuclei templates are well-tested
                description=description or f"Nuclei template {template_id} matched",
                evidence=Evidence(
                    tool="nuclei",
                    file_path=matched_at,
                    snippet=snippet,
                    raw_output=result,
                ),
                impact=f"Severity: {severity.upper()}. This vulnerability was detected using Nuclei template {template_id}.",
                recommendation=remediation,
                references=references,
            )

            return finding

        except Exception as e:
            logger.error(f"Error parsing Nuclei result: {e}")
            logger.debug(f"Result: {result}")
            return None

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """
        Parse raw Nuclei output into findings.
        
        Args:
            raw_output: Raw output from Nuclei (dict with results list)
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Handle both single result dict and list of results
        results = raw_output if isinstance(raw_output, list) else raw_output.get("results", [])
        
        for result in results:
            finding = self._parse_nuclei_result(result, result.get("matched-at", ""))
            if finding:
                findings.append(finding)
        
        return findings
