"""OSV Scanner adapter for dependency vulnerability scanning."""

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


class OsvScannerAdapter(BaseAdapter):
    """Adapter for OSV Scanner (osv-scanner) dependency vulnerability scanner."""

    name = "osv-scanner"
    tool_name = "osv-scanner"
    scan_types = [ScanType.DEPS]
    required_binaries = ["osv-scanner"]

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """Run osv-scanner on the target path."""
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="osv-scanner is not installed",
            )

        start_time = time.time()

        # Build command
        cmd = [
            "osv-scanner",
            "--format",
            "json",
            "-r",  # Recursive
            str(target_path),
        ]

        # Add lockfile if specified
        lockfile = self.config.get("lockfile")
        if lockfile:
            cmd = [
                "osv-scanner",
                "--format",
                "json",
                "-L",
                lockfile,
            ]

        # Add SBOM if specified
        sbom = self.config.get("sbom")
        if sbom:
            cmd = [
                "osv-scanner",
                "--format",
                "json",
                "-S",
                sbom,
            ]

        try:
            return_code, stdout, stderr = await self.run_command(
                cmd,
                cwd=target_path,
                timeout=kwargs.get("timeout", 300),
            )

            duration = time.time() - start_time
            version = await self.get_version()

            # osv-scanner returns 1 if vulnerabilities found
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
            logger.exception(f"osv-scanner scan failed: {e}")
            return AdapterResult(success=False, error_message=str(e))

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """Parse osv-scanner JSON output into findings."""
        findings = []

        results = raw_output.get("results", [])
        for result in results:
            source = result.get("source", {})
            source_path = source.get("path", "")

            packages = result.get("packages", [])
            for package in packages:
                pkg_info = package.get("package", {})
                pkg_name = pkg_info.get("name", "")
                pkg_version = pkg_info.get("version", "")
                pkg_ecosystem = pkg_info.get("ecosystem", "")

                vulnerabilities = package.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    try:
                        finding = self._parse_vulnerability(
                            vuln, pkg_name, pkg_version, pkg_ecosystem, source_path
                        )
                        if finding:
                            finding.fingerprint = self.generate_fingerprint(finding)
                            findings.append(finding)
                    except Exception as e:
                        logger.warning(f"Failed to parse osv-scanner vulnerability: {e}")

        return findings

    def _parse_vulnerability(
        self,
        vuln: dict[str, Any],
        pkg_name: str,
        pkg_version: str,
        ecosystem: str,
        source_path: str,
    ) -> Finding | None:
        """Parse a single vulnerability finding."""
        vuln_id = vuln.get("id", "")
        summary = vuln.get("summary", f"Vulnerability in {pkg_name}")
        details = vuln.get("details", "")
        published = vuln.get("published", "")
        modified = vuln.get("modified", "")

        # Get severity from CVSS or database severity
        severity = self._determine_severity(vuln)

        # Get affected versions and fixed version
        affected = vuln.get("affected", [])
        fixed_version = None
        for aff in affected:
            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                for event in events:
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        break

        # Get aliases (CVE IDs)
        aliases = vuln.get("aliases", [])
        cve_id = None
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break

        # Build references
        references = []
        for ref in vuln.get("references", [])[:5]:
            url = ref.get("url", "")
            if url:
                references.append(url)

        # Add database link
        if vuln_id.startswith("GHSA-"):
            references.insert(0, f"https://github.com/advisories/{vuln_id}")
        elif vuln_id.startswith("PYSEC-"):
            references.insert(0, f"https://osv.dev/vulnerability/{vuln_id}")

        evidence = Evidence(
            tool=self.name,
            file_path=source_path,
            line_start=None,
            line_end=None,
            snippet=f"{ecosystem}: {pkg_name}@{pkg_version}",
            raw_output=vuln,
        )

        # Generate patch
        patch = None
        if fixed_version:
            patch = Patch(
                file_path=source_path,
                diff=f"Update {pkg_name} from {pkg_version} to {fixed_version}",
                description=f"Upgrade {pkg_name} to version {fixed_version} or later to fix {vuln_id}",
            )

        return Finding(
            title=f"{vuln_id}: {summary[:100]}",
            severity=severity,
            category=FindingCategory.DEPS,
            confidence=FindingConfidence.HIGH,
            description=details[:1000] if details else summary,
            evidence=evidence,
            impact=(
                f"Vulnerability {vuln_id} in {pkg_name}@{pkg_version} could be exploited. "
                f"Check the vulnerability database for specific impact details."
            ),
            attack_scenario=(
                f"Attack scenarios depend on the specific vulnerability. "
                f"See {vuln_id} in the OSV database for details."
            ),
            recommendation=(
                f"Upgrade {pkg_name} to version {fixed_version}" if fixed_version
                else f"Monitor for a fix to {vuln_id} and upgrade when available. "
                "Consider alternative packages if no fix is coming."
            ),
            patch=patch,
            references=references,
            cve_id=cve_id,
        )

    def _determine_severity(self, vuln: dict[str, Any]) -> FindingSeverity:
        """Determine severity from vulnerability data."""
        # Check database_specific severity
        db_specific = vuln.get("database_specific", {})
        severity_str = db_specific.get("severity", "")
        if severity_str:
            severity_upper = severity_str.upper()
            if severity_upper == "CRITICAL":
                return FindingSeverity.CRITICAL
            elif severity_upper == "HIGH":
                return FindingSeverity.HIGH
            elif severity_upper == "MODERATE" or severity_upper == "MEDIUM":
                return FindingSeverity.MEDIUM
            elif severity_upper == "LOW":
                return FindingSeverity.LOW

        # Check CVSS scores in severity array
        severity_data = vuln.get("severity", [])
        for sev in severity_data:
            score_str = sev.get("score", "")
            if score_str.startswith("CVSS:"):
                # Parse CVSS score
                # Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                try:
                    # Try to extract base score
                    parts = score_str.split("/")
                    for part in parts:
                        if part.startswith("BM:") or part.startswith("BS:"):
                            score = float(part.split(":")[1])
                            return self._cvss_to_severity(score)
                except Exception:
                    pass

        # Check affected severity if available
        affected = vuln.get("affected", [])
        for aff in affected:
            eco_specific = aff.get("ecosystem_specific", {})
            if "severity" in eco_specific:
                sev = eco_specific["severity"].upper()
                if sev == "CRITICAL":
                    return FindingSeverity.CRITICAL
                elif sev == "HIGH":
                    return FindingSeverity.HIGH
                elif sev in ["MODERATE", "MEDIUM"]:
                    return FindingSeverity.MEDIUM
                elif sev == "LOW":
                    return FindingSeverity.LOW

        # Default to MEDIUM if unknown
        return FindingSeverity.MEDIUM

    def _cvss_to_severity(self, score: float) -> FindingSeverity:
        """Convert CVSS score to severity."""
        if score >= 9.0:
            return FindingSeverity.CRITICAL
        elif score >= 7.0:
            return FindingSeverity.HIGH
        elif score >= 4.0:
            return FindingSeverity.MEDIUM
        elif score >= 0.1:
            return FindingSeverity.LOW
        return FindingSeverity.INFO
