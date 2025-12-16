"""Syft adapter for SBOM generation."""

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
    ScanType,
)

logger = logging.getLogger(__name__)


class SyftAdapter(BaseAdapter):
    """Adapter for Syft SBOM generator."""

    name = "syft"
    tool_name = "syft"
    scan_types = [ScanType.DEPS]  # Used for SBOM, not direct findings
    required_binaries = ["syft"]

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """
        Generate SBOM for the target path.

        Note: Syft primarily generates SBOM, not security findings.
        The SBOM can be used by other tools for vulnerability scanning.
        """
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="syft is not installed",
            )

        start_time = time.time()

        # Output format
        output_format = self.config.get("format", "json")

        # Build command
        cmd = [
            "syft",
            str(target_path),
            "-o",
            output_format,
        ]

        # Add scope if specified (all-layers, squashed)
        scope = self.config.get("scope")
        if scope:
            cmd.extend(["--scope", scope])

        try:
            return_code, stdout, stderr = await self.run_command(
                cmd,
                cwd=target_path if target_path.is_dir() else target_path.parent,
                timeout=kwargs.get("timeout", 300),
            )

            duration = time.time() - start_time
            version = await self.get_version()

            if return_code != 0:
                return AdapterResult(
                    success=False,
                    error_message=f"syft failed: {stderr}",
                    duration_seconds=duration,
                    tool_version=version,
                )

            raw_output = stdout if isinstance(stdout, dict) else {"raw": stdout}
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
            logger.exception(f"syft scan failed: {e}")
            return AdapterResult(success=False, error_message=str(e))

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """
        Parse syft JSON output.

        Syft generates SBOM, not security findings directly.
        We return informational findings about the detected packages
        and flag any potentially risky patterns.
        """
        findings = []

        # Check for SBOM format
        artifacts = raw_output.get("artifacts", [])

        if not artifacts:
            return findings

        # Track package counts by type
        package_counts: dict[str, int] = {}
        potentially_risky: list[dict] = []

        for artifact in artifacts:
            pkg_type = artifact.get("type", "unknown")
            package_counts[pkg_type] = package_counts.get(pkg_type, 0) + 1

            # Check for potentially risky patterns
            name = artifact.get("name", "").lower()
            version = artifact.get("version", "")

            # Flag deprecated or dev packages in production
            if any(
                pattern in name
                for pattern in ["deprecated", "dev-", "-dev", "test", "debug"]
            ):
                potentially_risky.append(
                    {
                        "name": artifact.get("name"),
                        "version": version,
                        "type": pkg_type,
                        "reason": "Potentially development/test package",
                    }
                )

            # Flag very old versions (basic heuristic)
            if version and version.startswith("0."):
                # Version 0.x might be unstable
                potentially_risky.append(
                    {
                        "name": artifact.get("name"),
                        "version": version,
                        "type": pkg_type,
                        "reason": "Pre-1.0 version may be unstable",
                    }
                )

        # Create informational finding about SBOM
        if package_counts:
            summary_lines = [f"- {ptype}: {count}" for ptype, count in sorted(package_counts.items())]
            summary = "\n".join(summary_lines)

            evidence = Evidence(
                tool=self.name,
                file_path=str(raw_output.get("source", {}).get("target", "")),
                line_start=None,
                line_end=None,
                snippet=f"Total packages: {sum(package_counts.values())}\n{summary}",
                raw_output={"package_counts": package_counts},
            )

            findings.append(
                Finding(
                    title="SBOM Generated - Package Inventory",
                    severity=FindingSeverity.INFO,
                    category=FindingCategory.DEPS,
                    confidence=FindingConfidence.HIGH,
                    description=(
                        f"Software Bill of Materials (SBOM) generated. "
                        f"Found {sum(package_counts.values())} packages across "
                        f"{len(package_counts)} ecosystems."
                    ),
                    evidence=evidence,
                    impact="Informational - SBOM provides visibility into dependencies.",
                    attack_scenario=None,
                    recommendation=(
                        "Use this SBOM with vulnerability scanners (osv-scanner, trivy) "
                        "to identify vulnerable dependencies. Keep SBOM updated for "
                        "supply chain security visibility."
                    ),
                    patch=None,
                    references=[
                        "https://www.cisa.gov/sbom",
                        "https://github.com/anchore/syft",
                    ],
                )
            )

        # Create findings for potentially risky packages
        for risky in potentially_risky[:10]:  # Limit to avoid noise
            evidence = Evidence(
                tool=self.name,
                file_path=None,
                line_start=None,
                line_end=None,
                snippet=f"{risky['type']}: {risky['name']}@{risky['version']}",
                raw_output=risky,
            )

            findings.append(
                Finding(
                    title=f"Review Package: {risky['name']}",
                    severity=FindingSeverity.LOW,
                    category=FindingCategory.DEPS,
                    confidence=FindingConfidence.LOW,
                    description=f"{risky['reason']}. Package: {risky['name']}@{risky['version']}",
                    evidence=evidence,
                    impact="Low - may indicate code quality or stability concerns.",
                    attack_scenario=None,
                    recommendation=(
                        "Review if this package is necessary for production. "
                        "Consider upgrading to stable versions or finding alternatives."
                    ),
                    patch=None,
                    references=[],
                )
            )

        return findings

    async def generate_sbom(
        self,
        target_path: Path,
        output_path: Path | None = None,
        output_format: str = "spdx-json",
    ) -> dict[str, Any]:
        """
        Generate SBOM and optionally save to file.

        Args:
            target_path: Path to scan
            output_path: Path to save SBOM (optional)
            output_format: Output format (json, spdx-json, cyclonedx-json, etc.)

        Returns:
            SBOM data as dictionary
        """
        if not self.is_available():
            raise RuntimeError("syft is not installed")

        cmd = [
            "syft",
            str(target_path),
            "-o",
            output_format,
        ]

        if output_path:
            cmd.extend(["--file", str(output_path)])

        return_code, stdout, stderr = await self.run_command(
            cmd,
            timeout=300,
        )

        if return_code != 0:
            raise RuntimeError(f"syft failed: {stderr}")

        return stdout if isinstance(stdout, dict) else {}
