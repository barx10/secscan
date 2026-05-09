"""Scanner pipeline and orchestration."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from uuid import UUID, uuid4

from packages.adapters.base import AdapterResult, BaseAdapter
from packages.adapters.registry import AdapterRegistry, get_registry
from packages.core.models import (
    Finding,
    Project,
    Scan,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanType,
)
from packages.core.scoring import calculate_overall_risk_score, prioritize_findings

logger = logging.getLogger(__name__)


class ScanPipeline:
    """
    Pipeline for running security scans.

    Orchestrates multiple scanner adapters and aggregates results.
    """

    def __init__(
        self,
        registry: AdapterRegistry | None = None,
        config: dict[str, Any] | None = None,
    ):
        """
        Initialize the scan pipeline.

        Args:
            registry: Adapter registry (uses global if not provided)
            config: Pipeline configuration
        """
        self.registry = registry or get_registry(config)
        self.config = config or {}
        self._progress_callback: Callable[[str, float], None] | None = None

    def set_progress_callback(self, callback: Callable[[str, float], None]) -> None:
        """Set callback for progress updates."""
        self._progress_callback = callback

    def _report_progress(self, message: str, progress: float) -> None:
        """Report progress to callback if set."""
        if self._progress_callback:
            self._progress_callback(message, progress)
        logger.info(f"[{progress:.0%}] {message}")

    async def scan_repo(
        self,
        repo_path: Path,
        config: ScanConfig | None = None,
        project: Project | None = None,
        scan_id: UUID | None = None,
    ) -> ScanResult:
        """
        Scan a local git repository.

        Args:
            repo_path: Path to the repository
            config: Scan configuration
            project: Project metadata (optional)
            scan_id: Existing scan ID to use (optional)

        Returns:
            ScanResult with all findings
        """
        config = config or ScanConfig()

        if not repo_path.exists():
            raise FileNotFoundError(f"Repository path does not exist: {repo_path}")

        # Create project if not provided
        if not project:
            project = Project(
                name=repo_path.name,
                source_type="repo",
                source_path=str(repo_path),
            )

        # Create scan
        scan = Scan(
            id=scan_id or uuid4(),
            project_id=project.id,
            config=config,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._report_progress("Starting repository scan", 0.0)

        try:
            # Run scans
            findings, adapter_status = await self._run_scans(repo_path, config)

            # Finalize scan
            scan = self._finalize_scan(scan, findings)

            self._report_progress("Scan completed", 1.0)
            
            summary = self._generate_summary(scan, findings)
            summary["adapter_status"] = adapter_status

            return ScanResult(
                scan=scan,
                findings=findings,
                summary=summary,
                adapter_status=adapter_status,
            )

        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()

            return ScanResult(
                scan=scan,
                findings=[],
                summary={"error": str(e)},
            )

    async def scan_git_url(
        self,
        repo_url: str,
        config: ScanConfig | None = None,
        project: Project | None = None,
        scan_id: UUID | None = None,
    ) -> ScanResult:
        """
        Clone and scan a remote git repository.
        """
        # Create project if not provided
        if not project:
            project = Project(
                name=repo_url.split("/")[-1].replace(".git", ""),
                source_type="repo",
                source_path=repo_url,
            )

        # Create scanner here just to report starting status if needed, 
        # but we defer to scan_repo for the actual Scan object creation.
        # However, since we want to report "Cloning...", we might want to manage it roughly here.
        # For simplicity, we'll let scan_repo create the object, but we need to handle the temp dir.
        
        try:
            logger.info(f"Cloning {repo_url} with GIT_TERMINAL_PROMPT=0")
            self._report_progress("Cloning repository...", 0.05)
            logger.info("Progress reported: 5%")
        
            # Prevent git from asking for credentials
            env = os.environ.copy()
            env["GIT_TERMINAL_PROMPT"] = "0"
        
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                logger.info("Starting git subprocess...")
                # Run git clone with timeout
                process = await asyncio.create_subprocess_exec(
                    "git", "clone", "--depth", "1", repo_url, temp_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                logger.info("Git subprocess started.")

                # Wait for clone (max 2 minutes)
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
                except asyncio.TimeoutError:
                    process.kill()
                    raise TimeoutError("Git clone timed out (repo might be private or large)")

                if process.returncode != 0:
                     err_msg = stderr.decode()
                     if "Authentication failed" in err_msg or "could not read Username" in err_msg:
                         raise RuntimeError("Git authentication failed. Is the repository private?")
                     raise RuntimeError(f"Failed to clone repository: {err_msg}")
                
                # Delegate to scan_repo
                return await self.scan_repo(temp_path, config, project, scan_id)

        except Exception as e:
                 # If cloning fails, we need to return a Failed ScanResult manually 
                 # because scan_repo wasn't called.
                scan = Scan(
                    id=scan_id or uuid4(),
                    project_id=project.id,
                    config=config or ScanConfig(),
                    status=ScanStatus.FAILED,
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    error_message=str(e)
                )
                return ScanResult(scan=scan, findings=[], summary={"error": str(e)})


    async def scan_zip(
        self,
        zip_path: Path,
        config: ScanConfig | None = None,
        project: Project | None = None,
        scan_id: UUID | None = None,
    ) -> ScanResult:
        """
        Scan a zip file containing source code.

        Args:
            zip_path: Path to the zip file
            config: Scan configuration
            project: Project metadata (optional)
            scan_id: Existing scan ID (optional)

        Returns:
            ScanResult with all findings
        """
        config = config or ScanConfig()

        # Create temp directory and extract
        with tempfile.TemporaryDirectory() as temp_dir:
            extract_path = Path(temp_dir) / "source"
            extract_path.mkdir()

            self._report_progress("Extracting zip file", 0.05)

            try:
                with zipfile.ZipFile(zip_path, "r") as zf:
                    # Security: check for path traversal
                    for name in zf.namelist():
                        if name.startswith("/") or ".." in name:
                            raise ValueError(f"Unsafe path in zip: {name}")
                    zf.extractall(extract_path)
            except zipfile.BadZipFile as e:
                raise ValueError(f"Invalid zip file: {e}")

            # Find the actual source root (handle single directory zips)
            contents = list(extract_path.iterdir())
            if len(contents) == 1 and contents[0].is_dir():
                source_root = contents[0]
            else:
                source_root = extract_path

            # Create project if not provided
            if not project:
                project = Project(
                    name=zip_path.stem,
                    source_type="zip",
                    source_path=str(zip_path),
                )

            # Run scan on extracted content
            return await self.scan_repo(source_root, config, project, scan_id)

    async def scan_url(
        self,
        url: str,
        config: ScanConfig | None = None,
        project: Project | None = None,
        scan_id: UUID | None = None,
    ) -> ScanResult:
        """
        Scan a running web application by URL.

        Args:
            url: URL of the web application
            config: Scan configuration
            project: Project metadata (optional)
            scan_id: Existing scan ID (optional)

        Returns:
            ScanResult with all findings
        """
        config = config or ScanConfig()

        # Ensure web scan is included
        if ScanType.WEB not in config.scan_types and ScanType.FULL not in config.scan_types:
            config.scan_types = [ScanType.WEB]

        # Create project if not provided
        if not project:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            project = Project(
                name=parsed.netloc,
                source_type="url",
                source_path=url,
            )

        # Create scan
        scan = Scan(
            id=scan_id or uuid4(),
            project_id=project.id,
            config=config,
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._report_progress("Starting web scan", 0.0)

        try:
            # Get all available web adapters
            web_adapters = [
                self.registry.get("nuclei"),
                self.registry.get("zap"),
            ]
            web_adapters = [a for a in web_adapters if a and a.is_available()]

            if not web_adapters:
                scan.status = ScanStatus.FAILED
                scan.error_message = "No web scanners available (Nuclei or ZAP required)"
                scan.completed_at = datetime.utcnow()
                return ScanResult(
                    scan=scan,
                    findings=[],
                    summary={"error": scan.error_message},
                )

            # Run all available web scanners concurrently
            all_findings = []
            adapter_status = {}

            total = len(web_adapters)
            tasks = []
            for i, adapter in enumerate(web_adapters):
                self._report_progress(f"Running {adapter.name} scan", 0.1 + 0.8 * i / total)
                tasks.append(adapter.scan(Path(url), url=url, timeout=config.timeout_seconds))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for adapter, result in zip(web_adapters, results):
                if isinstance(result, Exception):
                    logger.error(f"{adapter.name} failed: {result}")
                    adapter_status[adapter.name] = {
                        "tool": adapter.name, "success": False,
                        "duration": 0.0, "message": str(result),
                    }
                    continue

                adapter_status[adapter.name] = {
                    "tool": adapter.name,
                    "success": result.success,
                    "duration": result.duration_seconds,
                    "version": result.tool_version,
                    "findings_count": len(result.findings) if result.success else 0,
                    "message": result.error_message or "",
                }
                if result.success:
                    all_findings.extend(result.findings)
                else:
                    logger.warning(f"{adapter.name} failed: {result.error_message}")

            findings = prioritize_findings(all_findings)

            # Finalize scan
            scan = self._finalize_scan(scan, findings)

            self._report_progress("Web scan completed", 1.0)
            
            summary = self._generate_summary(scan, findings)
            summary["adapter_status"] = adapter_status

            return ScanResult(
                scan=scan,
                findings=findings,
                summary=summary,
                adapter_status=adapter_status,
            )

        except Exception as e:
            logger.exception(f"Web scan failed: {e}")
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()

            return ScanResult(
                scan=scan,
                findings=[],
                summary={"error": str(e)},
            )

    async def _run_scans(
        self,
        target_path: Path,
        config: ScanConfig,
    ) -> tuple[list[Finding], dict[str, Any]]:
        """
        Run all configured scans.

        Args:
            target_path: Path to scan
            config: Scan configuration

        Returns:
            Tuple of (findings, adapter_status)
        """
        all_findings: list[Finding] = []
        adapter_status: dict[str, Any] = {}

        # Determine which scan types to run
        scan_types = config.scan_types
        if ScanType.FULL in scan_types:
            scan_types = [ScanType.SECRETS, ScanType.DEPS, ScanType.SAST, ScanType.CONFIG]

        # Get adapters for each scan type
        adapters_to_run: list[BaseAdapter] = []
        for scan_type in scan_types:
            adapter = self.registry.get_preferred_adapter(scan_type)
            if adapter and adapter not in adapters_to_run:
                adapters_to_run.append(adapter)

        if not adapters_to_run:
            logger.warning("No scanners available")
            raise RuntimeError("No scanner tools available or selected. Please check Settings to install tools.")
            
        # Run scans concurrently
        total_adapters = len(adapters_to_run)
        tasks = []

        for i, adapter in enumerate(adapters_to_run):
            self._report_progress(
                f"Running {adapter.name} scanner",
                0.1 + (0.8 * i / total_adapters),
            )
            tasks.append(self._run_adapter(adapter, target_path, config))

        # Wait for all scans to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect findings and status
        for adapter, result in zip(adapters_to_run, results):
            status = {"tool": adapter.name, "success": False, "duration": 0.0, "message": ""}
            
            if isinstance(result, Exception):
                logger.error(f"Adapter {adapter.name} failed: {result}")
                status["message"] = str(result)
                adapter_status[adapter.name] = status
                continue

            status["success"] = result.success
            status["duration"] = result.duration_seconds
            status["version"] = result.tool_version
            
            if result.success:
                all_findings.extend(result.findings)
                status["findings_count"] = len(result.findings)
                logger.info(f"{adapter.name}: found {len(result.findings)} issues")
            else:
                logger.warning(f"{adapter.name} failed: {result.error_message}")
                status["message"] = result.error_message
            
            adapter_status[adapter.name] = status

        # Deduplicate findings
        all_findings = self._deduplicate_findings(all_findings)

        # Filter by severity threshold
        all_findings = [
            f
            for f in all_findings
            if self._severity_meets_threshold(f.severity, config.severity_threshold)
        ]

        # Prioritize findings
        all_findings = prioritize_findings(all_findings)

        # Limit findings if configured
        if config.max_findings:
            all_findings = all_findings[: config.max_findings]

        return all_findings, adapter_status

    async def _run_adapter(
        self,
        adapter: BaseAdapter,
        target_path: Path,
        config: ScanConfig,
    ) -> AdapterResult:
        """Run a single adapter with timeout."""
        try:
            return await asyncio.wait_for(
                adapter.scan(target_path, timeout=config.timeout_seconds),
                timeout=config.timeout_seconds + 60,  # Extra buffer
            )
        except asyncio.TimeoutError:
            return AdapterResult(
                success=False,
                error_message=f"Adapter {adapter.name} timed out",
            )

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on fingerprint."""
        seen: set[str] = set()
        unique: list[Finding] = []

        for finding in findings:
            fingerprint = finding.fingerprint
            if not fingerprint:
                # Generate fingerprint if not set
                from packages.adapters.base import BaseAdapter

                adapter = BaseAdapter()
                fingerprint = adapter.generate_fingerprint(finding)
                finding.fingerprint = fingerprint

            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(finding)

        return unique

    def _severity_meets_threshold(
        self,
        severity: Any,
        threshold: Any,
    ) -> bool:
        """Check if severity meets the threshold."""
        from packages.core.models import FindingSeverity

        severity_order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }

        return severity_order.get(severity, 5) <= severity_order.get(threshold, 4)

    def _finalize_scan(self, scan: Scan, findings: list[Finding]) -> Scan:
        """Finalize scan with results."""
        from packages.core.models import FindingSeverity

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()

        if scan.started_at:
            scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

        # Count findings by severity
        scan.findings_count = len(findings)
        scan.critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
        scan.high_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
        scan.medium_count = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)
        scan.low_count = sum(1 for f in findings if f.severity == FindingSeverity.LOW)
        scan.info_count = sum(1 for f in findings if f.severity == FindingSeverity.INFO)

        # Calculate overall risk score
        scan.risk_score = calculate_overall_risk_score(findings)

        return scan

    def _generate_summary(self, scan: Scan, findings: list[Finding]) -> dict[str, Any]:
        """Generate scan summary."""
        from packages.core.models import FindingCategory

        # Group findings by category
        by_category: dict[str, int] = {}
        for finding in findings:
            cat = finding.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        # Get top findings
        top_findings = [
            {
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "risk_score": f.risk_score,
            }
            for f in findings[:5]
        ]

        return {
            "total_findings": scan.findings_count,
            "by_severity": {
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "info": scan.info_count,
            },
            "by_category": by_category,
            "risk_score": scan.risk_score,
            "duration_seconds": scan.duration_seconds,
            "top_findings": top_findings,
        }

    def get_exit_code(self, scan: Scan, config: ScanConfig) -> int:
        """
        Get CI exit code based on scan results.

        Returns:
            0: No issues meeting threshold
            1: Issues found meeting threshold
            2: Scan failed
        """
        if scan.status == ScanStatus.FAILED:
            return 2

        if not config.fail_on_severity:
            return 0

        from packages.core.models import FindingSeverity

        severity_counts = {
            FindingSeverity.CRITICAL: scan.critical_count,
            FindingSeverity.HIGH: scan.high_count,
            FindingSeverity.MEDIUM: scan.medium_count,
            FindingSeverity.LOW: scan.low_count,
            FindingSeverity.INFO: scan.info_count,
        }

        severity_order = [
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ]

        # Check if any findings meet or exceed the threshold
        threshold_index = severity_order.index(config.fail_on_severity)
        for i, severity in enumerate(severity_order):
            if i <= threshold_index and severity_counts.get(severity, 0) > 0:
                return 1

        return 0
