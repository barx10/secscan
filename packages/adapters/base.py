"""Base adapter interface for scanner tools."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packages.core.models import Finding, ScanType

logger = logging.getLogger(__name__)


@dataclass
class AdapterResult:
    """Result from a scanner adapter."""

    success: bool
    findings: list[Finding] = field(default_factory=list)
    raw_output: dict[str, Any] | None = None
    error_message: str | None = None
    duration_seconds: float = 0.0
    tool_version: str | None = None


class BaseAdapter(ABC):
    """
    Base class for scanner tool adapters.

    Each adapter wraps an external tool and converts its output to our
    standardized Finding format.
    """

    name: str = "base"
    tool_name: str = "unknown"
    scan_types: list[ScanType] = []
    required_binaries: list[str] = []

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize adapter with optional configuration."""
        self.config = config or {}
        self._tool_path: str | None = None

    def is_available(self) -> bool:
        """Check if the required tool is installed and available."""
        for binary in self.required_binaries:
            if not shutil.which(binary):
                logger.warning(f"{self.name}: Required binary '{binary}' not found")
                return False
        return True

    def get_tool_path(self) -> str | None:
        """Get the path to the tool binary."""
        if self._tool_path:
            return self._tool_path
        if self.required_binaries:
            self._tool_path = shutil.which(self.required_binaries[0])
        return self._tool_path

    async def get_version(self) -> str | None:
        """Get the version of the installed tool."""
        tool_path = self.get_tool_path()
        if not tool_path:
            return None

        try:
            proc = await asyncio.create_subprocess_exec(
                tool_path,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip().split("\n")[0]
        except Exception as e:
            logger.debug(f"Could not get version for {self.name}: {e}")
            return None

    @abstractmethod
    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """
        Run the scan on the target path.

        Args:
            target_path: Path to the directory or file to scan
            **kwargs: Additional scan options

        Returns:
            AdapterResult with findings and metadata
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """
        Parse raw tool output into standardized findings.

        Args:
            raw_output: Raw output from the tool (usually JSON)

        Returns:
            List of Finding objects
        """
        pass

    async def run_command(
        self,
        cmd: list[str],
        cwd: Path | None = None,
        timeout: int = 300,
        capture_json: bool = True,
    ) -> tuple[int, dict[str, Any] | str, str]:
        """
        Run a command and capture its output.

        Args:
            cmd: Command and arguments to run
            cwd: Working directory
            timeout: Timeout in seconds
            capture_json: Whether to parse stdout as JSON

        Returns:
            Tuple of (return_code, stdout, stderr)
        """

        logger.debug(f"Running command: {' '.join(cmd)}")

        if cwd and not cwd.exists():
            return 1, "", f"Working directory does not exist: {cwd}"
            
        executable = cmd[0]
        if not shutil.which(executable) and not Path(executable).exists():
             return 1, "", f"Executable not found: {executable}"

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                raise TimeoutError(f"Command timed out after {timeout}s")

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            if capture_json and stdout_str.strip():
                try:
                    stdout_parsed = json.loads(stdout_str)
                    return proc.returncode or 0, stdout_parsed, stderr_str
                except json.JSONDecodeError:
                    logger.debug(f"Could not parse JSON output: {stdout_str[:200]}")
                    return proc.returncode or 0, stdout_str, stderr_str

            return proc.returncode or 0, stdout_str, stderr_str

        except FileNotFoundError:
            raise RuntimeError(f"Command not found: {cmd[0]}")

    def generate_fingerprint(self, finding: Finding) -> str:
        """
        Generate a unique fingerprint for deduplication.

        The fingerprint is based on:
        - Tool name
        - File path
        - Line number (if available)
        - Finding title/rule ID
        """
        components = [
            finding.evidence.tool,
            finding.evidence.file_path or "",
            str(finding.evidence.line_start or 0),
            finding.title,
        ]
        content = "|".join(components)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def generate_patch(
        self, file_path: Path, line_start: int, original: str, replacement: str
    ) -> str:
        """
        Generate a unified diff patch.

        Args:
            file_path: Path to the file
            line_start: Starting line number
            original: Original content
            replacement: Replacement content

        Returns:
            Unified diff string
        """
        import difflib

        original_lines = original.splitlines(keepends=True)
        replacement_lines = replacement.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            replacement_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )

        return "".join(diff)
