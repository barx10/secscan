"""Base reporter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any

from packages.core.models import ScanResult


class ReportFormat(str, Enum):
    """Supported report formats."""

    JSON = "json"
    HTML = "html"
    SARIF = "sarif"  # Future: SARIF format for GitHub integration
    MARKDOWN = "markdown"  # Future: Markdown format


class BaseReporter(ABC):
    """Base class for report generators."""

    format: ReportFormat

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize reporter.

        Args:
            config: Reporter-specific configuration
        """
        self.config = config or {}

    @abstractmethod
    def generate(self, result: ScanResult) -> str:
        """
        Generate report content.

        Args:
            result: Scan result to report on

        Returns:
            Report content as string
        """
        pass

    def save(self, result: ScanResult, output_path: Path) -> None:
        """
        Generate and save report to file.

        Args:
            result: Scan result to report on
            output_path: Path to save the report
        """
        content = self.generate(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

    def get_severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            "critical": "#dc3545",  # Red
            "high": "#fd7e14",  # Orange
            "medium": "#ffc107",  # Yellow
            "low": "#17a2b8",  # Blue
            "info": "#6c757d",  # Gray
        }
        return colors.get(severity.lower(), "#6c757d")

    def get_severity_badge(self, severity: str) -> str:
        """Get emoji/badge for severity level."""
        badges = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }
        return badges.get(severity.lower(), "⚪")
