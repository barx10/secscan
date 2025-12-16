"""Core data models for SecScan."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Categories of security findings."""

    SECRETS = "secrets"
    DEPS = "deps"
    SAST = "sast"
    CONFIG = "config"
    WEB = "web"
    PRIVACY = "privacy"


class FindingConfidence(str, Enum):
    """Confidence levels for findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanType(str, Enum):
    """Types of scans supported."""

    SECRETS = "secrets"
    DEPS = "deps"
    SAST = "sast"
    CONFIG = "config"
    WEB = "web"
    FULL = "full"


class ScanStatus(str, Enum):
    """Status of a scan job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Evidence(BaseModel):
    """Evidence supporting a finding."""

    tool: str = Field(..., description="Name of the tool that found this")
    file_path: str | None = Field(None, description="Path to the affected file")
    line_start: int | None = Field(None, description="Starting line number")
    line_end: int | None = Field(None, description="Ending line number")
    snippet: str | None = Field(None, description="Code snippet (limited to few lines)")
    raw_output: dict[str, Any] | None = Field(None, description="Raw tool output for traceability")


class Patch(BaseModel):
    """Suggested patch for a finding."""

    file_path: str = Field(..., description="Path to the file to patch")
    diff: str = Field(..., description="Unified diff format patch")
    description: str | None = Field(None, description="Description of what the patch does")


class Finding(BaseModel):
    """A security finding from a scan."""

    id: UUID = Field(default_factory=uuid4, description="Unique identifier")
    title: str = Field(..., description="Short title of the finding")
    severity: FindingSeverity = Field(..., description="Severity level")
    category: FindingCategory = Field(..., description="Category of finding")
    confidence: FindingConfidence = Field(..., description="Confidence level")
    description: str = Field(..., description="Detailed description of the issue")
    evidence: Evidence = Field(..., description="Evidence supporting this finding")
    impact: str = Field(..., description="Potential impact if exploited")
    attack_scenario: str | None = Field(None, description="How this could be exploited")
    recommendation: str = Field(..., description="How to fix this issue")
    patch: Patch | None = Field(None, description="Suggested patch if available")
    references: list[str] = Field(default_factory=list, description="URLs to relevant docs/CVEs")
    risk_score: float = Field(default=0.0, description="Calculated risk score 0-100")
    cwe_id: str | None = Field(None, description="CWE identifier if applicable")
    cve_id: str | None = Field(None, description="CVE identifier if applicable")
    fingerprint: str | None = Field(None, description="Deduplication fingerprint")
    suppressed: bool = Field(default=False, description="Whether this finding is suppressed")
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {UUID: str, datetime: lambda v: v.isoformat()}


class ScanConfig(BaseModel):
    """Configuration for a scan."""

    scan_types: list[ScanType] = Field(
        default_factory=lambda: [ScanType.FULL], description="Types of scans to run"
    )
    include_patterns: list[str] = Field(
        default_factory=list, description="File patterns to include"
    )
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/.git/**",
            "**/venv/**",
            "**/__pycache__/**",
            "**/dist/**",
            "**/build/**",
        ],
        description="File patterns to exclude",
    )
    severity_threshold: FindingSeverity = Field(
        default=FindingSeverity.INFO, description="Minimum severity to report"
    )
    fail_on_severity: FindingSeverity | None = Field(
        default=FindingSeverity.HIGH, description="Fail CI if findings at or above this severity"
    )
    max_findings: int | None = Field(None, description="Maximum findings to return")
    timeout_seconds: int = Field(default=3600, description="Maximum time for scan")
    generate_patches: bool = Field(default=True, description="Generate suggested patches")


class Project(BaseModel):
    """A project being scanned."""

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., description="Project name")
    description: str | None = Field(None)
    source_type: str = Field(..., description="repo, zip, or url")
    source_path: str = Field(..., description="Path or URL to source")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {UUID: str, datetime: lambda v: v.isoformat()}


class Scan(BaseModel):
    """A scan job."""

    id: UUID = Field(default_factory=uuid4)
    project_id: UUID = Field(..., description="Associated project")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    config: ScanConfig = Field(default_factory=ScanConfig)
    started_at: datetime | None = Field(None)
    completed_at: datetime | None = Field(None)
    error_message: str | None = Field(None)
    findings_count: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)
    risk_score: float = Field(default=0.0, description="Overall risk score 0-100")
    duration_seconds: float | None = Field(None)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {UUID: str, datetime: lambda v: v.isoformat()}


class ScanResult(BaseModel):
    """Complete result of a scan."""

    scan: Scan
    findings: list[Finding]
    summary: dict[str, Any] = Field(default_factory=dict)
