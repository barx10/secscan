"""SQLAlchemy models for database storage."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class DBProject(Base):
    """Database model for projects."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # repo, zip, url
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    scans: Mapped[list["DBScan"]] = relationship("DBScan", back_populates="project")

    @property
    def project_metadata(self) -> dict[str, Any]:
        """Get metadata as dictionary."""
        if self.metadata_json:
            return json.loads(self.metadata_json)
        return {}

    @project_metadata.setter
    def project_metadata(self, value: dict[str, Any]) -> None:
        """Set metadata from dictionary."""
        self.metadata_json = json.dumps(value) if value else None


class DBScan(Base):
    """Database model for scans."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), default="pending")
    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    project: Mapped["DBProject"] = relationship("DBProject", back_populates="scans")
    findings: Mapped[list["DBFinding"]] = relationship("DBFinding", back_populates="scan")

    @property
    def config(self) -> dict[str, Any]:
        """Get config as dictionary."""
        if self.config_json:
            return json.loads(self.config_json)
        return {}

    @config.setter
    def config(self, value: dict[str, Any]) -> None:
        """Set config from dictionary."""
        self.config_json = json.dumps(value) if value else None


class DBFinding(Base):
    """Database model for findings."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    attack_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    patch_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    references_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    cwe_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    scan: Mapped["DBScan"] = relationship("DBScan", back_populates="findings")

    @property
    def evidence(self) -> dict[str, Any]:
        """Get evidence as dictionary."""
        return json.loads(self.evidence_json)

    @evidence.setter
    def evidence(self, value: dict[str, Any]) -> None:
        """Set evidence from dictionary."""
        self.evidence_json = json.dumps(value)

    @property
    def patch(self) -> dict[str, Any] | None:
        """Get patch as dictionary."""
        if self.patch_json:
            return json.loads(self.patch_json)
        return None

    @patch.setter
    def patch(self, value: dict[str, Any] | None) -> None:
        """Set patch from dictionary."""
        self.patch_json = json.dumps(value) if value else None

    @property
    def references(self) -> list[str]:
        """Get references as list."""
        if self.references_json:
            return json.loads(self.references_json)
        return []

    @references.setter
    def references(self, value: list[str]) -> None:
        """Set references from list."""
        self.references_json = json.dumps(value) if value else None
