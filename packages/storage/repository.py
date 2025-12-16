"""Repository classes for database operations."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from packages.core.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    Patch,
    Project,
    Scan,
    ScanConfig,
    ScanStatus,
)
from packages.storage.models import DBFinding, DBProject, DBScan


class ProjectRepository:
    """Repository for project operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, project: Project) -> DBProject:
        """Create a new project."""
        db_project = DBProject(
            id=str(project.id),
            name=project.name,
            description=project.description,
            source_type=project.source_type,
            source_path=project.source_path,
            metadata_json=json.dumps(project.metadata) if project.metadata else None,
            created_at=project.created_at,
            updated_at=project.updated_at,
        )
        self.session.add(db_project)
        await self.session.flush()
        return db_project

    async def get(self, project_id: str | UUID) -> DBProject | None:
        """Get a project by ID."""
        result = await self.session.execute(
            select(DBProject).where(DBProject.id == str(project_id))
        )
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> DBProject | None:
        """Get a project by name."""
        result = await self.session.execute(
            select(DBProject).where(DBProject.name == name)
        )
        return result.scalar_one_or_none()

    async def list(self, limit: int = 100, offset: int = 0) -> list[DBProject]:
        """List all projects."""
        result = await self.session.execute(
            select(DBProject)
            .order_by(DBProject.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def update(self, project_id: str | UUID, **kwargs: Any) -> DBProject | None:
        """Update a project."""
        db_project = await self.get(project_id)
        if not db_project:
            return None

        for key, value in kwargs.items():
            if hasattr(db_project, key):
                setattr(db_project, key, value)

        db_project.updated_at = datetime.utcnow()
        await self.session.flush()
        return db_project

    async def delete(self, project_id: str | UUID) -> bool:
        """Delete a project and all related data."""
        db_project = await self.get(project_id)
        if not db_project:
            return False

        await self.session.delete(db_project)
        await self.session.flush()
        return True

    def to_model(self, db_project: DBProject) -> Project:
        """Convert DB model to domain model."""
        return Project(
            id=UUID(db_project.id),
            name=db_project.name,
            description=db_project.description,
            source_type=db_project.source_type,
            source_path=db_project.source_path,
            metadata=db_project.metadata,
            created_at=db_project.created_at,
            updated_at=db_project.updated_at,
        )


class ScanRepository:
    """Repository for scan operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, scan: Scan) -> DBScan:
        """Create a new scan."""
        db_scan = DBScan(
            id=str(scan.id),
            project_id=str(scan.project_id),
            status=scan.status.value,
            config_json=scan.config.model_dump_json(),
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            error_message=scan.error_message,
            findings_count=scan.findings_count,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            info_count=scan.info_count,
            risk_score=scan.risk_score,
            duration_seconds=scan.duration_seconds,
            created_at=scan.created_at,
        )
        self.session.add(db_scan)
        await self.session.flush()
        return db_scan

    async def get(self, scan_id: str | UUID) -> DBScan | None:
        """Get a scan by ID."""
        result = await self.session.execute(
            select(DBScan).where(DBScan.id == str(scan_id))
        )
        return result.scalar_one_or_none()

    async def get_with_findings(self, scan_id: str | UUID) -> DBScan | None:
        """Get a scan with findings loaded."""
        result = await self.session.execute(
            select(DBScan)
            .options(selectinload(DBScan.findings))
            .where(DBScan.id == str(scan_id))
        )
        return result.scalar_one_or_none()

    async def list_by_project(
        self, project_id: str | UUID, limit: int = 100, offset: int = 0
    ) -> list[DBScan]:
        """List scans for a project."""
        result = await self.session.execute(
            select(DBScan)
            .where(DBScan.project_id == str(project_id))
            .order_by(DBScan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def list_recent(self, limit: int = 10) -> list[DBScan]:
        """List recent scans across all projects."""
        result = await self.session.execute(
            select(DBScan)
            .order_by(DBScan.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def update(self, scan_id: str | UUID, **kwargs: Any) -> DBScan | None:
        """Update a scan."""
        db_scan = await self.get(scan_id)
        if not db_scan:
            return None

        for key, value in kwargs.items():
            if key == "status" and isinstance(value, ScanStatus):
                value = value.value
            if key == "config" and isinstance(value, ScanConfig):
                value = value.model_dump_json()
                key = "config_json"
            if hasattr(db_scan, key):
                setattr(db_scan, key, value)

        await self.session.flush()
        return db_scan

    async def delete(self, scan_id: str | UUID) -> bool:
        """Delete a scan and all findings."""
        db_scan = await self.get(scan_id)
        if not db_scan:
            return False

        await self.session.delete(db_scan)
        await self.session.flush()
        return True

    def to_model(self, db_scan: DBScan) -> Scan:
        """Convert DB model to domain model."""
        config = ScanConfig.model_validate_json(db_scan.config_json) if db_scan.config_json else ScanConfig()

        return Scan(
            id=UUID(db_scan.id),
            project_id=UUID(db_scan.project_id),
            status=ScanStatus(db_scan.status),
            config=config,
            started_at=db_scan.started_at,
            completed_at=db_scan.completed_at,
            error_message=db_scan.error_message,
            findings_count=db_scan.findings_count,
            critical_count=db_scan.critical_count,
            high_count=db_scan.high_count,
            medium_count=db_scan.medium_count,
            low_count=db_scan.low_count,
            info_count=db_scan.info_count,
            risk_score=db_scan.risk_score,
            duration_seconds=db_scan.duration_seconds,
            created_at=db_scan.created_at,
        )


class FindingRepository:
    """Repository for finding operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, finding: Finding, scan_id: str | UUID) -> DBFinding:
        """Create a new finding."""
        db_finding = DBFinding(
            id=str(finding.id),
            scan_id=str(scan_id),
            title=finding.title,
            severity=finding.severity.value,
            category=finding.category.value,
            confidence=finding.confidence.value,
            description=finding.description,
            evidence_json=finding.evidence.model_dump_json(),
            impact=finding.impact,
            attack_scenario=finding.attack_scenario,
            recommendation=finding.recommendation,
            patch_json=finding.patch.model_dump_json() if finding.patch else None,
            references_json=json.dumps(finding.references),
            risk_score=finding.risk_score,
            cwe_id=finding.cwe_id,
            cve_id=finding.cve_id,
            fingerprint=finding.fingerprint,
            suppressed=finding.suppressed,
            created_at=finding.created_at,
        )
        self.session.add(db_finding)
        await self.session.flush()
        return db_finding

    async def create_many(self, findings: list[Finding], scan_id: str | UUID) -> list[DBFinding]:
        """Create multiple findings."""
        db_findings = []
        for finding in findings:
            db_finding = await self.create(finding, scan_id)
            db_findings.append(db_finding)
        return db_findings

    async def get(self, finding_id: str | UUID) -> DBFinding | None:
        """Get a finding by ID."""
        result = await self.session.execute(
            select(DBFinding).where(DBFinding.id == str(finding_id))
        )
        return result.scalar_one_or_none()

    async def list_by_scan(
        self,
        scan_id: str | UUID,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[DBFinding]:
        """List findings for a scan with optional filters."""
        query = select(DBFinding).where(DBFinding.scan_id == str(scan_id))

        if severity:
            query = query.where(DBFinding.severity == severity)
        if category:
            query = query.where(DBFinding.category == category)

        query = query.order_by(DBFinding.risk_score.desc()).limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def count_by_scan(self, scan_id: str | UUID) -> dict[str, int]:
        """Count findings by severity for a scan."""
        result = await self.session.execute(
            select(DBFinding.severity, func.count(DBFinding.id))
            .where(DBFinding.scan_id == str(scan_id))
            .group_by(DBFinding.severity)
        )

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for severity, count in result.all():
            counts[severity] = count

        return counts

    async def suppress(self, finding_id: str | UUID, suppressed: bool = True) -> DBFinding | None:
        """Suppress or unsuppress a finding."""
        db_finding = await self.get(finding_id)
        if not db_finding:
            return None

        db_finding.suppressed = suppressed
        await self.session.flush()
        return db_finding

    async def delete_by_scan(self, scan_id: str | UUID) -> int:
        """Delete all findings for a scan."""
        result = await self.session.execute(
            delete(DBFinding).where(DBFinding.scan_id == str(scan_id))
        )
        await self.session.flush()
        return result.rowcount or 0

    def to_model(self, db_finding: DBFinding) -> Finding:
        """Convert DB model to domain model."""
        evidence = Evidence.model_validate_json(db_finding.evidence_json)
        patch = Patch.model_validate_json(db_finding.patch_json) if db_finding.patch_json else None
        references = json.loads(db_finding.references_json) if db_finding.references_json else []

        return Finding(
            id=UUID(db_finding.id),
            title=db_finding.title,
            severity=FindingSeverity(db_finding.severity),
            category=FindingCategory(db_finding.category),
            confidence=FindingConfidence(db_finding.confidence),
            description=db_finding.description,
            evidence=evidence,
            impact=db_finding.impact,
            attack_scenario=db_finding.attack_scenario,
            recommendation=db_finding.recommendation,
            patch=patch,
            references=references,
            risk_score=db_finding.risk_score,
            cwe_id=db_finding.cwe_id,
            cve_id=db_finding.cve_id,
            fingerprint=db_finding.fingerprint,
            suppressed=db_finding.suppressed,
            created_at=db_finding.created_at,
        )
