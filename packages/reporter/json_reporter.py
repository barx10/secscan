"""JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from packages.core.models import ScanResult
from packages.reporter.base import BaseReporter, ReportFormat
from packages.reporter.localization import get_localized_finding_content, normalize_language


class CustomEncoder(json.JSONEncoder):
    """Custom JSON encoder for special types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if hasattr(obj, "value"):
            return obj.value
        return super().default(obj)


class JsonReporter(BaseReporter):
    """Generate JSON format reports."""

    format = ReportFormat.JSON

    def generate(self, result: ScanResult) -> str:
        """Generate JSON report."""
        lang = normalize_language(self.config.get("language", "en"))
        summary = dict(result.summary or {})
        if any("byok" in finding.title.lower() for finding in result.findings):
            summary["architecture"] = {
                "type": "byok",
                "label": "BYOK (Bring Your Own Key)",
                "note": (
                    "Ingen server-side brukerdata oppdaget"
                    if lang == "no"
                    else "No server-side user data detected"
                ),
            }
        report = {
            "version": "1.0",
            "language": lang,
            "report_title": self.config.get("report_title", "SecScan Report"),
            "generated_at": datetime.utcnow().isoformat(),
            "scan": self._serialize_scan(result.scan),
            "summary": summary,
            "findings": [self._serialize_finding(f, lang) for f in result.findings],
        }

        indent = self.config.get("indent", 2)
        return json.dumps(report, cls=CustomEncoder, indent=indent, ensure_ascii=False)

    def _serialize_scan(self, scan: Any) -> dict[str, Any]:
        """Serialize scan object."""
        return {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "status": scan.status.value if hasattr(scan.status, "value") else scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "findings_count": scan.findings_count,
            "risk_score": round(scan.risk_score, 2),
            "severity_counts": {
                "critical": scan.critical_count,
                "high": scan.high_count,
                "medium": scan.medium_count,
                "low": scan.low_count,
                "info": scan.info_count,
            },
        }

    def _serialize_finding(self, finding: Any, lang: str) -> dict[str, Any]:
        """Serialize finding object."""
        localized = get_localized_finding_content(finding, lang)
        return {
            "id": str(finding.id),
            "title": localized["title"],
            "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
            "category": finding.category.value if hasattr(finding.category, "value") else finding.category,
            "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else finding.confidence,
            "risk_score": round(finding.risk_score, 2),
            "description": localized["description"],
            "evidence": {
                "tool": finding.evidence.tool,
                "file_path": finding.evidence.file_path,
                "line_start": finding.evidence.line_start,
                "line_end": finding.evidence.line_end,
                "snippet": finding.evidence.snippet,
            },
            "impact": localized["impact"],
            "attack_scenario": localized["attack_scenario"],
            "recommendation": localized["recommendation"],
            "patch": {
                "file_path": finding.patch.file_path,
                "diff": finding.patch.diff,
                "description": finding.patch.description,
            } if finding.patch else None,
            "references": finding.references,
            "cwe_id": finding.cwe_id,
            "cve_id": finding.cve_id,
            "fingerprint": finding.fingerprint,
            "suppressed": finding.suppressed,
        }
