"""HTML report generator."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from packages.core.models import Finding, FindingCategory, ScanResult
from packages.reporter.base import BaseReporter, ReportFormat
from packages.reporter.localization import (
    get_localized_finding_content,
    localize_tool_message,
    normalize_language,
)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="{lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title} - {project_name}</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
            --success: #28a745;
            --bg: #f8f9fa;
            --card-bg: #ffffff;
            --text: #212529;
            --text-muted: #6c757d;
            --border: #dee2e6;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #2c3e50, #3498db);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}

        header .subtitle {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .summary-card h3 {{
            font-size: 0.9rem;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 8px;
        }}

        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
        }}

        .risk-score {{
            font-size: 3rem !important;
        }}

        .severity-counts {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}

        .severity-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
        }}

        .severity-badge.critical {{ background: var(--critical); color: white; }}
        .severity-badge.high {{ background: var(--high); color: white; }}
        .severity-badge.medium {{ background: var(--medium); color: #212529; }}
        .severity-badge.low {{ background: var(--low); color: white; }}
        .severity-badge.info {{ background: var(--info); color: white; }}

        .findings-section {{
            margin-bottom: 30px;
        }}

        .findings-section h2 {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border);
        }}

        .finding-card {{
            background: var(--card-bg);
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
        }}

        .finding-header:hover {{
            background: var(--bg);
        }}

        .finding-severity {{
            width: 4px;
            height: 40px;
            border-radius: 2px;
        }}

        .finding-severity.critical {{ background: var(--critical); }}
        .finding-severity.high {{ background: var(--high); }}
        .finding-severity.medium {{ background: var(--medium); }}
        .finding-severity.low {{ background: var(--low); }}
        .finding-severity.info {{ background: var(--info); }}

        .finding-title {{
            flex: 1;
        }}

        .finding-title h3 {{
            font-size: 1.1rem;
            margin-bottom: 4px;
        }}

        .finding-meta {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .finding-score {{
            text-align: right;
        }}

        .finding-score .score {{
            font-size: 1.5rem;
            font-weight: bold;
        }}

        .finding-body {{
            padding: 20px;
            display: none;
        }}

        .finding-body.open {{
            display: block;
        }}

        .finding-section {{
            margin-bottom: 20px;
        }}

        .finding-section h4 {{
            font-size: 0.9rem;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 8px;
        }}

        .finding-section p {{
            white-space: pre-wrap;
        }}

        .code-block {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            white-space: pre;
        }}

        .evidence-info {{
            background: var(--bg);
            padding: 15px;
            border-radius: 6px;
            margin-top: 10px;
        }}

        .evidence-info p {{
            margin-bottom: 5px;
            font-size: 0.9rem;
        }}

        .reference-list {{
            list-style: none;
        }}

        .reference-list li {{
            margin-bottom: 8px;
        }}

        .reference-list a {{
            color: #3498db;
            text-decoration: none;
        }}

        .reference-list a:hover {{
            text-decoration: underline;
        }}

        .diff-block {{
            background: #1e1e1e;
            padding: 15px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }}

        .diff-line {{
            display: block;
        }}

        .diff-add {{
            color: #98c379;
            background: rgba(152, 195, 121, 0.1);
        }}

        .diff-remove {{
            color: #e06c75;
            background: rgba(224, 108, 117, 0.1);
        }}

        footer {{
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            color: var(--text-muted);
        }}

        .no-findings .icon {{
            font-size: 4rem;
            margin-bottom: 20px;
        }}

        /* Tool Status Grid */
        .tool-status-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
        }}

        .tool-status-item {{
            padding: 10px 15px;
            background: var(--bg);
            border-radius: 6px;
            border-left: 4px solid var(--text-muted);
        }}
        
        .tool-status-item.success {{ border-left-color: var(--success); }}
        .tool-status-item.failed {{ border-left-color: var(--critical); }}

        .tool-name {{ font-weight: bold; margin-bottom: 4px; text-transform: capitalize; }}
        .tool-meta {{ font-size: 0.8rem; color: var(--text-muted); }}

        .section-nav {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 24px;
        }}

        .section-nav a {{
            color: var(--text);
            text-decoration: none;
            padding: 8px 12px;
            border-radius: 999px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            font-size: 0.9rem;
        }}

        .summary-list {{
            list-style: none;
            display: grid;
            gap: 8px;
        }}

        .summary-list li {{
            display: flex;
            justify-content: space-between;
            gap: 12px;
            font-size: 0.95rem;
        }}

        .finding-badges {{
            display: inline-flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
        }}

        .finding-badge {{
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.02em;
            text-transform: uppercase;
            border: 1px solid var(--border);
        }}

        .finding-badge.web {{
            background: rgba(23, 162, 184, 0.12);
            color: #0b7285;
        }}

        .finding-badge.privacy {{
            background: rgba(255, 193, 7, 0.14);
            color: #8a5a00;
        }}

        .finding-badge.article {{
            background: rgba(52, 152, 219, 0.1);
            color: #1b5f8a;
        }}

        .crossref-card {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
        }}

        .crossref-card h3 {{
            margin-bottom: 8px;
            font-size: 1.05rem;
        }}

        .crossref-card p, .crossref-card li {{
            white-space: pre-wrap;
        }}

        .crossref-card ul {{
            margin-left: 20px;
        }}

        .crossref-priority-box {{
            margin: 14px 0 18px;
            padding: 14px 16px;
            border-radius: 8px;
            border: 1px solid rgba(52, 152, 219, 0.2);
            background: rgba(52, 152, 219, 0.08);
        }}

        .crossref-priority-box ol {{
            margin: 8px 0 0 20px;
        }}

        .crossref-priority-box li {{
            margin-bottom: 6px;
        }}

        @media (max-width: 768px) {{
            header h1 {{
                font-size: 1.8rem;
            }}

            .summary-grid {{
                grid-template-columns: 1fr;
            }}

            .finding-header {{
                flex-wrap: wrap;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🔒 {report_title}</h1>
            <p class="subtitle">{project_name} • {generated_label} {generated_at}</p>
        </div>
    </header>

    <div class="container">
        <div id="summary" class="summary-grid">
            <div class="summary-card">
                <h3>{label_risk_score}</h3>
                <div class="value risk-score" style="color: {risk_color}">{risk_score}</div>
            </div>
            <div class="summary-card">
                <h3>{label_total_findings}</h3>
                <div class="value">{total_findings}</div>
            </div>
            <div class="summary-card">
                <h3>{label_summary_split}</h3>
                <ul class="summary-list">
                    {summary_split_html}
                </ul>
            </div>
            <div class="summary-card">
                <h3>{label_scanners_used}</h3>
                <ul class="summary-list">
                    {scanner_summary_html}
                </ul>
            </div>
            <div class="summary-card">
                <h3>{label_duration}</h3>
                <div class="value">{duration}</div>
            </div>
            <div class="summary-card">
                <h3>{label_by_severity}</h3>
                <div class="severity-counts">
                    {severity_badges}
                </div>
            </div>
            {architecture_summary_html}
            <div class="summary-card" style="grid-column: 1 / -1;">
                <h3>{label_tool_status}</h3>
                <div class="tool-status-grid">
                    {tool_status_html}
                </div>
            </div>
        </div>

        <div class="section-nav">
            <a href="#summary">{label_summary}</a>
            <a href="#security">{label_security_findings}</a>
            <a href="#gdpr">{label_privacy_findings}</a>
            <a href="#crossrefs">{label_cross_references}</a>
        </div>

        <div id="security" class="findings-section">
            <h2>{label_security_findings}</h2>
            {security_findings_html}
        </div>

        <div id="gdpr" class="findings-section">
            <h2>{label_privacy_findings}</h2>
            {privacy_findings_html}
        </div>

        <div id="crossrefs" class="findings-section">
            <h2>{label_cross_references}</h2>
            {cross_references_html}
        </div>
    </div>

    <footer>
        <p>{label_footer} • <a href="https://github.com/secscan/secscan">Documentation</a></p>
    </footer>

    <script>
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const body = header.nextElementSibling;
                body.classList.toggle('open');
            }});
        }});
    </script>
</body>
</html>"""

FINDING_TEMPLATE = """
<div class="finding-card">
    <div class="finding-header">
        <div class="finding-severity {severity}"></div>
        <div class="finding-title">
            <h3>{title}</h3>
            <div class="finding-meta">
                <span class="severity-badge {severity}">{severity_upper}</span>
                <span class="finding-badges">{category_badge}{article_badge}</span>
                • {tool} • {file_path}
            </div>
        </div>
        <div class="finding-score">
            <div class="score">{risk_score}</div>
            <div style="font-size: 0.8rem; color: var(--text-muted)">{label_risk}</div>
        </div>
    </div>
    <div class="finding-body">
        <div class="finding-section">
            <h4>{label_description}</h4>
            <p>{description}</p>
        </div>

        {evidence_section}

        <div class="finding-section">
            <h4>{label_impact}</h4>
            <p>{impact}</p>
        </div>

        {attack_section}

        <div class="finding-section">
            <h4>{label_recommendation}</h4>
            <p>{recommendation}</p>
        </div>

        {patch_section}

        {references_section}
    </div>
</div>
"""

TRANSLATIONS = {
    "en": {
        "report_title": "SecScan Report",
        "generated_label": "Generated",
        "label_risk_score": "Risk Score",
        "label_total_findings": "Total Findings",
        "label_duration": "Scan Duration",
        "label_by_severity": "By Severity",
        "label_tool_status": "Scanner Status",
        "label_findings": "Findings",
        "label_summary": "Summary",
        "label_summary_split": "Security vs GDPR",
        "label_scanners_used": "Scanners Used",
        "label_architecture": "Architecture",
        "label_note": "Note",
        "label_security_findings": "Security Findings",
        "label_privacy_findings": "GDPR Findings",
        "label_cross_references": "Cross-References",
        "label_security_count": "Security",
        "label_privacy_count": "GDPR",
        "label_combined_priority": "Combined priority",
        "label_relationship": "Relationship",
        "label_recommended_order": "Recommended order",
        "label_gdpr_article": "GDPR",
        "label_no_cross_references": "No overlapping security and GDPR findings were detected for the same page or endpoint.",
        "label_footer": "Generated by SecScan v0.1.0",
        "no_findings_title": "No findings in this section.",
        "no_findings_desc": "SecScan did not detect issues for this part of the report.",
        "label_description": "Description",
        "label_impact": "Impact",
        "label_recommendation": "Recommendation",
        "label_evidence": "Evidence",
        "label_attack": "Attack Scenario",
        "label_fix": "Suggested Fix",
        "label_refs": "References",
        "label_risk": "risk",
        "label_tool": "Tool",
        "file": "File",
        "lines": "Lines",
        "severity_critical": "critical",
        "severity_high": "high",
        "severity_medium": "medium",
        "severity_low": "low",
        "severity_info": "info",
        "no_issues": "0 issues",
        "na": "N/A",
        "no_details": "No details available",
    },
    "no": {
        "report_title": "SecScan Rapport",
        "generated_label": "Generert",
        "label_risk_score": "Risikoscore",
        "label_total_findings": "Totale Funn",
        "label_duration": "Tidsbruk",
        "label_by_severity": "Etter Alvorlighetsgrad",
        "label_tool_status": "Status for Skannere",
        "label_findings": "Sikkerhetsfunn",
        "label_summary": "Sammendrag",
        "label_summary_split": "Sikkerhet vs GDPR",
        "label_scanners_used": "Skannere brukt",
        "label_architecture": "Arkitektur",
        "label_note": "Merknad",
        "label_security_findings": "Sikkerhetsfunn",
        "label_privacy_findings": "GDPR-funn",
        "label_cross_references": "Kryssreferanser",
        "label_security_count": "Sikkerhet",
        "label_privacy_count": "GDPR",
        "label_combined_priority": "Kombinert prioritet",
        "label_relationship": "Sammenheng",
        "label_recommended_order": "Anbefalt rekkefølge",
        "label_gdpr_article": "GDPR",
        "label_no_cross_references": "Ingen overlapp mellom sikkerhetsfunn og GDPR-funn ble funnet for samme side eller endepunkt.",
        "label_footer": "Generert av SecScan v0.1.0",
        "no_findings_title": "Ingen funn i denne delen.",
        "no_findings_desc": "SecScan fant ingen saker for denne delen av rapporten.",
        "label_description": "Beskrivelse",
        "label_impact": "Konsekvens",
        "label_recommendation": "Anbefaling",
        "label_evidence": "Bevis",
        "label_attack": "Angrepsscenario",
        "label_fix": "Foreslått Løsning",
        "label_refs": "Referanser",
        "label_risk": "risiko",
        "label_tool": "Verktøy",
        "file": "Fil",
        "lines": "Linjer",
        "severity_critical": "kritisk",
        "severity_high": "høy",
        "severity_medium": "medium",
        "severity_low": "lav",
        "severity_info": "info",
        "no_issues": "0 funn",
        "na": "Ikke oppgitt",
        "no_details": "Ingen detaljer tilgjengelig",
    }
}

class HtmlReporter(BaseReporter):
    """Generate HTML format reports."""

    format = ReportFormat.HTML

    def generate(self, result: ScanResult) -> str:
        """Generate HTML report."""
        scan = result.scan
        findings = result.findings
        
        # Get language
        lang = normalize_language(self.config.get("language", "en"))
        t = TRANSLATIONS[lang]

        # Generate severity badges
        severity_badges = self._generate_severity_badges(scan, t)

        # Generate tool status HTML
        tool_status_html = self._generate_tool_status_html(result.adapter_status, t, lang)

        security_findings = self._sort_findings(
            [finding for finding in findings if finding.category != FindingCategory.PRIVACY]
        )
        privacy_findings = self._sort_findings(
            [finding for finding in findings if finding.category == FindingCategory.PRIVACY]
        )

        security_findings_html = self._generate_findings_section_html(security_findings, t, lang)
        privacy_findings_html = self._generate_findings_section_html(privacy_findings, t, lang)
        cross_references_html = self._generate_cross_references_html(security_findings, privacy_findings, t, lang)
        summary_split_html = self._generate_summary_split_html(security_findings, privacy_findings, t)
        scanner_summary_html = self._generate_scanner_summary_html(result.adapter_status, t)
        architecture_summary_html = self._generate_architecture_summary_html(findings, t, lang)

        # Calculate risk color
        risk_score = round(scan.risk_score, 1)
        if risk_score >= 70:
            risk_color = "var(--critical)"
        elif risk_score >= 40:
            risk_color = "var(--high)"
        elif risk_score >= 20:
            risk_color = "var(--medium)"
        else:
            risk_color = "var(--low)"

        # Format duration
        duration = "N/A"
        if scan.duration_seconds is not None:
            if scan.duration_seconds < 0.1:
                duration = "< 0.1s"
            elif scan.duration_seconds < 60:
                duration = f"{scan.duration_seconds:.1f}s"
            else:
                minutes = int(scan.duration_seconds // 60)
                seconds = int(scan.duration_seconds % 60)
                duration = f"{minutes}m {seconds}s"

        report_title = self.config.get("report_title", t["report_title"])
        template_labels = {key: value for key, value in t.items() if key != "report_title"}

        return HTML_TEMPLATE.format(
            lang=lang,
            report_title=report_title,
            project_name=self.config.get("project_name", "Security Scan"),
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            risk_score=risk_score,
            risk_color=risk_color,
            total_findings=scan.findings_count,
            duration=duration,
            severity_badges=severity_badges,
            summary_split_html=summary_split_html,
            scanner_summary_html=scanner_summary_html,
            architecture_summary_html=architecture_summary_html,
            security_findings_html=security_findings_html,
            privacy_findings_html=privacy_findings_html,
            cross_references_html=cross_references_html,
            tool_status_html=tool_status_html,
            **template_labels  # Unpack translations
        )

    def _sort_findings(self, findings: list[Finding]) -> list[Finding]:
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        return sorted(
            findings,
            key=lambda finding: (
                severity_order.get(getattr(finding.severity, "value", str(finding.severity)), 5),
                -finding.risk_score,
                getattr(finding.title, "lower", lambda: str(finding.title).lower())(),
            ),
        )

    def _generate_findings_section_html(self, findings: list[Finding], t: dict[str, str], lang: str) -> str:
        if findings:
            return "\n".join(self._generate_finding_html(finding, t, lang) for finding in findings)
        return f"""
            <div class="no-findings">
                <div class="icon">✅</div>
                <h3>{t['no_findings_title']}</h3>
                <p>{t['no_findings_desc']}</p>
            </div>
        """

    def _generate_summary_split_html(
        self,
        security_findings: list[Finding],
        privacy_findings: list[Finding],
        t: dict[str, str],
    ) -> str:
        return "".join(
            [
                f"<li><span>{t['label_security_count']}</span><strong>{len(security_findings)}</strong></li>",
                f"<li><span>{t['label_privacy_count']}</span><strong>{len(privacy_findings)}</strong></li>",
            ]
        )

    def _generate_scanner_summary_html(self, adapter_status: dict[str, Any] | None, t: dict[str, str]) -> str:
        if not adapter_status:
            return f"<li><span>{t['label_tool_status']}</span><strong>{t['no_details']}</strong></li>"
        items = []
        for name, status in adapter_status.items():
            state = "ok" if status.get("success") else "failed"
            items.append(f"<li><span>{self._escape_html(name)}</span><strong>{state}</strong></li>")
        return "".join(items)

    def _generate_architecture_summary_html(self, findings: list[Finding], t: dict[str, str], lang: str) -> str:
        if not any("byok" in finding.title.lower() for finding in findings):
            return ""

        architecture_label = "BYOK (Bring Your Own Key)"
        architecture_note = (
            "Ingen server-side brukerdata oppdaget"
            if lang == "no"
            else "No server-side user data detected"
        )
        return f"""
            <div class="summary-card">
                <h3>{t['label_architecture']}</h3>
                <div class="value">{self._escape_html(architecture_label)}</div>
                <ul class="summary-list">
                    <li><span>{t['label_note']}</span><strong>{self._escape_html(architecture_note)}</strong></li>
                </ul>
            </div>
        """

    def _generate_cross_references_html(
        self,
        security_findings: list[Finding],
        privacy_findings: list[Finding],
        t: dict[str, str],
        lang: str,
    ) -> str:
        security_by_path: dict[str, list[Finding]] = {}
        privacy_by_path: dict[str, list[Finding]] = {}

        for finding in security_findings:
            path = finding.evidence.file_path or ""
            if path:
                security_by_path.setdefault(path, []).append(finding)
        for finding in privacy_findings:
            path = finding.evidence.file_path or ""
            if path:
                privacy_by_path.setdefault(path, []).append(finding)

        overlapping_paths = sorted(set(security_by_path) & set(privacy_by_path))
        if not overlapping_paths:
            return f'<div class="no-findings"><p>{t["label_no_cross_references"]}</p></div>'

        cards: list[str] = []
        for path in overlapping_paths:
            insights = self._generate_cross_reference_insights(
                security_by_path[path],
                privacy_by_path[path],
                lang,
            )
            recommended_order = self._generate_cross_reference_order(
                security_by_path[path],
                privacy_by_path[path],
                lang,
            )
            insights_html = ""
            if insights:
                insights_html = (
                    f"<p><strong>{t['label_relationship']}:</strong></p>"
                    f"<ul>{''.join(f'<li>{self._escape_html(insight)}</li>' for insight in insights)}</ul>"
                )
            recommended_order_html = ""
            if recommended_order:
                recommended_order_html = (
                    f"<div class=\"crossref-priority-box\">"
                    f"<strong>{t['label_recommended_order']}:</strong>"
                    f"<ol>{''.join(f'<li>{self._escape_html(step)}</li>' for step in recommended_order)}</ol>"
                    f"</div>"
                )
            security_titles = "".join(
                f"<li>{self._escape_html(get_localized_finding_content(finding, lang)['title'])} ({round(finding.risk_score, 1)})</li>"
                for finding in security_by_path[path]
            )
            privacy_titles = "".join(
                f"<li>{self._escape_html(get_localized_finding_content(finding, lang)['title'])} ({round(finding.risk_score, 1)})</li>"
                for finding in privacy_by_path[path]
            )
            combined_priority = max(
                max(finding.risk_score for finding in security_by_path[path]),
                max(finding.risk_score for finding in privacy_by_path[path]),
            )
            cards.append(
                f"""
                <div class=\"crossref-card\">
                    <h3>{self._escape_html(path)}</h3>
                    <p><strong>{t['label_combined_priority']}:</strong> {combined_priority:.1f}</p>
                    {insights_html}
                    {recommended_order_html}
                    <p><strong>{t['label_security_findings']}:</strong></p>
                    <ul>{security_titles}</ul>
                    <p><strong>{t['label_privacy_findings']}:</strong></p>
                    <ul>{privacy_titles}</ul>
                </div>
                """
            )
        return "\n".join(cards)

    def _generate_cross_reference_insights(
        self,
        security_findings: list[Finding],
        privacy_findings: list[Finding],
        lang: str,
    ) -> list[str]:
        security_titles = {finding.title.lower() for finding in security_findings}
        privacy_titles = {finding.title.lower() for finding in privacy_findings}
        insights: list[str] = []

        has_csp = any("content security policy" in title and "header not set" in title for title in security_titles)
        has_localstorage_key = any("api key stored in localstorage" in title for title in security_titles)
        has_byok = any("byok" in title for title in privacy_titles)
        has_privacy_contact = any("privacy contact information missing" in title for title in privacy_titles)

        if has_csp and has_localstorage_key:
            insights.append(
                "Content-Security-Policy mangler + API-nøkkel i localStorage gir forhøyet XSS-risiko. Fiks CSP først for å redusere sannsynligheten for nøkkeltyveri, og reduser deretter lagringstiden eller flytt nøkkelen ut av localStorage."
                if lang == "no"
                else "Missing Content Security Policy + API key in localStorage creates an elevated XSS path. Fix CSP first to reduce key theft risk, then reduce browser persistence or move the key out of localStorage."
            )

        if has_byok and has_privacy_contact:
            insights.append(
                "BYOK reduserer klassiske kontofunn, men personvernkontakt er fortsatt relevant fordi driftslogger, hosting og tredjeparter fortsatt kan behandle IP-adresser og diagnostiske metadata."
                if lang == "no"
                else "BYOK reduces classic account findings, but a privacy contact still matters because hosting, logs, and third parties may process IP addresses and diagnostic metadata."
            )

        if not insights:
            insights.append(
                "Denne siden har både sikkerhets- og GDPR-funn. Prioriter kontroller som reduserer eksponering av nøkler, metadata eller tredjepartsdeling først."
                if lang == "no"
                else "This page has both security and GDPR findings. Prioritize controls that reduce exposure of keys, metadata, or third-party sharing first."
            )

        return insights

    def _generate_cross_reference_order(
        self,
        security_findings: list[Finding],
        privacy_findings: list[Finding],
        lang: str,
    ) -> list[str]:
        security_titles = {finding.title.lower() for finding in security_findings}
        privacy_titles = {finding.title.lower() for finding in privacy_findings}

        has_csp = any("content security policy" in title and "header not set" in title for title in security_titles)
        has_localstorage_key = any("api key stored in localstorage" in title for title in security_titles)
        has_privacy_contact = any("privacy contact information missing" in title for title in privacy_titles)

        if has_csp and has_localstorage_key and has_privacy_contact:
            if lang == "no":
                return [
                    "Sett en streng Content-Security-Policy for å redusere sannsynligheten for at XSS kan lese nøkkelen.",
                    "Reduser eksponeringen til API-nøkkelen ved å forkorte levetid eller flytte den ut av localStorage.",
                    "Publiser personvernkontakt og forklar hvilke logger, driftsleverandører eller tredjeparter som fortsatt kan behandle metadata.",
                ]
            return [
                "Set a strict Content Security Policy first to reduce the chance that XSS can read the key.",
                "Reduce API key exposure next by shortening lifetime or moving it out of localStorage.",
                "Publish a privacy contact and explain which logs, operators, or third parties may still process metadata.",
            ]

        if has_csp and has_localstorage_key:
            if lang == "no":
                return [
                    "Fiks CSP først for å redusere XSS-risikoen rundt nøkkelen i nettleseren.",
                    "Reduser deretter lagringstiden eller flytt nøkkelen ut av localStorage.",
                ]
            return [
                "Fix CSP first to reduce XSS risk around the browser-stored key.",
                "Then reduce persistence or move the key out of localStorage.",
            ]

        if has_privacy_contact:
            if lang == "no":
                return [
                    "Dokumenter hvilke metadata og tredjeparter som fortsatt er relevante i denne BYOK-flyten.",
                    "Publiser deretter en tydelig personvernkontakt for forespørsler om logger, metadata og overføringer.",
                ]
            return [
                "Document which metadata and third parties still matter in this BYOK flow.",
                "Then publish a clear privacy contact for log, metadata, and transfer questions.",
            ]

        return []

    def _gdpr_article(self, finding: Finding, lang: str) -> str | None:
        title = finding.title.lower()
        if "privacy policy not found" in title:
            return "Art. 13"
        if "brukerrettigheter" in title or "missing controls" in (finding.evidence.snippet or "").lower():
            return "Art. 17/20"
        if "contact information missing" in title:
            return "Art. 13(1)(a)"
        if "data collection without consent" in title or "tracking and analytics" in title:
            return "Art. 6/7"
        if "third-party data transfers" in title:
            return "Art. 44-49"
        if "browser storage" in title or "frontend content" in title or "query parameters" in title:
            return "Art. 5/32"
        if "dpia" in title:
            return "Art. 35"
        if "retention" in title:
            return "Art. 5(1)(e)"
        if "terms and conditions" in title:
            return "Ingen direkte artikkel" if lang == "no" else "No direct article"
        return None

    def _generate_severity_badges(self, scan: Any, t: dict[str, str]) -> str:
        """Generate severity count badges."""
        badges = []
        counts = [
            ("critical", scan.critical_count),
            ("high", scan.high_count),
            ("medium", scan.medium_count),
            ("low", scan.low_count),
            ("info", scan.info_count),
        ]

        for severity, count in counts:
            if count > 0:
                label = t.get(f"severity_{severity}", severity)
                badges.append(
                    f'<span class="severity-badge {severity}">{count} {label}</span>'
                )

        return " ".join(badges) if badges else f'<span class="severity-badge info">{t["no_issues"]}</span>'

    def _generate_tool_status_html(self, adapter_status: dict[str, Any] | None, t: dict[str, str], lang: str) -> str:
        """Generate HTML for tool status."""
        if not adapter_status:
            return f'<div class="tool-status-item"><span class="tool-meta">{t["no_details"]}</span></div>'
            
        html = []
        for name, status in adapter_status.items():
            success = status.get("success", False)
            css_class = "success" if success else "failed"
            duration = status.get("duration", 0)
            msg = status.get("message", "")
            msg = localize_tool_message(msg, lang)
            if duration < 0.1:
                dur_str = "< 0.1s"
            else:
                dur_str = f"{duration:.1f}s"
                
            details = f"{dur_str}"
            if msg:
                details += f" • {msg}"
            
            html.append(f"""
            <div class="tool-status-item {css_class}">
                <div class="tool-name">{name}</div>
                <div class="tool-meta">{details}</div>
            </div>
            """)
        return "\n".join(html)

    def _generate_finding_html(self, finding: Finding, t: dict[str, str], lang: str) -> str:
        """Generate HTML for a single finding."""
        severity = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
        category = finding.category.value if hasattr(finding.category, "value") else finding.category

        localized = get_localized_finding_content(finding, lang)
        title = localized["title"]
        description = localized["description"]
        impact = localized["impact"]
        recommendation = localized["recommendation"]
        attack_scenario = localized["attack_scenario"]
        category_badge = f'<span class="finding-badge {category}">{self._escape_html(category)}</span>'
        article = self._gdpr_article(finding, lang) if category == FindingCategory.PRIVACY.value else None
        article_badge = (
            f'<span class="finding-badge article">{t["label_gdpr_article"]} {self._escape_html(article)}</span>'
            if article
            else ""
        )

        # Evidence section
        evidence_section = ""
        if finding.evidence.snippet:
            evidence_section = f"""
            <div class="finding-section">
                <h4>{t['label_evidence']}</h4>
                <div class="code-block">{self._escape_html(finding.evidence.snippet)}</div>
                <div class="evidence-info">
                    <p><strong>{t['label_tool']}:</strong> {finding.evidence.tool}</p>
                    <p><strong>{t['file']}:</strong> {finding.evidence.file_path or t['na']}</p>
                    <p><strong>{t['lines']}:</strong> {finding.evidence.line_start or t['na']} - {finding.evidence.line_end or t['na']}</p>
                </div>
            </div>
            """

        # Attack scenario section
        attack_section = ""
        if attack_scenario:
            attack_section = f"""
            <div class="finding-section">
                <h4>{t['label_attack']}</h4>
                <p>{self._escape_html(attack_scenario)}</p>
            </div>
            """

        # Patch section
        patch_section = ""
        if finding.patch and finding.patch.diff:
            diff_html = self._format_diff(finding.patch.diff)
            patch_section = f"""
            <div class="finding-section">
                <h4>{t['label_fix']}</h4>
                <p>{self._escape_html(finding.patch.description or '')}</p>
                <div class="diff-block">{diff_html}</div>
            </div>
            """

        # References section
        references_section = ""
        if finding.references:
            refs_html = "\n".join(
                f'<li><a href="{ref}" target="_blank">{ref}</a></li>'
                for ref in finding.references
            )
            references_section = f"""
            <div class="finding-section">
                <h4>{t['label_refs']}</h4>
                <ul class="reference-list">{refs_html}</ul>
            </div>
            """

        return FINDING_TEMPLATE.format(
            title=self._escape_html(title),
            severity=severity.lower(),
            severity_upper=severity.upper(),
            category=category,
            tool=finding.evidence.tool,
            file_path=finding.evidence.file_path or t["na"],
            risk_score=round(finding.risk_score, 1),
            description=self._escape_html(description),
            impact=self._escape_html(impact),
            recommendation=self._escape_html(recommendation),
            category_badge=category_badge,
            article_badge=article_badge,
            evidence_section=evidence_section,
            attack_section=attack_section,
            patch_section=patch_section,
            references_section=references_section,
            **t  # Unpack translations for labels
        )

    def _escape_html(self, text: str | None) -> str:
        """Escape HTML special characters."""
        if text is None:
            return ""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

    def _format_diff(self, diff: str) -> str:
        """Format diff with syntax highlighting."""
        lines = []
        for line in diff.split("\n"):
            escaped = self._escape_html(line)
            if line.startswith("+") and not line.startswith("+++"):
                lines.append(f'<span class="diff-line diff-add">{escaped}</span>')
            elif line.startswith("-") and not line.startswith("---"):
                lines.append(f'<span class="diff-line diff-remove">{escaped}</span>')
            else:
                lines.append(f'<span class="diff-line">{escaped}</span>')
        return "\n".join(lines)
