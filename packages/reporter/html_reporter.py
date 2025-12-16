"""HTML report generator."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from packages.core.models import Finding, ScanResult
from packages.reporter.base import BaseReporter, ReportFormat

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecScan Report - {project_name}</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
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
            <h1>🔒 SecScan Report</h1>
            <p class="subtitle">{project_name} • Generated {generated_at}</p>
        </div>
    </header>

    <div class="container">
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Risk Score</h3>
                <div class="value risk-score" style="color: {risk_color}">{risk_score}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{total_findings}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="value">{duration}</div>
            </div>
            <div class="summary-card">
                <h3>By Severity</h3>
                <div class="severity-counts">
                    {severity_badges}
                </div>
            </div>
        </div>

        <div class="findings-section">
            <h2>Findings</h2>
            {findings_html}
        </div>
    </div>

    <footer>
        <p>Generated by SecScan v0.1.0 • <a href="https://github.com/secscan/secscan">Documentation</a></p>
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
                • {category} • {tool} • {file_path}
            </div>
        </div>
        <div class="finding-score">
            <div class="score">{risk_score}</div>
            <div style="font-size: 0.8rem; color: var(--text-muted)">risk</div>
        </div>
    </div>
    <div class="finding-body">
        <div class="finding-section">
            <h4>Description</h4>
            <p>{description}</p>
        </div>

        {evidence_section}

        <div class="finding-section">
            <h4>Impact</h4>
            <p>{impact}</p>
        </div>

        {attack_section}

        <div class="finding-section">
            <h4>Recommendation</h4>
            <p>{recommendation}</p>
        </div>

        {patch_section}

        {references_section}
    </div>
</div>
"""


class HtmlReporter(BaseReporter):
    """Generate HTML format reports."""

    format = ReportFormat.HTML

    def generate(self, result: ScanResult) -> str:
        """Generate HTML report."""
        scan = result.scan
        findings = result.findings

        # Generate severity badges
        severity_badges = self._generate_severity_badges(scan)

        # Generate findings HTML
        if findings:
            findings_html = "\n".join(
                self._generate_finding_html(f) for f in findings
            )
        else:
            findings_html = """
            <div class="no-findings">
                <div class="icon">✅</div>
                <h3>No security issues found!</h3>
                <p>Great job! Your code passed all security checks.</p>
            </div>
            """

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
        if scan.duration_seconds:
            if scan.duration_seconds < 60:
                duration = f"{scan.duration_seconds:.1f}s"
            else:
                minutes = int(scan.duration_seconds // 60)
                seconds = int(scan.duration_seconds % 60)
                duration = f"{minutes}m {seconds}s"

        return HTML_TEMPLATE.format(
            project_name=self.config.get("project_name", "Security Scan"),
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            risk_score=risk_score,
            risk_color=risk_color,
            total_findings=scan.findings_count,
            duration=duration,
            severity_badges=severity_badges,
            findings_html=findings_html,
        )

    def _generate_severity_badges(self, scan: Any) -> str:
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
                badges.append(
                    f'<span class="severity-badge {severity}">{count} {severity}</span>'
                )

        return " ".join(badges) if badges else '<span class="severity-badge info">0 issues</span>'

    def _generate_finding_html(self, finding: Finding) -> str:
        """Generate HTML for a single finding."""
        severity = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
        category = finding.category.value if hasattr(finding.category, "value") else finding.category

        # Evidence section
        evidence_section = ""
        if finding.evidence.snippet:
            evidence_section = f"""
            <div class="finding-section">
                <h4>Evidence</h4>
                <div class="code-block">{self._escape_html(finding.evidence.snippet)}</div>
                <div class="evidence-info">
                    <p><strong>Tool:</strong> {finding.evidence.tool}</p>
                    <p><strong>File:</strong> {finding.evidence.file_path or 'N/A'}</p>
                    <p><strong>Lines:</strong> {finding.evidence.line_start or 'N/A'} - {finding.evidence.line_end or 'N/A'}</p>
                </div>
            </div>
            """

        # Attack scenario section
        attack_section = ""
        if finding.attack_scenario:
            attack_section = f"""
            <div class="finding-section">
                <h4>Attack Scenario</h4>
                <p>{self._escape_html(finding.attack_scenario)}</p>
            </div>
            """

        # Patch section
        patch_section = ""
        if finding.patch and finding.patch.diff:
            diff_html = self._format_diff(finding.patch.diff)
            patch_section = f"""
            <div class="finding-section">
                <h4>Suggested Fix</h4>
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
                <h4>References</h4>
                <ul class="reference-list">{refs_html}</ul>
            </div>
            """

        return FINDING_TEMPLATE.format(
            title=self._escape_html(finding.title),
            severity=severity.lower(),
            severity_upper=severity.upper(),
            category=category,
            tool=finding.evidence.tool,
            file_path=finding.evidence.file_path or "N/A",
            risk_score=round(finding.risk_score, 1),
            description=self._escape_html(finding.description),
            impact=self._escape_html(finding.impact),
            recommendation=self._escape_html(finding.recommendation),
            evidence_section=evidence_section,
            attack_section=attack_section,
            patch_section=patch_section,
            references_section=references_section,
        )

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
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
