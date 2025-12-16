"""SecScan CLI - Security vulnerability scanner."""

from __future__ import annotations

import asyncio
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from packages.core.models import FindingSeverity, ScanConfig, ScanType

app = typer.Typer(
    name="secscan",
    help="Security vulnerability scanner for applications and websites",
    add_completion=False,
)

console = Console()


class OutputFormat(str, Enum):
    """Output format options."""

    JSON = "json"
    HTML = "html"
    TABLE = "table"


class SeverityOption(str, Enum):
    """Severity level options."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def print_banner() -> None:
    """Print the SecScan banner."""
    banner = """
[bold blue]╔═══════════════════════════════════════════╗
║           SecScan v0.1.0                  ║
║     Security Vulnerability Scanner        ║
╚═══════════════════════════════════════════╝[/bold blue]
"""
    console.print(banner)


def severity_to_color(severity: str) -> str:
    """Get Rich color for severity."""
    colors = {
        "critical": "red bold",
        "high": "orange1",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")


def print_summary(result: any) -> None:
    """Print scan summary."""
    scan = result.scan

    # Summary table
    table = Table(title="Scan Summary", show_header=False, box=None)
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Status", f"[green]{scan.status.value}[/green]")
    table.add_row("Total Findings", str(scan.findings_count))
    table.add_row(
        "Risk Score",
        f"[{severity_to_color('critical' if scan.risk_score >= 70 else 'medium')}]{scan.risk_score:.1f}/100[/]",
    )

    if scan.duration_seconds:
        table.add_row("Duration", f"{scan.duration_seconds:.1f}s")

    console.print(table)
    console.print()

    # Severity breakdown
    if scan.findings_count > 0:
        severity_table = Table(title="Findings by Severity")
        severity_table.add_column("Severity")
        severity_table.add_column("Count", justify="right")

        if scan.critical_count:
            severity_table.add_row(
                f"[{severity_to_color('critical')}]Critical[/]",
                str(scan.critical_count),
            )
        if scan.high_count:
            severity_table.add_row(
                f"[{severity_to_color('high')}]High[/]",
                str(scan.high_count),
            )
        if scan.medium_count:
            severity_table.add_row(
                f"[{severity_to_color('medium')}]Medium[/]",
                str(scan.medium_count),
            )
        if scan.low_count:
            severity_table.add_row(
                f"[{severity_to_color('low')}]Low[/]",
                str(scan.low_count),
            )
        if scan.info_count:
            severity_table.add_row(
                f"[{severity_to_color('info')}]Info[/]",
                str(scan.info_count),
            )

        console.print(severity_table)
        console.print()


def print_findings(findings: list, max_items: int = 10) -> None:
    """Print top findings."""
    if not findings:
        console.print("[green]No security issues found![/green]")
        return

    console.print(f"\n[bold]Top {min(len(findings), max_items)} Findings:[/bold]\n")

    for i, finding in enumerate(findings[:max_items], 1):
        severity = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
        color = severity_to_color(severity)

        panel_content = f"""[bold]{finding.title}[/bold]

[dim]Category:[/dim] {finding.category.value if hasattr(finding.category, 'value') else finding.category}
[dim]File:[/dim] {finding.evidence.file_path or 'N/A'}
[dim]Tool:[/dim] {finding.evidence.tool}
[dim]Risk Score:[/dim] {finding.risk_score:.1f}

{finding.description[:200]}{'...' if len(finding.description) > 200 else ''}

[bold]Recommendation:[/bold]
{finding.recommendation[:300]}{'...' if len(finding.recommendation) > 300 else ''}
"""

        console.print(
            Panel(
                panel_content,
                title=f"[{color}][{severity.upper()}][/] Finding #{i}",
                border_style=color,
            )
        )


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(help="Path to repository/zip or URL to scan"),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option("-o", "--output", help="Output file path"),
    ] = None,
    format: Annotated[
        OutputFormat,
        typer.Option("-f", "--format", help="Output format"),
    ] = OutputFormat.TABLE,
    scan_types: Annotated[
        Optional[list[str]],
        typer.Option("-t", "--type", help="Scan types (secrets, deps, sast, config, web, full)"),
    ] = None,
    severity: Annotated[
        SeverityOption,
        typer.Option("-s", "--severity", help="Minimum severity to report"),
    ] = SeverityOption.INFO,
    fail_on: Annotated[
        Optional[SeverityOption],
        typer.Option("--fail-on", help="Fail with exit code 1 if findings at or above this severity"),
    ] = SeverityOption.HIGH,
    no_banner: Annotated[
        bool,
        typer.Option("--no-banner", help="Don't show banner"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("-q", "--quiet", help="Minimal output"),
    ] = False,
) -> None:
    """
    Scan a repository, zip file, or URL for security vulnerabilities.

    Examples:
        secscan scan ./my-project
        secscan scan ./source.zip -o report.html -f html
        secscan scan https://example.com -t web
        secscan scan . --fail-on critical
    """
    if not no_banner and not quiet:
        print_banner()

    # Determine target type
    target_path = Path(target)
    is_url = target.startswith("http://") or target.startswith("https://")
    is_zip = target_path.suffix.lower() == ".zip"

    # Build scan config
    config = ScanConfig(
        severity_threshold=FindingSeverity(severity.value),
        fail_on_severity=FindingSeverity(fail_on.value) if fail_on else None,
    )

    # Set scan types
    if scan_types:
        config.scan_types = [ScanType(t) for t in scan_types]
    elif is_url:
        config.scan_types = [ScanType.WEB]
    else:
        config.scan_types = [ScanType.FULL]

    # Run scan
    async def run_scan():
        from packages.core.pipeline import ScanPipeline

        pipeline = ScanPipeline()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            def progress_callback(message: str, pct: float) -> None:
                progress.update(task, description=message)

            pipeline.set_progress_callback(progress_callback)

            if is_url:
                result = await pipeline.scan_url(target, config)
            elif is_zip:
                result = await pipeline.scan_zip(target_path, config)
            else:
                result = await pipeline.scan_repo(target_path, config)

            progress.update(task, description="Complete!")

        return result, pipeline.get_exit_code(result.scan, config)

    result, exit_code = asyncio.run(run_scan())

    # Output results
    if format == OutputFormat.JSON:
        from packages.reporter import JsonReporter

        reporter = JsonReporter()
        report = reporter.generate(result)

        if output:
            output.write_text(report)
            if not quiet:
                console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(report)

    elif format == OutputFormat.HTML:
        from packages.reporter import HtmlReporter

        reporter = HtmlReporter({"project_name": target_path.name if not is_url else target})
        report = reporter.generate(result)

        if output:
            output.write_text(report)
            if not quiet:
                console.print(f"[green]Report saved to {output}[/green]")
        else:
            # Default to report.html if no output specified
            default_output = Path("secscan-report.html")
            default_output.write_text(report)
            if not quiet:
                console.print(f"[green]Report saved to {default_output}[/green]")

    else:  # TABLE format
        if not quiet:
            print_summary(result)
            print_findings(result.findings)

            if output:
                # Also save JSON if output specified
                from packages.reporter import JsonReporter

                reporter = JsonReporter()
                output.write_text(reporter.generate(result))
                console.print(f"\n[green]Report saved to {output}[/green]")

    # Exit with appropriate code
    if exit_code != 0:
        if not quiet:
            console.print(f"\n[red]Scan found issues meeting failure threshold. Exit code: {exit_code}[/red]")
    sys.exit(exit_code)


@app.command()
def check_tools() -> None:
    """Check which scanner tools are installed and available."""
    print_banner()

    async def check():
        from packages.adapters.registry import get_registry

        registry = get_registry()
        status = await registry.check_availability()

        table = Table(title="Scanner Tools Status")
        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Version")
        table.add_column("Path")

        for name, info in status.items():
            if info["available"]:
                status_str = "[green]✓ Available[/green]"
            else:
                status_str = "[red]✗ Not Found[/red]"

            table.add_row(
                name,
                status_str,
                info.get("version") or "-",
                info.get("tool_path") or "-",
            )

        console.print(table)

        # Print installation instructions for missing tools
        missing = [name for name, info in status.items() if not info["available"]]
        if missing:
            console.print("\n[yellow]Missing tools can be installed with:[/yellow]")
            instructions = {
                "gitleaks": "brew install gitleaks  # or download from GitHub releases",
                "semgrep": "pip install semgrep",
                "trivy": "brew install trivy  # or download from GitHub releases",
                "osv-scanner": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
                "zap": "docker pull ghcr.io/zaproxy/zaproxy:stable",
                "syft": "brew install syft  # or download from GitHub releases",
            }
            for tool in missing:
                if tool in instructions:
                    console.print(f"  [dim]{tool}:[/dim] {instructions[tool]}")

    asyncio.run(check())


@app.command()
def version() -> None:
    """Show version information."""
    console.print("[bold]SecScan[/bold] version [cyan]0.1.0[/cyan]")


@app.command()
def init(
    path: Annotated[
        Path,
        typer.Argument(help="Path to initialize"),
    ] = Path("."),
) -> None:
    """Initialize SecScan configuration in a project."""
    config_path = path / ".secscan.yaml"

    if config_path.exists():
        console.print(f"[yellow]Configuration already exists at {config_path}[/yellow]")
        return

    default_config = """# SecScan Configuration
# See documentation for all options

# Scan settings
scan:
  types:
    - secrets
    - deps
    - sast
    - config

  # Severity threshold for reporting
  severity_threshold: info

  # Fail CI if findings at or above this severity
  fail_on_severity: high

  # Patterns to exclude
  exclude:
    - "**/node_modules/**"
    - "**/venv/**"
    - "**/.git/**"
    - "**/dist/**"
    - "**/build/**"

# Tool-specific configuration
tools:
  semgrep:
    rulesets:
      - auto
  gitleaks:
    # config_path: .gitleaks.toml
  trivy:
    severity: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

# Suppressions
# suppress:
#   - fingerprint: "abc123..."
#     reason: "False positive"
"""

    config_path.write_text(default_config)
    console.print(f"[green]Created configuration at {config_path}[/green]")


if __name__ == "__main__":
    app()
