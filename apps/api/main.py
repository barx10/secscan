"""SecScan FastAPI application."""

from __future__ import annotations

import asyncio
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from packages.core.models import (
    FindingSeverity,
    Project,
    Scan,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanType,
)
from packages.core.pipeline import ScanPipeline
from packages.reporter import HtmlReporter, JsonReporter
from packages.storage.database import get_database, init_database
from packages.storage.repository import FindingRepository, ProjectRepository, ScanRepository

# In-memory scan status storage (for MVP - use Redis in production)
scan_results: dict[str, ScanResult] = {}
scan_tasks: dict[str, asyncio.Task] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    await init_database()
    yield
    # Shutdown
    db = get_database()
    await db.close()


app = FastAPI(
    title="SecScan API",
    description="Security vulnerability scanner API",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response models
class ScanRequest(BaseModel):
    """Request to create a new scan."""

    target: str = Field(..., description="Path or URL to scan")
    target_type: str = Field("repo", description="Type: repo, zip, or url")
    scan_types: list[str] = Field(
        default=["full"],
        description="Scan types: secrets, deps, sast, config, web, full",
    )
    severity_threshold: str = Field(default="info", description="Minimum severity to report")
    fail_on_severity: str | None = Field(default="high", description="Fail if findings at this severity")


class ScanResponse(BaseModel):
    """Response with scan ID."""

    scan_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    """Response with scan status."""

    scan_id: str
    status: str
    progress: float | None = None
    findings_count: int | None = None
    error_message: str | None = None


class FindingResponse(BaseModel):
    """Finding in API response."""

    id: str
    title: str
    severity: str
    category: str
    confidence: str
    risk_score: float
    description: str
    file_path: str | None
    line_start: int | None
    tool: str
    recommendation: str
    cwe_id: str | None = None
    cve_id: str | None = None


class ReportResponse(BaseModel):
    """Full scan report response."""

    scan_id: str
    status: str
    started_at: str | None
    completed_at: str | None
    duration_seconds: float | None
    findings_count: int
    risk_score: float
    severity_counts: dict[str, int]
    findings: list[FindingResponse]


class ToolStatus(BaseModel):
    """Status of a scanner tool."""

    name: str
    available: bool
    version: str | None = None


# API Routes
@app.get("/")
async def root():
    """API root."""
    return {
        "name": "SecScan API",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/tools", response_model=list[ToolStatus])
async def list_tools():
    """List available scanner tools."""
    from packages.adapters.registry import get_registry

    registry = get_registry()
    status = await registry.check_availability()

    return [
        ToolStatus(name=name, available=info["available"], version=info.get("version"))
        for name, info in status.items()
    ]


@app.post("/tools/{name}/install")
async def install_tool(name: str):
    """Attempt to install a missing tool."""
    import shutil
    import subprocess
    import sys

    # Map tools to install commands
    install_commands = {}
    
    # Python tools (install in current env)
    if name == "semgrep":
        install_commands[name] = [sys.executable, "-m", "pip", "install", "semgrep"]
    
    # Homebrew tools (Mac/Linux)
    elif name in ["gitleaks", "trivy", "syft", "osv-scanner", "zap"]:
        if shutil.which("brew"):
            pkg_name = name
            if name == "zap":
                pkg_name = "--cask owasp-zap" # Zap is a cask
                
            install_commands[name] = ["brew", "install"] + pkg_name.split()
        else:
            raise HTTPException(status_code=400, detail="Homebrew is required to install this tool automatically.")
    
    else:
        raise HTTPException(status_code=400, detail=f"Automatic installation not supported for {name}")

    cmd = install_commands.get(name)
    if not cmd:
         raise HTTPException(status_code=400, detail=f"No install command found for {name}")

    try:
        # Run the installation
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode != 0:
            raise Exception(process.stderr)
            
        return {"status": "installed", "message": f"{name} installed successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Installation failed: {str(e)}")



@app.get("/scans", response_model=list[ScanStatusResponse])
async def list_scans():
    """List all scans."""
    return [
        ScanStatusResponse(
            scan_id=scan_id,
            status=result.scan.status.value,
            findings_count=result.scan.findings_count,
            progress=result.scan.progress,
            error_message=result.scan.error_message,
        )
        for scan_id, result in scan_results.items()
    ]


@app.post("/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Create and start a new scan.

    The scan runs in the background. Use GET /scans/{scan_id} to check status.
    """
    # Build scan config
    config = ScanConfig(
        scan_types=[ScanType(t) for t in request.scan_types],
        severity_threshold=FindingSeverity(request.severity_threshold),
        fail_on_severity=(
            FindingSeverity(request.fail_on_severity) if request.fail_on_severity else None
        ),
    )

    # Create project
    project = Project(
        name=request.target.split("/")[-1] if "/" in request.target else request.target,
        source_type=request.target_type,
        source_path=request.target,
    )

    # Create initial scan record
    scan = Scan(
        project_id=project.id,
        config=config,
        status=ScanStatus.PENDING,
    )

    scan_id = str(scan.id)

    # Store initial status
    scan_results[scan_id] = ScanResult(scan=scan, findings=[])

    # Start background scan
    async def run_scan():
        pipeline = ScanPipeline()
        
        def update_progress(message: str, progress: float):
            # Update in-memory status
            if scan_id in scan_results:
                scan_results[scan_id].scan.status = ScanStatus.RUNNING
                scan_results[scan_id].scan.progress = progress
                # We could also store the 'message' somewhere if we want to show "Cloning..."
        
        pipeline.set_progress_callback(update_progress)

        try:
            target_path = Path(request.target)

            if request.target_type == "url":
                result = await pipeline.scan_url(request.target, config, project, scan_id=UUID(scan_id))
            elif request.target_type == "zip":
                result = await pipeline.scan_zip(target_path, config, project, scan_id=UUID(scan_id))
            else:
                # Check for git URL or if scanning local path
                if request.target.startswith(('http://', 'https://', 'git@', 'ssh://')):
                     result = await pipeline.scan_git_url(request.target, config, project, scan_id=UUID(scan_id))
                else:
                    result = await pipeline.scan_repo(target_path, config, project, scan_id=UUID(scan_id))

            scan_results[scan_id] = result
            
            # Inject target for reporting
            scan_results[scan_id].summary["target"] = request.target

            # Store in database
            db = get_database()
            async with db.session() as session:
                project_repo = ProjectRepository(session)
                scan_repo = ScanRepository(session)
                finding_repo = FindingRepository(session)

                await project_repo.create(project)
                await scan_repo.create(result.scan)
                await finding_repo.create_many(result.findings, result.scan.id)

        except Exception as e:
            scan_results[scan_id].scan.status = ScanStatus.FAILED
            scan_results[scan_id].scan.error_message = str(e)

    task = asyncio.create_task(run_scan())
    scan_tasks[scan_id] = task

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan started. Use GET /scans/{scan_id} to check status.",
    )


@app.post("/scans/upload", response_model=ScanResponse)
async def upload_and_scan(
    file: UploadFile = File(...),
    scan_types: list[str] = Query(default=["full"]),
    severity_threshold: str = Query(default="info"),
    background_tasks: BackgroundTasks = None,
):
    """
    Upload a zip file and scan it.

    The zip file is extracted to a temporary directory and scanned.
    """
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a .zip file")

    # Save uploaded file
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    # Build scan config
    config = ScanConfig(
        scan_types=[ScanType(t) for t in scan_types],
        severity_threshold=FindingSeverity(severity_threshold),
    )

    # Create project
    project = Project(
        name=file.filename.replace(".zip", ""),
        source_type="zip",
        source_path=str(tmp_path),
    )

    # Create scan
    scan = Scan(
        project_id=project.id,
        config=config,
        status=ScanStatus.PENDING,
    )

    scan_id = str(scan.id)
    scan_results[scan_id] = ScanResult(scan=scan, findings=[])

    # Start background scan
    async def run_scan():
        pipeline = ScanPipeline()
        try:
            result = await pipeline.scan_zip(tmp_path, config, project)
            scan_results[scan_id] = result
        except Exception as e:
            scan_results[scan_id].scan.status = ScanStatus.FAILED
            scan_results[scan_id].scan.error_message = str(e)
        finally:
            # Clean up temp file
            tmp_path.unlink(missing_ok=True)

    task = asyncio.create_task(run_scan())
    scan_tasks[scan_id] = task

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="File uploaded and scan started.",
    )


@app.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get the status of a scan."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[scan_id]
    scan = result.scan

    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan.status.value,
        findings_count=scan.findings_count if scan.status == ScanStatus.COMPLETED else None,
        error_message=scan.error_message,
    )


@app.get("/scans/{scan_id}/report", response_model=ReportResponse)
async def get_scan_report(scan_id: str):
    """Get the full scan report."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[scan_id]
    scan = result.scan

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan not completed. Current status: {scan.status.value}",
        )

    findings = [
        FindingResponse(
            id=str(f.id),
            title=f.title,
            severity=f.severity.value,
            category=f.category.value,
            confidence=f.confidence.value,
            risk_score=f.risk_score,
            description=f.description,
            file_path=f.evidence.file_path,
            line_start=f.evidence.line_start,
            tool=f.evidence.tool,
            recommendation=f.recommendation,
            cwe_id=f.cwe_id,
            cve_id=f.cve_id,
        )
        for f in result.findings
    ]

    return ReportResponse(
        scan_id=scan_id,
        status=scan.status.value,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        duration_seconds=scan.duration_seconds,
        findings_count=scan.findings_count,
        risk_score=scan.risk_score,
        severity_counts={
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count,
        },
        findings=findings,
    )


@app.get("/scans/{scan_id}/report.json")
async def get_json_report(scan_id: str):
    """Get scan report as JSON file."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[scan_id]

    if result.scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not completed")

    reporter = JsonReporter()
    content = reporter.generate(result)

    return JSONResponse(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="secscan-{scan_id}.json"'},
    )


@app.get("/scans/{scan_id}/report.html", response_class=HTMLResponse)
async def get_html_report(scan_id: str, lang: str = "en"):
    """Get scan report as HTML page."""
    print(f"Generating report for scan {scan_id} with lang={lang}")
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[scan_id]

    if result.scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not completed")

    # Use target URL/path if available, otherwise scan ID
    project_name = result.summary.get("target", f"Scan {scan_id[:8]}")

    reporter = HtmlReporter({
        "project_name": project_name,
        "language": lang
    })
    content = reporter.generate(result)

    return HTMLResponse(content=content)


@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan from history (cancels if running)."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Cancel if running
    if scan_id in scan_tasks:
        task = scan_tasks[scan_id]
        if not task.done():
            task.cancel()
        del scan_tasks[scan_id]

    # Remove from results
    del scan_results[scan_id]

    return {"message": "Scan deleted"}


# Run with: uvicorn apps.api.main:app --reload
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
