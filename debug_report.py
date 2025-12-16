
from packages.reporter.html_reporter import HtmlReporter
from packages.core.models import ScanResult, Scan, Finding, Evidence, FindingSeverity, FindingCategory, FindingConfidence
from uuid import uuid4
from datetime import datetime

# Create dummy data
scan = Scan(
    id=uuid4(),
    project_id=uuid4(),
    status="completed",
    duration_seconds=0.05,
    findings_count=1,
    high_count=1
)

findings = [
    Finding(
        title="Test Finding",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.SAST,
        confidence=FindingConfidence.HIGH,
        description="Desc",
        evidence=Evidence(tool="semgrep", file_path="foo.py", snippet="code"),
        impact="Impact",
        attack_scenario="Attack",
        recommendation="Fix",
        references=[]
    )
]

adapter_status = {
    "semgrep": {
        "success": True,
        "duration": 0.5,
        "message": "",
        "version": "1.0"
    }
}

result = ScanResult(
    scan=scan,
    findings=findings,
    summary={},
    adapter_status=adapter_status
)

try:
    print("Generating report...")
    reporter = HtmlReporter({"project_name": "Test", "language": "no"})
    html = reporter.generate(result)
    print("Report generated successfully!")
    print(html[:100])
except Exception as e:
    print("FAILED:")
    import traceback
    traceback.print_exc()
