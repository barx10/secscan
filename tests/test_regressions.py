import asyncio
import json
from datetime import datetime
from uuid import uuid4

from apps.api.main import get_gdpr_report, scan_results, _warn_on_missing_findings
from packages.adapters.gdpr import GdprAdapter, PageArtifact
from packages.adapters.nuclei import NucleiAdapter
from packages.adapters.zap import ZapAdapter
from packages.adapters.web_context import EndpointContext, apply_context_to_finding
from packages.core.models import Evidence, Finding, FindingCategory, FindingConfidence, FindingSeverity, Scan, ScanConfig, ScanResult, ScanStatus
from packages.core.pipeline import _apply_byok_adjustments
from packages.core.scoring import calculate_risk_score, prioritize_findings
from packages.reporter.html_reporter import HtmlReporter
from packages.reporter.json_reporter import JsonReporter
from packages.reporter.localization import get_localized_finding_content


def make_finding(
    *,
    title: str,
    severity: FindingSeverity,
    category: FindingCategory = FindingCategory.WEB,
    description: str = "Concrete scanner description",
    snippet: str | None = None,
    confidence: FindingConfidence = FindingConfidence.HIGH,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        confidence=confidence,
        description=description,
        evidence=Evidence(tool="test", file_path="https://example.com", snippet=snippet),
        impact="Concrete impact",
        attack_scenario="Concrete scenario",
        recommendation="Concrete remediation",
    )


def make_scan_result(*findings: Finding) -> ScanResult:
    scan = Scan(
        id=uuid4(),
        project_id=uuid4(),
        config=ScanConfig(),
        status=ScanStatus.COMPLETED,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        findings_count=len(findings),
        critical_count=sum(1 for finding in findings if finding.severity == FindingSeverity.CRITICAL),
        high_count=sum(1 for finding in findings if finding.severity == FindingSeverity.HIGH),
        medium_count=sum(1 for finding in findings if finding.severity == FindingSeverity.MEDIUM),
        low_count=sum(1 for finding in findings if finding.severity == FindingSeverity.LOW),
        info_count=sum(1 for finding in findings if finding.severity == FindingSeverity.INFO),
        risk_score=max((finding.risk_score for finding in findings), default=0.0),
    )
    return ScanResult(
        scan=scan,
        findings=list(findings),
        summary={"target": "https://example.com"},
        adapter_status={"zap": {"success": True}, "gdpr": {"success": True}},
    )


def test_gdpr_missing_controls_uses_dedicated_title() -> None:
    adapter = GdprAdapter()
    page = PageArtifact(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        html="<html><body><footer>privacy policy privacy@example.com</footer></body></html>",
        headers={},
        text="privacy policy privacy@example.com",
    )

    findings = adapter._build_findings("https://example.com", [page])
    rights_finding = next(f for f in findings if "brukerrettigheter" in f.title.lower())

    assert rights_finding.title == "Manglende brukerrettigheter (GDPR Art. 17/20)"
    assert rights_finding.severity == FindingSeverity.MEDIUM
    assert rights_finding.evidence.snippet is not None
    assert "Missing controls" in rights_finding.evidence.snippet


def test_localized_content_preserves_concrete_description() -> None:
    finding = make_finding(
        title="Reflected XSS in search parameter",
        severity=FindingSeverity.MEDIUM,
        description="ZAP found executable script content in the reflected response body.",
    )

    localized = get_localized_finding_content(finding, "no")

    assert localized["title"] == finding.title
    assert localized["description"] == finding.description
    assert localized["impact"] == finding.impact


def test_standard_findings_are_localized_to_norwegian_when_requested() -> None:
    finding = make_finding(
        title="Privacy Policy Not Found",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.PRIVACY,
        description="The scan could not find a linked privacy policy or personvernerklæring on the crawled pages.",
    )

    localized = get_localized_finding_content(finding, "no")

    assert localized["title"] == "Personvernerklæring ikke funnet"
    assert "personvernerklæring" in localized["description"].lower()
    assert localized["impact"].startswith("HØY:")


def test_standard_security_headers_are_localized_in_norwegian_report() -> None:
    finding = make_finding(
        title="Missing Anti-clickjacking Header",
        severity=FindingSeverity.MEDIUM,
        description="The response does not protect against 'ClickJacking' attacks.",
    )

    localized = get_localized_finding_content(finding, "no")

    assert localized["title"] == "Manglende anti-clickjacking-header"
    assert "clickjacking" in localized["description"].lower()
    assert localized["recommendation"].startswith("1. Sett")


def test_byok_architecture_filters_irrelevant_privacy_rights_and_adds_storage_finding() -> None:
    adapter = GdprAdapter()
    page = PageArtifact(
        url="https://example.com/app",
        final_url="https://example.com/app",
        status_code=200,
        html=(
            '<html><body><label>API key</label><input name="api_key" />'
            '<script>localStorage.setItem("openai_api_key", value)</script></body></html>'
        ),
        headers={},
        storage_ops=[("localStorage", "openai_api_key")],
        text="api key",
    )

    findings = adapter._build_findings("https://example.com/app", [page])
    titles = [finding.title for finding in findings]

    assert "BYOK Architecture Detected – Verify Keys Stay Client-Side" in titles
    assert "API Key Stored in localStorage" in titles
    assert not any("brukerrettigheter" in title.lower() for title in titles)
    assert "Privacy Policy Not Found" not in titles


def test_byok_privacy_policy_remains_when_tracking_is_detected() -> None:
    adapter = GdprAdapter()
    page = PageArtifact(
        url="https://example.com/app",
        final_url="https://example.com/app",
        status_code=200,
        html=(
            '<html><body><label>API key</label><input name="api_key" />'
            '<script src="https://www.googletagmanager.com/gtm.js"></script></body></html>'
        ),
        headers={},
        external_urls=["https://www.googletagmanager.com/gtm.js"],
        text="api key",
    )

    findings = adapter._build_findings("https://example.com/app", [page])

    assert any(finding.title == "Privacy Policy Not Found" for finding in findings)


def test_nuclei_xss_keeps_original_low_severity_without_context() -> None:
    adapter = NucleiAdapter()
    finding = adapter._parse_nuclei_result(
        {
            "template-id": "reflected-xss",
            "matched-at": "https://example.com/search?q=test",
            "info": {
                "name": "Reflected XSS",
                "severity": "low",
                "description": "Concrete nuclei description",
                "tags": ["xss"],
            },
        },
        "https://example.com/search?q=test",
    )

    assert finding is not None
    assert finding.severity == FindingSeverity.LOW
    assert finding.description.startswith("Concrete nuclei description")


def test_xss_on_admin_surface_is_never_below_medium() -> None:
    finding = make_finding(
        title="Reflected XSS",
        severity=FindingSeverity.LOW,
        description="Cross-site scripting in admin page",
    )
    context = EndpointContext(
        url="https://example.com/admin",
        final_url="https://example.com/admin",
        status_code=200,
        admin_surface=True,
        can_modify_data=True,
        sensitive_surface=True,
        publicly_accessible=False,
    )

    updated = apply_context_to_finding(finding, context)

    assert updated.severity == FindingSeverity.HIGH


def test_gdpr_risk_scores_are_not_flat() -> None:
    privacy_policy = make_finding(
        title="Privacy Policy Not Found",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.PRIVACY,
        confidence=FindingConfidence.MEDIUM,
    )
    rights = make_finding(
        title="Manglende brukerrettigheter (GDPR Art. 17/20)",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.PRIVACY,
        snippet="Missing controls: delete account, download my data",
        confidence=FindingConfidence.MEDIUM,
    )
    contact = make_finding(
        title="Privacy Contact Information Missing",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.PRIVACY,
        confidence=FindingConfidence.MEDIUM,
    )
    terms = make_finding(
        title="Terms and Conditions Not Found",
        severity=FindingSeverity.LOW,
        category=FindingCategory.PRIVACY,
        confidence=FindingConfidence.LOW,
    )

    privacy_policy_score = calculate_risk_score(privacy_policy)
    rights_score = calculate_risk_score(rights)
    contact_score = calculate_risk_score(contact)
    terms_score = calculate_risk_score(terms)

    assert privacy_policy_score >= 70.0
    assert rights_score >= 40.0
    assert contact_score >= 40.0
    assert 20.0 <= terms_score < 30.0
    assert len({privacy_policy_score, rights_score, contact_score, terms_score}) > 1


def test_info_findings_do_not_get_state_changing_text() -> None:
    finding = make_finding(
        title="Modern Web Application",
        severity=FindingSeverity.INFO,
        description="Informational technology fingerprinting.",
    )
    context = EndpointContext(
        url="https://example.com/app",
        final_url="https://example.com/app",
        status_code=200,
        methods=["GET"],
        actions=["edit", "save"],
        input_names=["q"],
        publicly_accessible=True,
    )

    updated = apply_context_to_finding(finding, context)

    assert "submit state-changing requests" not in updated.impact
    assert "submit state-changing requests" not in (updated.attack_scenario or "")


def test_zap_reported_xss_is_preserved_in_findings() -> None:
    adapter = ZapAdapter()
    findings = adapter.parse_output(
        {
            "site": {
                "@name": "https://example.com",
                "alerts": [
                    {
                        "name": "Cross Site Scripting (Reflected)",
                        "riskcode": "2",
                        "confidence": "2",
                        "desc": "Concrete ZAP XSS description.",
                        "solution": "Escape reflected content.",
                        "instances": [
                            {
                                "uri": "https://example.com/search?q=test",
                                "method": "GET",
                                "param": "q",
                                "evidence": "<script>alert(1)</script>",
                                "attack": "\"><script>alert(1)</script>",
                            }
                        ],
                    }
                ],
            }
        }
    )

    assert any("xss" in finding.title.lower() or "cross site scripting" in finding.title.lower() for finding in findings)


def test_csp_on_admin_route_never_below_medium() -> None:
    adapter = ZapAdapter()
    finding = make_finding(
        title="Content Security Policy (CSP) Header Not Set",
        severity=FindingSeverity.LOW,
        description="CSP header is missing.",
    )
    context = EndpointContext(
        url="https://example.com/admin",
        final_url="https://example.com/admin",
        status_code=200,
        methods=["GET"],
        admin_surface=True,
        publicly_accessible=True,
    )

    updated = adapter._adjust_clickjacking(finding.title, finding, context)

    assert updated is not None
    assert updated.severity == FindingSeverity.MEDIUM


def test_merged_html_report_contains_security_gdpr_and_crossrefs() -> None:
    security_finding = make_finding(
        title="Missing Anti-clickjacking Header",
        severity=FindingSeverity.MEDIUM,
        description="Concrete clickjacking description.",
    )
    security_finding.evidence.file_path = "https://example.com/account"
    security_finding.risk_score = 40.0

    privacy_finding = make_finding(
        title="Privacy Policy Not Found",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.PRIVACY,
        description="Concrete GDPR description.",
    )
    privacy_finding.evidence.file_path = "https://example.com/account"
    privacy_finding.risk_score = 70.0

    report = HtmlReporter({"project_name": "Example", "language": "no"}).generate(
        make_scan_result(security_finding, privacy_finding)
    )

    assert 'id="security"' in report
    assert 'id="gdpr"' in report
    assert 'id="crossrefs"' in report
    assert "Kryssreferanser" in report
    assert "GDPR Art. 13" in report
    assert "Personvernerklæring ikke funnet" in report
    assert "Manglende anti-clickjacking-header" in report


def test_byok_summary_is_rendered_in_norwegian_reports_and_json() -> None:
    security_finding = make_finding(
        title="API Key Stored in localStorage",
        severity=FindingSeverity.MEDIUM,
        description="API key stored in localStorage.",
    )
    privacy_finding = make_finding(
        title="BYOK Architecture Detected – Verify Keys Stay Client-Side",
        severity=FindingSeverity.LOW,
        category=FindingCategory.PRIVACY,
        description="BYOK detected.",
    )

    result = make_scan_result(security_finding, privacy_finding)
    html_report = HtmlReporter({"project_name": "Example", "language": "no"}).generate(result)
    json_report = json.loads(JsonReporter({"language": "no"}).generate(result))

    assert "Arkitektur" in html_report
    assert "BYOK (Bring Your Own Key)" in html_report
    assert "Ingen server-side brukerdata oppdaget" in html_report
    assert json_report["summary"]["architecture"]["type"] == "byok"
    assert json_report["summary"]["architecture"]["note"] == "Ingen server-side brukerdata oppdaget"


def test_pipeline_byok_adjustment_removes_privacy_rights_and_sets_summary() -> None:
    byok_finding = make_finding(
        title="BYOK Architecture Detected – Verify Keys Stay Client-Side",
        severity=FindingSeverity.LOW,
        category=FindingCategory.PRIVACY,
    )
    storage_finding = make_finding(
        title="API Key Stored in localStorage",
        severity=FindingSeverity.MEDIUM,
    )
    rights_finding = make_finding(
        title="Manglende brukerrettigheter (GDPR Art. 17/20)",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.PRIVACY,
    )

    findings, summary = _apply_byok_adjustments(
        [byok_finding, storage_finding, rights_finding],
        {"target": "https://example.com"},
    )

    assert [finding.title for finding in findings] == [
        "BYOK Architecture Detected – Verify Keys Stay Client-Side",
        "API Key Stored in localStorage",
    ]
    assert summary["architecture"]["type"] == "byok"
    assert summary["architecture"]["note"] == "Ingen server-side brukerdata oppdaget"


def test_pipeline_byok_adjustment_promotes_csp_and_explains_privacy_contact() -> None:
    byok_finding = make_finding(
        title="BYOK Architecture Detected – Verify Keys Stay Client-Side",
        severity=FindingSeverity.LOW,
        category=FindingCategory.PRIVACY,
    )
    storage_finding = make_finding(
        title="API Key Stored in localStorage",
        severity=FindingSeverity.MEDIUM,
    )
    csp_finding = make_finding(
        title="Content Security Policy (CSP) Header Not Set",
        severity=FindingSeverity.LOW,
        description="The response does not include the Content Security Policy header not set finding from ZAP.",
    )
    contact_finding = make_finding(
        title="Privacy Contact Information Missing",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.PRIVACY,
    )

    findings, summary = _apply_byok_adjustments(
        [byok_finding, storage_finding, csp_finding, contact_finding],
        {"target": "https://example.com"},
    )
    findings = prioritize_findings(findings)
    adjusted_csp = next(finding for finding in findings if finding.title == "Content Security Policy (CSP) Header Not Set")
    adjusted_contact = next(finding for finding in findings if finding.title == "Privacy Contact Information Missing")

    assert adjusted_csp.severity == FindingSeverity.MEDIUM
    assert "BYOK context:" in adjusted_csp.description
    assert calculate_risk_score(adjusted_csp) >= 40.0
    assert "BYOK context:" in adjusted_contact.description
    assert summary["architecture"]["type"] == "byok"

    localized_csp = get_localized_finding_content(adjusted_csp, "no")
    localized_contact = get_localized_finding_content(adjusted_contact, "no")

    assert localized_csp["impact"].startswith("MEDIUM:")
    assert "localStorage" in localized_csp["description"]
    assert "metadata" in localized_contact["description"].lower() or "logger" in localized_contact["description"].lower()


def test_cross_references_explain_byok_xss_chain() -> None:
    csp_finding = make_finding(
        title="Content Security Policy (CSP) Header Not Set",
        severity=FindingSeverity.MEDIUM,
        description="The response does not include the Content Security Policy header not set finding from ZAP.",
    )
    storage_finding = make_finding(
        title="API Key Stored in localStorage",
        severity=FindingSeverity.MEDIUM,
    )
    byok_finding = make_finding(
        title="BYOK Architecture Detected – Verify Keys Stay Client-Side",
        severity=FindingSeverity.LOW,
        category=FindingCategory.PRIVACY,
    )

    html = HtmlReporter({"language": "no"}).generate(make_scan_result(csp_finding, storage_finding, byok_finding))

    assert "Content-Security-Policy mangler + API-nøkkel i localStorage gir forhøyet XSS-risiko." in html
    assert "Fiks CSP først" in html
    assert "Anbefalt rekkefølge:" in html
    assert "Fiks CSP først for å redusere XSS-risikoen rundt nøkkelen i nettleseren." in html


def test_static_asset_cors_is_downgraded_to_info() -> None:
    adapter = ZapAdapter()
    finding = make_finding(
        title="Access-Control-Allow-Origin Header set to *",
        severity=FindingSeverity.MEDIUM,
        description="Wildcard CORS detected.",
    )
    finding.evidence.file_path = "https://example.com/assets/app.js"
    context = EndpointContext(
        url="https://example.com/assets/app.js",
        final_url="https://example.com/assets/app.js",
        status_code=200,
        publicly_accessible=True,
    )

    updated = adapter._adjust_cors_wildcard(finding.title, finding, context)

    assert updated.severity == FindingSeverity.INFO


def test_legacy_gdpr_route_redirects_to_merged_report() -> None:
    result = make_scan_result(make_finding(title="Privacy Policy Not Found", severity=FindingSeverity.HIGH, category=FindingCategory.PRIVACY))
    scan_id = str(result.scan.id)
    scan_results[scan_id] = result

    try:
        response = asyncio.run(get_gdpr_report(scan_id, "no"))
        assert response.status_code == 301
        assert response.headers["location"].endswith(f"/scans/{scan_id}/report.html?lang=no#gdpr")
    finally:
        scan_results.pop(scan_id, None)


def test_missing_previous_findings_logs_warning(caplog) -> None:
    previous_finding = make_finding(title="Cross Site Scripting (Reflected)", severity=FindingSeverity.MEDIUM)
    previous_finding.fingerprint = "prev-xss"
    current_finding = make_finding(title="Privacy Policy Not Found", severity=FindingSeverity.HIGH, category=FindingCategory.PRIVACY)
    current_finding.fingerprint = "privacy-1"

    with caplog.at_level("WARNING"):
        _warn_on_missing_findings(
            make_scan_result(previous_finding),
            make_scan_result(current_finding),
            "https://example.com",
        )

    assert "Previously seen XSS finding is missing from the latest scan" in caplog.text