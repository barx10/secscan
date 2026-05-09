"""Risk scoring and prioritization logic."""

from __future__ import annotations

from packages.core.models import Finding, FindingCategory, FindingConfidence, FindingSeverity

# Base severity scores
SEVERITY_SCORES: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 90.0,
    FindingSeverity.HIGH: 70.0,
    FindingSeverity.MEDIUM: 40.0,
    FindingSeverity.LOW: 20.0,
    FindingSeverity.INFO: 5.0,
}

# Confidence multipliers
CONFIDENCE_MULTIPLIERS: dict[FindingConfidence, float] = {
    FindingConfidence.HIGH: 1.0,
    FindingConfidence.MEDIUM: 0.8,
    FindingConfidence.LOW: 0.5,
}

# Category risk modifiers (some categories are inherently more risky)
CATEGORY_MODIFIERS: dict[FindingCategory, float] = {
    FindingCategory.SECRETS: 1.2,  # Secrets are high risk
    FindingCategory.DEPS: 1.0,
    FindingCategory.SAST: 1.1,
    FindingCategory.CONFIG: 0.9,
    FindingCategory.WEB: 1.15,
    FindingCategory.PRIVACY: 1.1,
}

# High-risk patterns that increase score
HIGH_RISK_PATTERNS = [
    # Auth bypass / IDOR
    "authentication",
    "authorization",
    "auth bypass",
    "idor",
    "insecure direct object",
    "access control",
    # RCE
    "remote code execution",
    "rce",
    "command injection",
    "code injection",
    "eval(",
    "exec(",
    "os.system",
    "subprocess",
    # SSRF
    "ssrf",
    "server-side request",
    # SQLi
    "sql injection",
    "sqli",
    # XSS
    "cross-site scripting",
    "xss",
    "script injection",
    # Secrets in frontend
    "api key",
    "api_key",
    "apikey",
    "secret",
    "password",
    "token",
    "credential",
    # Supply chain
    "dependency confusion",
    "typosquatting",
    "malicious package",
]

# Internet-exposed indicators
INTERNET_EXPOSED_PATTERNS = [
    "public",
    "internet",
    "external",
    "exposed",
    "endpoint",
    "api",
    "route",
    "handler",
]


def calculate_risk_score(finding: Finding) -> float:
    """
    Calculate risk score (0-100) for a finding.

    Factors:
    - Base severity score
    - Confidence multiplier
    - Category modifier
    - High-risk pattern boost
    - Internet exposure boost
    """
    # Start with base severity score
    score = SEVERITY_SCORES.get(finding.severity, 50.0)

    # Apply confidence multiplier
    score *= CONFIDENCE_MULTIPLIERS.get(finding.confidence, 0.8)

    # Apply category modifier
    score *= CATEGORY_MODIFIERS.get(finding.category, 1.0)

    # Check for high-risk patterns in title, description, and attack scenario
    text_to_check = " ".join(
        [
            finding.title.lower(),
            finding.description.lower(),
            (finding.attack_scenario or "").lower(),
            (finding.impact or "").lower(),
        ]
    )

    # --- Score adjustments for known low-value findings ---

    # Cap INFO findings related to timestamps or generic cache headers
    if finding.severity == FindingSeverity.INFO and any(
        kw in text_to_check for kw in ("timestamp", "cache-info", "retrieved from cache")
    ):
        return min(score, 2.0)

    # Clickjacking: only MEDIUM if sensitive page; otherwise LOW (max 25)
    is_clickjacking = any(
        kw in text_to_check
        for kw in ("clickjacking", "x-frame-options", "frame-ancestors", "x-frame")
    )
    if is_clickjacking:
        has_sensitive_context = any(
            kw in text_to_check
            for kw in ("login", "auth", "account", "payment", "checkout", "admin", "password")
        )
        if not has_sensitive_context:
            return min(score, 25.0)  # No sensitive data – cap at LOW range
        # Sensitive page: cap at MEDIUM ceiling
        return min(score, 50.0)

    # XSS boost: if HIGH confidence and has PoC/innerHTML evidence, push toward 90
    is_xss = any(kw in text_to_check for kw in ("cross-site scripting", "xss", "script injection"))
    if is_xss and finding.confidence == FindingConfidence.HIGH:
        has_concrete_evidence = any(
            kw in text_to_check
            for kw in ("dangerouslysetinnerhtml", "innerhtml", "proof-of-concept", "payload")
        )
        if has_concrete_evidence:
            score = max(score, 85.0)

    # --- Standard pattern boosts ---

    high_risk_matches = sum(1 for pattern in HIGH_RISK_PATTERNS if pattern in text_to_check)
    if high_risk_matches > 0:
        # Boost up to 15% for high-risk patterns
        boost = min(high_risk_matches * 5, 15)
        score *= 1 + (boost / 100)

    # Check for internet exposure
    if any(pattern in text_to_check for pattern in INTERNET_EXPOSED_PATTERNS):
        score *= 1.1  # 10% boost for internet-exposed issues

    # Check for specific high-impact indicators
    if finding.cve_id:
        score *= 1.05  # Known CVE gets a boost

    if finding.category == FindingCategory.SECRETS and finding.evidence.file_path:
        # Secrets in frontend/public directories are extra risky
        path_lower = finding.evidence.file_path.lower()
        if any(p in path_lower for p in ["public", "static", "frontend", "client", "dist"]):
            score *= 1.25

    # Cap at 100
    return min(score, 100.0)


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """
    Prioritize findings by risk score and return sorted list.

    Priority order:
    1. Risk score (highest first)
    2. Severity (critical > high > medium > low > info)
    3. Confidence (high > medium > low)
    """
    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4,
    }

    confidence_order = {
        FindingConfidence.HIGH: 0,
        FindingConfidence.MEDIUM: 1,
        FindingConfidence.LOW: 2,
    }

    # Calculate scores for all findings
    for finding in findings:
        finding.risk_score = calculate_risk_score(finding)

    # Sort by risk score (desc), then severity, then confidence
    return sorted(
        findings,
        key=lambda f: (
            -f.risk_score,
            severity_order.get(f.severity, 5),
            confidence_order.get(f.confidence, 3),
        ),
    )


def calculate_overall_risk_score(findings: list[Finding]) -> float:
    """
    Calculate overall risk score for a scan based on all findings.

    Uses a weighted approach that considers:
    - Number and severity of findings
    - Individual risk scores
    - Diminishing returns for many similar findings
    """
    if not findings:
        return 0.0

    # Count by severity
    severity_counts = {s: 0 for s in FindingSeverity}
    for finding in findings:
        severity_counts[finding.severity] += 1

    # Calculate weighted score
    # Critical findings have exponential impact, others linear
    score = 0.0

    # Critical: each one adds significant risk, with diminishing returns
    critical_count = severity_counts[FindingSeverity.CRITICAL]
    if critical_count > 0:
        score += 50 * (1 - 0.9**critical_count)  # Approaches 50 asymptotically

    # High: significant but less than critical
    high_count = severity_counts[FindingSeverity.HIGH]
    if high_count > 0:
        score += 30 * (1 - 0.92**high_count)

    # Medium
    medium_count = severity_counts[FindingSeverity.MEDIUM]
    if medium_count > 0:
        score += 15 * (1 - 0.95**medium_count)

    # Low and Info have minimal impact
    low_count = severity_counts[FindingSeverity.LOW]
    info_count = severity_counts[FindingSeverity.INFO]
    score += min(low_count * 0.5, 3)
    score += min(info_count * 0.1, 2)

    return min(score, 100.0)


def get_severity_from_score(score: float) -> FindingSeverity:
    """Convert a numeric score to a severity level."""
    if score >= 9.0:
        return FindingSeverity.CRITICAL
    elif score >= 7.0:
        return FindingSeverity.HIGH
    elif score >= 4.0:
        return FindingSeverity.MEDIUM
    elif score >= 2.0:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def map_tool_severity(tool: str, severity: str) -> FindingSeverity:
    """
    Map tool-specific severity strings to standard FindingSeverity.

    Different tools use different severity naming conventions.
    """
    severity_lower = severity.lower().strip()

    # Common mappings
    critical_terms = ["critical", "blocker", "urgent", "error"]
    high_terms = ["high", "major", "severe", "important"]
    medium_terms = ["medium", "moderate", "warning", "warn"]
    low_terms = ["low", "minor", "note"]
    info_terms = ["info", "informational", "style", "hint", "suggestion"]

    if any(term in severity_lower for term in critical_terms):
        return FindingSeverity.CRITICAL
    elif any(term in severity_lower for term in high_terms):
        return FindingSeverity.HIGH
    elif any(term in severity_lower for term in medium_terms):
        return FindingSeverity.MEDIUM
    elif any(term in severity_lower for term in low_terms):
        return FindingSeverity.LOW
    elif any(term in severity_lower for term in info_terms):
        return FindingSeverity.INFO

    # Tool-specific mappings
    if tool == "semgrep":
        semgrep_map = {"error": FindingSeverity.HIGH, "warning": FindingSeverity.MEDIUM}
        return semgrep_map.get(severity_lower, FindingSeverity.MEDIUM)

    if tool == "trivy":
        trivy_map = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "unknown": FindingSeverity.INFO,
        }
        return trivy_map.get(severity_lower, FindingSeverity.MEDIUM)

    if tool == "gitleaks":
        # Gitleaks doesn't have severity levels, all findings are considered high
        return FindingSeverity.HIGH

    if tool == "osv-scanner" or tool == "npm-audit" or tool == "pip-audit":
        # CVSS-based mapping
        try:
            cvss = float(severity_lower)
            if cvss >= 9.0:
                return FindingSeverity.CRITICAL
            elif cvss >= 7.0:
                return FindingSeverity.HIGH
            elif cvss >= 4.0:
                return FindingSeverity.MEDIUM
            elif cvss >= 0.1:
                return FindingSeverity.LOW
            return FindingSeverity.INFO
        except ValueError:
            pass

    # Default to medium if unknown
    return FindingSeverity.MEDIUM
