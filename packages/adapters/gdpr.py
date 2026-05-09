"""GDPR/privacy analysis for web applications."""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx

from packages.adapters.base import AdapterResult, BaseAdapter
from packages.core.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingConfidence,
    FindingSeverity,
    ScanType,
)

COOKIE_BANNER_PATTERNS = [
    "cookie",
    "consent",
    "samtykke",
    "personvern",
    "privacy preferences",
    "cookie preferences",
]

ACCEPT_ALL_PATTERNS = [
    "accept all",
    "allow all",
    "aksepter alle",
    "godta alle",
    "accept cookies",
]

PRIVACY_LINK_PATTERNS = [
    "privacy policy",
    "privacy notice",
    "personvernerkl",
    "personvern",
    "data protection",
]

TERMS_LINK_PATTERNS = ["terms", "vilkår", "terms of service", "bruksvilkår"]

DELETE_ACCOUNT_PATTERNS = [
    "delete account",
    "remove account",
    "slett konto",
    "close account",
]

DOWNLOAD_DATA_PATTERNS = [
    "download my data",
    "export my data",
    "data export",
    "last ned mine data",
    "export data",
]

PERSONALIZATION_PATTERNS = [
    "privacy settings",
    "data preferences",
    "personalization settings",
    "samtykkeinnstillinger",
    "personalisering",
    "manage preferences",
]

CONTACT_PATTERNS = [
    "privacy@",
    "dpo@",
    "personvern@",
    "data protection officer",
    "privacy officer",
    "personvernombud",
]

DPIA_PATTERNS = [
    "dpia",
    "data protection impact assessment",
    "konsekvensanalyse",
    "personvernkonsekvens",
]

RETENTION_PATTERNS = [
    r"retain(?:ed)? for (\d+) (day|days|month|months|year|years)",
    r"lagres i (\d+) (dag|dager|måned|måneder|år)",
]

TRACKING_VENDORS = {
    "www.google-analytics.com": ("Google Analytics", "US"),
    "google-analytics.com": ("Google Analytics", "US"),
    "www.googletagmanager.com": ("Google Tag Manager", "US"),
    "googletagmanager.com": ("Google Tag Manager", "US"),
    "static.hotjar.com": ("Hotjar", "EU"),
    "script.hotjar.com": ("Hotjar", "EU"),
    "api.hotjar.com": ("Hotjar", "EU"),
    "connect.facebook.net": ("Meta Pixel", "US"),
    "www.facebook.com": ("Meta Pixel", "US"),
    "cdn.segment.com": ("Segment", "US"),
    "api.segment.io": ("Segment", "US"),
    "fullstory.com": ("FullStory", "US"),
    "mouseflow.com": ("Mouseflow", "EU"),
    "clarity.ms": ("Microsoft Clarity", "US"),
    "script.crazyegg.com": ("Crazy Egg", "US"),
}

SESSION_REPLAY_VENDORS = {"Hotjar", "FullStory", "Mouseflow", "Microsoft Clarity", "Crazy Egg"}

PERSONAL_DATA_KEYS = {
    "name",
    "fullname",
    "first_name",
    "last_name",
    "email",
    "e-mail",
    "phone",
    "mobile",
    "user",
    "userid",
    "user_id",
    "customer",
    "customer_id",
    "profile",
    "personnummer",
}

CONSENT_STORAGE_KEYS = {"consent", "cookie_consent", "tracking_consent", "analytics_consent"}

BYOK_INPUT_PATTERNS = [
    r"api[\s_-]*key",
    r"api_key",
    r"apikey",
    r"access[\s_-]*key",
    r"secret[\s_-]*key",
    r"nøkkel",
]

AUTH_UI_PATTERNS = [
    "login",
    "log in",
    "signin",
    "sign in",
    "session",
    "password",
    "innlogging",
    "brukernavn",
    "oauth",
    "auth",
]

AUTH_NETWORK_PATTERNS = [
    "/login",
    "/signin",
    "/auth",
    "/session",
    "/oauth",
    "authorization",
    "www-authenticate",
    "bearer ",
    "set-cookie",
]

LOGGING_HINTS = [
    "sentry",
    "logrocket",
    "datadog",
    "newrelic",
    "bugsnag",
    "posthog",
    "telemetry",
    "/log",
    "/logs",
    "/events",
    "/analytics",
]


@dataclass(slots=True)
class PageArtifact:
    url: str
    final_url: str
    status_code: int
    html: str
    headers: dict[str, str]
    internal_links: list[str] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)
    storage_ops: list[tuple[str, str]] = field(default_factory=list)
    cookie_writes: list[str] = field(default_factory=list)
    text: str = ""


@dataclass(slots=True)
class ByokDetection:
    detected: bool
    api_key_inputs: list[tuple[str, str]] = field(default_factory=list)
    local_storage_keys: list[tuple[str, str, str]] = field(default_factory=list)
    login_flow_observed: bool = False
    server_auth_observed: bool = False
    reasons: list[str] = field(default_factory=list)


class GdprAdapter(BaseAdapter):
    """Adapter for GDPR/privacy analysis of web targets."""

    name = "gdpr"
    tool_name = "GDPR analyzer"
    scan_types = [ScanType.WEB]
    required_binaries: list[str] = []

    def is_available(self) -> bool:
        return True

    async def get_version(self) -> str | None:
        return "builtin"

    async def scan(self, target_path: Path, **kwargs: Any) -> AdapterResult:
        start_time = time.time()
        target_url = kwargs.get("url", str(target_path))

        try:
            pages = await self._crawl_site(target_url)
            findings = self._build_findings(target_url, pages)
            for finding in findings:
                finding.fingerprint = self.generate_fingerprint(finding)
            return AdapterResult(
                success=True,
                findings=findings,
                raw_output={"pages": [page.url for page in pages]},
                duration_seconds=time.time() - start_time,
                tool_version="builtin",
            )
        except Exception as exc:
            return AdapterResult(
                success=False,
                error_message=str(exc),
                duration_seconds=time.time() - start_time,
                tool_version="builtin",
            )

    def parse_output(self, raw_output: dict[str, Any]) -> list[Finding]:
        return []

    async def _crawl_site(self, target_url: str) -> list[PageArtifact]:
        parsed_target = urlparse(target_url)
        base_host = parsed_target.netloc
        max_pages = int(self.config.get("max_pages", 8))
        queue: deque[str] = deque([target_url])
        seen: set[str] = set()
        pages: list[PageArtifact] = []

        timeout = httpx.Timeout(10.0, connect=5.0)
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=False) as client:
            while queue and len(pages) < max_pages:
                current = queue.popleft()
                if current in seen:
                    continue
                seen.add(current)

                response = await client.get(current)
                content_type = response.headers.get("content-type", "").lower()
                if "html" not in content_type and "<html" not in response.text.lower():
                    continue

                page = self._parse_page(current, str(response.url), response.status_code, response.text, dict(response.headers))
                pages.append(page)

                for link in page.internal_links:
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == base_host and link not in seen:
                        queue.append(link)

        return pages

    def _parse_page(
        self,
        source_url: str,
        final_url: str,
        status_code: int,
        html: str,
        headers: dict[str, str],
    ) -> PageArtifact:
        internal_links: list[str] = []
        external_urls: list[str] = []
        storage_ops: list[tuple[str, str]] = []
        cookie_writes: list[str] = []

        parsed_base = urlparse(final_url)
        base_host = parsed_base.netloc
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip().lower()

        for attr in re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            absolute = urljoin(final_url, attr)
            parsed = urlparse(absolute)
            if not parsed.scheme.startswith("http"):
                continue
            if parsed.netloc == base_host:
                internal_links.append(absolute)
            else:
                external_urls.append(absolute)

        for url in re.findall(r'(?:fetch|axios\.(?:get|post|put|patch|delete)|navigator\.sendBeacon)\s*\(\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            absolute = urljoin(final_url, url)
            parsed = urlparse(absolute)
            if parsed.netloc and parsed.netloc != base_host:
                external_urls.append(absolute)
            else:
                internal_links.append(absolute)

        for storage_type, key in re.findall(
            r'(localStorage|sessionStorage)\.setItem\(\s*["\']([^"\']+)["\']',
            html,
            re.IGNORECASE,
        ):
            storage_ops.append((storage_type, key))

        for cookie_name in re.findall(r'document\.cookie\s*=\s*["\']([^=;"\']+)', html, re.IGNORECASE):
            cookie_writes.append(cookie_name)

        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            for cookie_name in re.findall(r'([^=;,\s]+)=', set_cookie):
                cookie_writes.append(cookie_name)

        return PageArtifact(
            url=source_url,
            final_url=final_url,
            status_code=status_code,
            html=html,
            headers=headers,
            internal_links=self._dedupe(internal_links),
            external_urls=self._dedupe(external_urls),
            storage_ops=self._dedupe_pairs(storage_ops),
            cookie_writes=self._dedupe(cookie_writes),
            text=text,
        )

    def _build_findings(self, target_url: str, pages: list[PageArtifact]) -> list[Finding]:
        findings: list[Finding] = []
        if not pages:
            return [
                self._finding(
                    title="Unable to Analyze GDPR Surface",
                    severity=FindingSeverity.MEDIUM,
                    description="The GDPR module could not fetch any HTML pages from the target, so consent and privacy controls could not be verified.",
                    impact="Privacy compliance issues may remain undetected.",
                    recommendation="Ensure the target is reachable during scanning and expose the main HTML pages without requiring JavaScript-only rendering.",
                    url=target_url,
                    snippet="No HTML pages retrieved",
                )
            ]

        cookie_banner_present = any(self._contains_any(page.text, COOKIE_BANNER_PATTERNS) for page in pages)
        accept_all_present = any(self._contains_any(page.text, ACCEPT_ALL_PATTERNS) for page in pages)
        consent_storage = self._find_consent_storage(pages)
        privacy_page = self._find_matching_page(pages, PRIVACY_LINK_PATTERNS)
        terms_page = self._find_matching_page(pages, TERMS_LINK_PATTERNS)
        contact_present = any(self._contains_any(page.text, CONTACT_PATTERNS) for page in pages)
        delete_account_present = any(self._contains_any(page.text, DELETE_ACCOUNT_PATTERNS) for page in pages)
        download_data_present = any(self._contains_any(page.text, DOWNLOAD_DATA_PATTERNS) for page in pages)
        personalization_present = any(self._contains_any(page.text, PERSONALIZATION_PATTERNS) for page in pages)
        dpia_present = any(self._contains_any(page.text, DPIA_PATTERNS) for page in pages)

        personal_storage = self._find_personal_storage(pages)
        tracking = self._detect_tracking_integrations(pages)
        logging_integrations = self._detect_logging_integrations(pages)
        third_party_flows = self._detect_external_flows(pages)
        query_pii = self._detect_query_param_pii(pages)
        inline_pii = self._detect_inline_pii(pages)
        retention_issue = self._detect_retention_issue(pages)
        byok = self._detect_byok(pages)

        if byok.detected:
            findings.append(
                self._finding(
                    title="BYOK Architecture Detected – Verify Keys Stay Client-Side",
                    severity=FindingSeverity.LOW,
                    description=(
                        "The application appears to use a Bring Your Own Key (BYOK) pattern. "
                        "No conventional login/session flow or server-side authentication markers were observed, "
                        "or the UI explicitly asks the user for an API key."
                    ),
                    impact=(
                        "If the architecture is truly client-side BYOK, classic account-deletion and data-export findings "
                        "may be less relevant. The remaining risk is whether API keys leak to the server, browser storage or third parties."
                    ),
                    recommendation=(
                        "Confirm that API keys remain client-side, are never logged server-side, and are not sent to backend endpoints except where explicitly documented. "
                        "Document the BYOK model in the privacy notice if analytics, logging or other telemetry is active."
                    ),
                    url=pages[0].url,
                    snippet="BYOK indicators: " + "; ".join(byok.reasons),
                )
            )

        if byok.detected:
            if byok.local_storage_keys:
                details = "; ".join(
                    f"{storage_type} key '{key}' on {url}"
                    for storage_type, key, url in byok.local_storage_keys[:6]
                )
                evidence_url = byok.local_storage_keys[0][2]
            else:
                details = "; ".join(f"API key input '{label}' on {url}" for label, url in byok.api_key_inputs[:6])
                evidence_url = byok.api_key_inputs[0][1] if byok.api_key_inputs else pages[0].url
            findings.append(
                Finding(
                    title="API Key Stored in localStorage",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingCategory.WEB,
                    confidence=FindingConfidence.MEDIUM,
                    description=(
                        "BYOK applications often keep the API key in browser localStorage. localStorage is accessible to all JavaScript on the page, "
                        "and an XSS issue can exfiltrate the key without the user noticing."
                    ),
                    evidence=Evidence(tool=self.name, file_path=evidence_url, snippet=details),
                    impact=(
                        "Attackers who achieve script execution in the browser can exfiltrate the API key and reuse it outside the application."
                    ),
                    attack_scenario=(
                        "An attacker lands XSS on any page, reads the key from localStorage, and sends it to an external endpoint for reuse."
                    ),
                    recommendation=(
                        "Consider sessionStorage so the key is cleared when the browser closes, or encrypt the key with Web Crypto before storing it in localStorage. "
                        "Prioritize a CSP header to reduce XSS risk."
                    ),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"],
                )
            )

        if personal_storage:
            details = "; ".join(
                f"{storage_type} key '{key}' on {url}"
                for storage_type, key, url in personal_storage[:6]
            )
            findings.append(
                self._finding(
                    title="Personal Data Stored in Browser Storage",
                    severity=FindingSeverity.CRITICAL,
                    description=(
                        "Persondata ser ut til å bli lagret i localStorage eller sessionStorage uten tilstrekkelig beskyttelse. "
                        "Dette er lett tilgjengelig for JavaScript og øker GDPR-risikoen ved XSS eller delt enhet."
                    ),
                    impact="Personal data such as names, email addresses or user identifiers can be extracted from the browser and reused without user consent.",
                    recommendation="Avoid storing persondata in browser storage. Prefer HttpOnly cookies or encrypted, short-lived references. If storage is unavoidable, minimize fields and add client-side encryption plus rotation.",
                    url=personal_storage[0][2],
                    snippet=details,
                )
            )

        if (tracking or third_party_flows) and not cookie_banner_present:
            systems = ", ".join(sorted({item[0] for item in tracking})[:6]) or "external tracking systems"
            findings.append(
                self._finding(
                    title="Data Collection Without Consent Banner",
                    severity=FindingSeverity.HIGH,
                    description=(
                        "The site appears to load tracking or third-party data collection systems before a visible cookie or consent banner is presented. "
                        f"Detected systems: {systems}."
                    ),
                    impact="Users may be tracked before valid GDPR consent is collected, creating unlawful processing risk.",
                    recommendation="Display a consent banner before loading analytics, marketing pixels or third-party data collection scripts. Block non-essential scripts until the user has explicitly consented.",
                    url=pages[0].url,
                    snippet=self._summarize_domains(third_party_flows),
                )
            )

        if accept_all_present and consent_storage:
            findings.append(
                self._finding(
                    title="Consent Acceptance Mechanism Detected",
                    severity=FindingSeverity.LOW,
                    description="The site appears to expose an 'Accept All' consent path and stores a consent marker in browser storage or cookies.",
                    impact="This is informational, but the consent flow should still support granular choices and rejection.",
                    recommendation="Verify that the consent UI also offers reject/customize options and that consent is logged with clear categories.",
                    url=consent_storage[0][2],
                    snippet="; ".join(f"{storage_type}:{key}" for storage_type, key, _ in consent_storage[:5]),
                )
            )

        if query_pii:
            snippet = "; ".join(f"{url} -> {', '.join(params)}" for url, params in query_pii[:5])
            findings.append(
                self._finding(
                    title="Personal Data Sent in URL Query Parameters",
                    severity=FindingSeverity.HIGH,
                    description="API calls or links include persondata in the URL query string. Query parameters leak into browser history, logs, referrers and monitoring systems.",
                    impact="Email addresses, phone numbers or user identifiers may be exposed to logs, proxies and third parties.",
                    recommendation="Move personal data into POST bodies or encrypted payloads. Strip persondata from URLs and rotate any identifiers already exposed.",
                    url=query_pii[0][0],
                    snippet=snippet,
                )
            )

        if inline_pii:
            snippet = "; ".join(f"{kind}:{value} on {url}" for kind, value, url in inline_pii[:6])
            findings.append(
                self._finding(
                    title="Personal Data Exposed in Frontend Content",
                    severity=FindingSeverity.MEDIUM,
                    description="The HTML or inline scripts contain email addresses or phone numbers in places that may be cached or exposed to unauthorized users.",
                    impact="Front-end leakage can disclose persondata to other users, crawlers or shared devices.",
                    recommendation="Avoid embedding persondata in publicly cacheable HTML or inline JavaScript. Render only the minimum needed for the active user session.",
                    url=inline_pii[0][2],
                    snippet=snippet,
                )
            )

        if third_party_flows:
            outside_eu = [flow for flow in third_party_flows if flow[2] not in {"EU", "Unknown"}]
            severity = FindingSeverity.CRITICAL if outside_eu else FindingSeverity.LOW
            title = "Third-Party Data Transfers Detected"
            description = "The site sends data or loads assets from third-party domains. "
            if outside_eu:
                description += "Some detected destinations are associated with jurisdictions outside the EU/EEA."
            else:
                description += "These integrations should still be documented in the privacy notice and consent flow."
            findings.append(
                self._finding(
                    title=title,
                    severity=severity,
                    description=description,
                    impact="Users may have their data transferred to external processors without adequate notice, safeguards or regional controls.",
                    recommendation="List every third-party processor in the privacy notice, gate non-essential transfers behind consent, and verify SCCs or EU-hosted alternatives for non-EU destinations.",
                    url=third_party_flows[0][1],
                    snippet=self._summarize_domains(third_party_flows),
                )
            )

        if tracking:
            replay_tools = [name for name, _, _ in tracking if name in SESSION_REPLAY_VENDORS]
            severity = FindingSeverity.MEDIUM if replay_tools else FindingSeverity.LOW
            description = "Analytics or tracking integrations were detected: " + ", ".join(sorted({name for name, _, _ in tracking})) + "."
            if replay_tools:
                description += " Session replay or detailed clicktracking increases privacy impact and may require DPIA review."
            findings.append(
                self._finding(
                    title="Tracking and Analytics Systems Detected",
                    severity=severity,
                    description=description,
                    impact="Tracking can profile user behavior and create additional GDPR obligations around consent, minimization and retention.",
                    recommendation="Document each analytics system, block non-essential trackers until consent, and evaluate whether session replay or granular clicktracking is necessary.",
                    url=tracking[0][1],
                    snippet=self._summarize_domains([(name, url, region) for name, url, region in tracking]),
                )
            )

        missing_controls: list[str] = []
        if not delete_account_present:
            missing_controls.append("delete account")
        if not download_data_present:
            missing_controls.append("download my data")
        if not personalization_present:
            missing_controls.append("privacy/personalization settings")
        if missing_controls and not byok.detected:
            findings.append(
                self._finding(
                    title="Manglende brukerrettigheter (GDPR Art. 17/20)",
                    severity=FindingSeverity.MEDIUM,
                    description="The scan could not find key self-service privacy controls: " + ", ".join(missing_controls) + ".",
                    impact="Users may be unable to exercise GDPR rights around deletion, access and control of profiling or personalization.",
                    recommendation="Expose clear account-level controls for deleting the account, downloading personal data and managing personalization or consent preferences.",
                    url=pages[0].url,
                    snippet="Missing controls: " + ", ".join(missing_controls),
                )
            )

        privacy_notice_required = bool(tracking or logging_integrations)
        if not privacy_page and (not byok.detected or privacy_notice_required):
            findings.append(
                self._finding(
                    title="Privacy Policy Not Found",
                    severity=FindingSeverity.HIGH,
                    description="The scan could not find a linked privacy policy or personvernerklæring on the crawled pages.",
                    impact="Users are not given the information required to understand how their personal data is collected, processed or shared.",
                    recommendation="Add a clearly linked privacy policy in the footer or main navigation, and describe purposes, processors, retention, rights and contact details.",
                    url=pages[0].url,
                    snippet="No privacy-policy link detected",
                )
            )

        if not terms_page:
            findings.append(
                self._finding(
                    title="Terms and Conditions Not Found",
                    severity=FindingSeverity.LOW,
                    description="The scan could not verify that the site links to terms and conditions or vilkår.",
                    impact="Users may lack contractual context for account use, processor roles and dispute handling.",
                    recommendation="Add a clearly linked Terms or Vilkår page alongside the privacy notice.",
                    url=pages[0].url,
                    snippet="No terms link detected",
                )
            )

        if not contact_present:
            findings.append(
                self._finding(
                    title="Privacy Contact Information Missing",
                    severity=FindingSeverity.MEDIUM,
                    description="No obvious privacy contact, DPO address or personvernombud contact was detected on the crawled pages.",
                    impact="Users may not know where to send GDPR requests or complaints.",
                    recommendation="Publish a privacy contact email or DPO/contact point in the privacy policy and footer.",
                    url=(privacy_page.url if privacy_page else pages[0].url),
                    snippet="No privacy-specific contact details detected",
                )
            )

        if tracking and not dpia_present:
            findings.append(
                self._finding(
                    title="No DPIA or Privacy Impact Reference Found",
                    severity=FindingSeverity.MEDIUM,
                    description="Tracking or analytics was detected, but the site does not reference a DPIA or privacy impact assessment.",
                    impact="Higher-risk processing may not have documented risk assessment or accountability evidence.",
                    recommendation="Document DPIA outcomes for high-risk analytics, profiling or session replay, and link or reference the assessment where appropriate.",
                    url=pages[0].url,
                    snippet="Tracking detected without DPIA reference",
                )
            )

        if retention_issue:
            findings.append(
                self._finding(
                    title="Potentially Excessive Data Retention Disclosure",
                    severity=FindingSeverity.MEDIUM,
                    description="The privacy text appears to describe retention periods longer than necessary without visible justification.",
                    impact="Over-retention increases the impact of breaches and may violate storage limitation requirements.",
                    recommendation="Review retention schedules, justify every long retention period, and publish a shorter or purpose-based retention policy.",
                    url=retention_issue[0],
                    snippet=retention_issue[1],
                )
            )

        return findings

    def _detect_tracking_integrations(self, pages: list[PageArtifact]) -> list[tuple[str, str, str]]:
        results: list[tuple[str, str, str]] = []
        for page in pages:
            for external_url in page.external_urls:
                domain = urlparse(external_url).netloc.lower()
                for known_domain, (name, region) in TRACKING_VENDORS.items():
                    if known_domain in domain:
                        results.append((name, page.url, region))
        return self._dedupe_tuples(results)

    def _detect_logging_integrations(self, pages: list[PageArtifact]) -> list[tuple[str, str]]:
        matches: list[tuple[str, str]] = []
        for page in pages:
            for candidate in [page.url, page.final_url, *page.internal_links, *page.external_urls]:
                candidate_lower = candidate.lower()
                for hint in LOGGING_HINTS:
                    if hint in candidate_lower:
                        matches.append((hint, page.url))
        return self._dedupe_tuples(matches)

    def _detect_byok(self, pages: list[PageArtifact]) -> ByokDetection:
        api_key_inputs: list[tuple[str, str]] = []
        local_storage_keys: list[tuple[str, str, str]] = []
        login_flow_observed = False
        server_auth_observed = False
        app_like_client_surface = False

        for page in pages:
            api_key_inputs.extend((label, page.url) for label in self._extract_api_key_inputs(page.html))

            for storage_type, key in page.storage_ops:
                if storage_type.lower() == "localstorage" and self._looks_like_api_key_name(key):
                    local_storage_keys.append((storage_type, key, page.url))

            html_lower = page.html.lower()
            if (
                re.search(r"<(?:form|input|textarea|select)\b", page.html, re.IGNORECASE)
                or any(marker in html_lower for marker in ("localstorage", "sessionstorage", "fetch(", "axios.", "navigator.sendbeacon"))
            ):
                app_like_client_surface = True

            page_blob = f"{page.html}\n{page.text}".lower()
            if any(pattern in page_blob for pattern in AUTH_UI_PATTERNS):
                login_flow_observed = True
            if any(self._looks_like_session_cookie(cookie_name) for cookie_name in page.cookie_writes):
                login_flow_observed = True
                server_auth_observed = True

            if self._has_server_auth_markers(page):
                server_auth_observed = True

        reasons: list[str] = []
        if api_key_inputs:
            reasons.append("API key input field observed")
        if local_storage_keys:
            reasons.append("key-like value stored in localStorage")
        absence_support_signal = app_like_client_surface and not login_flow_observed and not server_auth_observed
        if absence_support_signal:
            reasons.append("no login flow or session handling observed")
            reasons.append("no server-side authentication visible in network traffic")

        return ByokDetection(
            detected=bool(reasons),
            api_key_inputs=self._dedupe_tuples(api_key_inputs),
            local_storage_keys=self._dedupe_tuples(local_storage_keys),
            login_flow_observed=login_flow_observed,
            server_auth_observed=server_auth_observed,
            reasons=reasons,
        )

    def _extract_api_key_inputs(self, html: str) -> list[str]:
        matches: list[str] = []
        for pattern in BYOK_INPUT_PATTERNS:
            label_regex = rf"<label[^>]*>([^<]{{0,80}}{pattern}[^<]{{0,80}})</label>"
            attr_regex = rf"<(?:input|textarea)[^>]*(?:name|id|placeholder|aria-label)\s*=\s*[\"\']([^\"\']*{pattern}[^\"\']*)[\"\']"
            matches.extend(re.findall(label_regex, html, re.IGNORECASE))
            matches.extend(re.findall(attr_regex, html, re.IGNORECASE))
        return self._dedupe([re.sub(r"\s+", " ", match).strip() for match in matches if match.strip()])

    def _looks_like_api_key_name(self, key: str) -> bool:
        normalized = key.lower().replace("-", "_").strip()
        if normalized in CONSENT_STORAGE_KEYS:
            return False
        markers = (
            "api_key",
            "apikey",
            "access_key",
            "secret_key",
            "openai",
            "anthropic",
            "claude",
            "gemini",
            "mistral",
        )
        return any(marker in normalized for marker in markers) or normalized.endswith("_key")

    def _looks_like_session_cookie(self, cookie_name: str) -> bool:
        normalized = cookie_name.lower().replace("-", "_")
        return any(marker in normalized for marker in ("session", "sess", "auth", "jwt", "token"))

    def _has_server_auth_markers(self, page: PageArtifact) -> bool:
        headers_blob = "\n".join(f"{key}: {value}" for key, value in page.headers.items()).lower()
        network_blob = "\n".join([page.url, page.final_url, *page.internal_links, *page.external_urls]).lower()
        return any(pattern in headers_blob for pattern in AUTH_NETWORK_PATTERNS) or any(
            pattern in network_blob for pattern in AUTH_NETWORK_PATTERNS if pattern.startswith("/")
        )

    def _detect_external_flows(self, pages: list[PageArtifact]) -> list[tuple[str, str, str]]:
        flows: list[tuple[str, str, str]] = []
        for page in pages:
            for external_url in page.external_urls:
                domain = urlparse(external_url).netloc.lower()
                vendor_name, region = TRACKING_VENDORS.get(domain, (domain, self._infer_region(domain)))
                flows.append((vendor_name, page.url, region))
        return self._dedupe_tuples(flows)

    def _detect_query_param_pii(self, pages: list[PageArtifact]) -> list[tuple[str, list[str]]]:
        matches: list[tuple[str, list[str]]] = []
        for page in pages:
            urls = [page.url, *page.internal_links, *page.external_urls]
            for candidate in urls:
                parsed = urlparse(candidate)
                params = [
                    key
                    for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
                    if self._is_personal_key(key)
                ]
                if params:
                    matches.append((candidate, self._dedupe(params)))
        return matches

    def _detect_inline_pii(self, pages: list[PageArtifact]) -> list[tuple[str, str, str]]:
        matches: list[tuple[str, str, str]] = []
        email_pattern = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
        phone_pattern = re.compile(r"\+?\d[\d\s().-]{7,}\d")
        for page in pages:
            for email in email_pattern.findall(page.html)[:5]:
                matches.append(("email", email, page.url))
            for phone in phone_pattern.findall(page.html)[:5]:
                matches.append(("phone", phone.strip(), page.url))
        return self._dedupe_tuples(matches)

    def _find_personal_storage(self, pages: list[PageArtifact]) -> list[tuple[str, str, str]]:
        findings: list[tuple[str, str, str]] = []
        for page in pages:
            for storage_type, key in page.storage_ops:
                if self._is_personal_key(key):
                    findings.append((storage_type, key, page.url))
            for cookie_name in page.cookie_writes:
                if self._is_personal_key(cookie_name):
                    findings.append(("cookie", cookie_name, page.url))
        return self._dedupe_tuples(findings)

    def _find_consent_storage(self, pages: list[PageArtifact]) -> list[tuple[str, str, str]]:
        matches: list[tuple[str, str, str]] = []
        for page in pages:
            for storage_type, key in page.storage_ops:
                if any(consent in key.lower() for consent in CONSENT_STORAGE_KEYS):
                    matches.append((storage_type, key, page.url))
            for cookie_name in page.cookie_writes:
                if any(consent in cookie_name.lower() for consent in CONSENT_STORAGE_KEYS):
                    matches.append(("cookie", cookie_name, page.url))
        return self._dedupe_tuples(matches)

    def _find_matching_page(self, pages: list[PageArtifact], patterns: list[str]) -> PageArtifact | None:
        for page in pages:
            if self._contains_any(page.text, patterns):
                return page
            if any(self._contains_any(link.lower(), patterns) for link in page.internal_links):
                return page
        return None

    def _detect_retention_issue(self, pages: list[PageArtifact]) -> tuple[str, str] | None:
        for page in pages:
            for pattern in RETENTION_PATTERNS:
                for match in re.finditer(pattern, page.text, re.IGNORECASE):
                    amount = int(match.group(1))
                    unit = match.group(2).lower()
                    months = amount
                    if unit.startswith("day") or unit.startswith("dag"):
                        months = amount / 30
                    elif unit.startswith("year") or unit == "år":
                        months = amount * 12
                    if months > 24:
                        return page.url, match.group(0)
        return None

    def _finding(
        self,
        *,
        title: str,
        severity: FindingSeverity,
        description: str,
        impact: str,
        recommendation: str,
        url: str,
        snippet: str,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            category=FindingCategory.PRIVACY,
            confidence=FindingConfidence.MEDIUM if severity != FindingSeverity.LOW else FindingConfidence.LOW,
            description=description,
            evidence=Evidence(tool=self.name, file_path=url, snippet=snippet),
            impact=impact,
            attack_scenario=(
                "An attacker, third-party processor or auditor can observe how the application stores, shares or exposes personal data from this endpoint."
            ),
            recommendation=recommendation,
            references=[
                "https://gdpr.eu/what-is-gdpr/",
                "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/",
            ],
        )

    def _contains_any(self, text: str, patterns: list[str]) -> bool:
        return any(pattern in text for pattern in patterns)

    def _is_personal_key(self, key: str) -> bool:
        key_lower = key.lower().replace("-", "_")
        return any(marker in key_lower for marker in PERSONAL_DATA_KEYS)

    def _infer_region(self, domain: str) -> str:
        if domain.endswith(".eu"):
            return "EU"
        if domain.endswith(".no") or domain.endswith(".de") or domain.endswith(".fr") or domain.endswith(".nl"):
            return "EU"
        if domain.endswith(".io") or domain.endswith(".com") or domain.endswith(".net"):
            return "Unknown"
        if domain.endswith(".us"):
            return "US"
        return "Unknown"

    def _summarize_domains(self, flows: list[tuple[str, str, str]]) -> str:
        return "; ".join(f"{name} from {url} ({region})" for name, url, region in flows[:8])

    def _dedupe(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _dedupe_pairs(self, values: list[tuple[str, str]]) -> list[tuple[str, str]]:
        seen: set[tuple[str, str]] = set()
        result: list[tuple[str, str]] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _dedupe_tuples(self, values: list[tuple[Any, ...]]) -> list[tuple[Any, ...]]:
        seen: set[tuple[Any, ...]] = set()
        result: list[tuple[Any, ...]] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result