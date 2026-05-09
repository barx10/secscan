"""Endpoint-aware HTML analysis for web findings."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse

import httpx

from packages.core.models import Evidence, Finding, FindingCategory, FindingConfidence, FindingSeverity

logger = logging.getLogger(__name__)

PROTECTED_PATH_KEYWORDS = (
    "admin",
    "dashboard",
    "account",
    "settings",
    "profile",
    "billing",
    "checkout",
    "orders",
    "users",
    "roles",
    "editor",
)

LOGIN_PATH_KEYWORDS = ("login", "signin", "sign-in", "auth", "session")

ADMIN_BODY_KEYWORDS = (
    "admin panel",
    "admin dashboard",
    "user management",
    "role management",
    "system settings",
    "manage users",
)

AUTH_WALL_KEYWORDS = (
    "login required",
    "please log in",
    "please sign in",
    "authentication required",
    "unauthorized",
    "access denied",
    "forbidden",
    "session expired",
)

STATE_CHANGE_KEYWORDS = (
    "create",
    "add",
    "edit",
    "update",
    "delete",
    "remove",
    "save",
    "publish",
    "invite",
    "reset password",
    "change password",
)


@dataclass(slots=True)
class EndpointContext:
    """Observed security-relevant context for a single URL."""

    url: str
    final_url: str
    status_code: int
    page_title: str = ""
    methods: list[str] = field(default_factory=list)
    input_names: list[str] = field(default_factory=list)
    input_types: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    auth_wall_detected: bool = False
    login_surface: bool = False
    admin_surface: bool = False
    sensitive_surface: bool = False
    can_modify_data: bool = False
    publicly_accessible: bool = False
    error: str | None = None


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value:
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _extract_attr(tag: str, attr_name: str) -> str:
    pattern = rf'{attr_name}\s*=\s*["\']([^"\']+)["\']'
    match = re.search(pattern, tag, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_forms(html: str) -> tuple[list[str], list[str], list[str], list[str]]:
    methods: list[str] = []
    actions: list[str] = []
    input_names: list[str] = []
    input_types: list[str] = []

    for form_match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
        form_attrs, form_body = form_match.groups()
        method = (_extract_attr(form_attrs, "method") or "GET").upper()
        action = _extract_attr(form_attrs, "action")
        methods.append(method)
        if action:
            actions.append(action)

        for input_match in re.finditer(r"<(input|textarea|select)\b([^>]*)>", form_body, re.IGNORECASE):
            _, input_attrs = input_match.groups()
            input_name = _extract_attr(input_attrs, "name")
            input_type = (_extract_attr(input_attrs, "type") or "text").lower()
            if input_name:
                input_names.append(input_name)
            input_types.append(input_type)

    return (
        _dedupe(methods),
        _dedupe(actions),
        _dedupe(input_names),
        _dedupe(input_types),
    )


def _extract_script_methods(html: str) -> list[str]:
    matches = re.findall(r'method\s*:\s*["\'](post|put|patch|delete)["\']', html, re.IGNORECASE)
    return _dedupe(match.upper() for match in matches)


def _extract_page_title(html: str) -> str:
    match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def describe_endpoint(context: EndpointContext) -> str:
    """Build a compact endpoint summary for finding descriptions."""
    surface_parts: list[str] = []
    if context.admin_surface:
        surface_parts.append("admin")
    if context.login_surface:
        surface_parts.append("login/auth")
    if context.sensitive_surface and not surface_parts:
        surface_parts.append("sensitive")
    if not surface_parts:
        surface_parts.append("general")

    access = "publicly accessible" if context.publicly_accessible else "auth-protected or redirected"
    methods = ", ".join(context.methods[:4]) if context.methods else "GET"
    inputs = ", ".join(context.input_names[:6]) if context.input_names else "no named inputs detected"
    actions = ", ".join(context.actions[:4]) if context.actions else "no explicit actions detected"
    return (
        f"Endpoint analysis for {context.url}: {'/'.join(surface_parts)} surface, {access}, "
        f"observed methods {methods}, inputs {inputs}, actions {actions}."
    )


def _has_state_changing_methods(context: EndpointContext) -> bool:
    return any(method in context.methods for method in ("POST", "PUT", "PATCH", "DELETE"))


def describe_attacker_impact(context: EndpointContext, *, include_state_change: bool = True) -> str:
    """Describe what an attacker could realistically do on this endpoint."""
    impacts: list[str] = []
    if context.admin_surface:
        impacts.append("reach administrative functionality")
    if include_state_change and _has_state_changing_methods(context):
        impacts.append("submit state-changing requests")
    if context.input_names:
        impacts.append(f"tamper with fields such as {', '.join(context.input_names[:4])}")
    if context.login_surface:
        impacts.append("target credentials or session handling")
    if not impacts:
        impacts.append("interact with the rendered page content")
    return "Attackers could " + ", ".join(impacts) + "."


def apply_context_to_finding(finding: Finding, context: EndpointContext | None) -> Finding:
    """Add URL-specific context and apply documented minimum severity floors only."""
    if not context:
        return finding

    endpoint_summary = describe_endpoint(context)
    attacker_impact = describe_attacker_impact(
        context,
        include_state_change=finding.severity != FindingSeverity.INFO,
    )

    if endpoint_summary not in finding.description:
        finding.description = f"{finding.description}\n\n{endpoint_summary}"
    if attacker_impact not in finding.impact:
        finding.impact = f"{finding.impact} {attacker_impact}".strip()
    if attacker_impact not in (finding.attack_scenario or ""):
        prefix = f"{finding.attack_scenario}\n\n" if finding.attack_scenario else ""
        finding.attack_scenario = f"{prefix}{attacker_impact}"

    combined_text = " ".join(
        [
            finding.title.lower(),
            finding.description.lower(),
            finding.impact.lower(),
            (finding.attack_scenario or "").lower(),
        ]
    )

    is_xss = any(token in combined_text for token in ("xss", "cross-site scripting", "script injection"))
    if is_xss:
        if context.admin_surface or context.login_surface:
            if finding.severity in (FindingSeverity.INFO, FindingSeverity.LOW, FindingSeverity.MEDIUM):
                finding.severity = FindingSeverity.HIGH
                logger.info("Raised XSS severity to HIGH due to privileged/authenticated surface: %s", context.url)
        elif finding.severity in (FindingSeverity.INFO, FindingSeverity.LOW):
            finding.severity = FindingSeverity.MEDIUM
            logger.info("Raised XSS severity to MEDIUM to enforce minimum XSS floor: %s", context.url)

    is_clickjacking = any(
        token in combined_text
        for token in ("clickjacking", "x-frame-options", "frame-ancestors", "content security policy")
    )
    if is_clickjacking:
        if context.admin_surface:
            finding.severity = FindingSeverity.HIGH
        elif context.login_surface or context.sensitive_surface:
            if finding.severity in (FindingSeverity.INFO, FindingSeverity.LOW):
                finding.severity = FindingSeverity.MEDIUM

    return finding


def build_auth_exposure_findings(contexts: Iterable[EndpointContext], tool_name: str) -> list[Finding]:
    """Create authentication/access-control findings from endpoint analysis."""
    findings: list[Finding] = []

    for context in contexts:
        if not context.publicly_accessible or context.login_surface:
            continue
        if not (context.admin_surface or context.sensitive_surface):
            continue

        title = "Administrative Interface Accessible Without Authentication"
        if not context.admin_surface:
            title = "Authenticated Surface Accessible Without Authentication"

        description = (
            f"The endpoint {context.url} appears to expose a protected surface without redirecting "
            f"to login or returning an authentication challenge. {describe_endpoint(context)}"
        )
        impact = describe_attacker_impact(context)
        recommendation = (
            "Require server-side authentication and authorization before rendering this route or "
            "processing any privileged action. Do not rely on client-side guards for admin or user-only pages."
        )
        findings.append(
            Finding(
                title=title,
                severity=FindingSeverity.CRITICAL,
                category=FindingCategory.WEB,
                confidence=FindingConfidence.MEDIUM,
                description=description,
                evidence=Evidence(
                    tool=tool_name,
                    file_path=context.url,
                    snippet=describe_endpoint(context),
                ),
                impact=impact,
                attack_scenario=(
                    f"An unauthenticated user can browse directly to {context.url} and access functionality "
                    f"that should be restricted. {impact}"
                ),
                recommendation=recommendation,
                references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            )
        )

    return findings


async def analyze_urls(urls: Iterable[str]) -> dict[str, EndpointContext]:
    """Fetch and analyze each URL independently for endpoint-aware findings."""
    unique_urls = _dedupe(url for url in urls if url)
    if not unique_urls:
        return {}

    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=False) as client:
        tasks = [_analyze_url(client, url) for url in unique_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    contexts: dict[str, EndpointContext] = {}
    for url, result in zip(unique_urls, results):
        if isinstance(result, Exception):
            contexts[url] = EndpointContext(url=url, final_url=url, status_code=0, error=str(result))
        else:
            contexts[url] = result
    return contexts


async def _analyze_url(client: httpx.AsyncClient, url: str) -> EndpointContext:
    response = await client.get(url)
    content_type = response.headers.get("content-type", "").lower()
    body = response.text if ("html" in content_type or "<html" in response.text.lower()) else ""
    body_lower = body.lower()
    parsed = urlparse(str(response.url))
    path_blob = f"{parsed.path} {parsed.query}".lower()
    methods, actions, input_names, input_types = _extract_forms(body)
    methods.extend(method for method in _extract_script_methods(body) if method not in methods)
    actions = _dedupe(actions)
    input_names = _dedupe(input_names)
    input_types = _dedupe(input_types)

    login_surface = any(keyword in path_blob for keyword in LOGIN_PATH_KEYWORDS)
    if not login_surface and "password" in input_types and any(kind in input_types for kind in ("email", "text")):
        login_surface = True

    admin_surface = any(keyword in path_blob for keyword in PROTECTED_PATH_KEYWORDS)
    if not admin_surface:
        admin_surface = any(keyword in body_lower for keyword in ADMIN_BODY_KEYWORDS)

    auth_wall_detected = response.status_code in (401, 403) or any(
        keyword in body_lower for keyword in AUTH_WALL_KEYWORDS
    )
    if response.history:
        auth_wall_detected = auth_wall_detected or any(
            any(keyword in str(item.headers.get("location", "")).lower() for keyword in LOGIN_PATH_KEYWORDS)
            for item in response.history
        )
    if not auth_wall_detected and login_surface and response.status_code in (200, 301, 302):
        auth_wall_detected = False

    actions.extend(
        action
        for action in STATE_CHANGE_KEYWORDS
        if action in body_lower and action not in actions
    )
    can_modify_data = any(method in methods for method in ("POST", "PUT", "PATCH", "DELETE"))
    sensitive_surface = admin_surface or any(
        keyword in path_blob
        for keyword in ("password", "account", "settings", "profile", "billing", "checkout", "payment")
    )
    publicly_accessible = response.status_code < 400 and not auth_wall_detected

    return EndpointContext(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        page_title=_extract_page_title(body),
        methods=methods,
        input_names=input_names,
        input_types=input_types,
        actions=actions,
        auth_wall_detected=auth_wall_detected,
        login_surface=login_surface,
        admin_surface=admin_surface,
        sensitive_surface=sensitive_surface,
        can_modify_data=can_modify_data,
        publicly_accessible=publicly_accessible,
    )