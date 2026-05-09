"""Language helpers for consistent localized report content."""

from __future__ import annotations

from typing import Any

from packages.core.models import Finding
from packages.reporter.knowledge_base import KnowledgeBase

_LANG_ALIASES = {
    "en": "en",
    "en-us": "en",
    "en-gb": "en",
    "no": "no",
    "nb": "no",
    "nn": "no",
    "nb-no": "no",
    "nn-no": "no",
    "no-no": "no",
}


def normalize_language(lang: str | None) -> str:
    """Normalize language code to supported values: en/no."""
    if not lang:
        return "en"
    normalized = lang.strip().lower().replace("_", "-")
    return _LANG_ALIASES.get(normalized, "en")


def _human_topic(finding: Finding, lang: str) -> str:
    topic = KnowledgeBase._detect_topic(finding)
    if lang == "no":
        mapping = {
            "sql_injection": "SQL-injeksjon",
            "xss": "skriptinjeksjon (XSS)",
            "secrets": "eksponerte hemmeligheter",
            "command_injection": "kommandoinjeksjon",
            "dependency": "sårbar avhengighet",
        }
        return mapping.get(topic or "", "en sikkerhetssvakhet")

    mapping = {
        "sql_injection": "SQL injection",
        "xss": "cross-site scripting (XSS)",
        "secrets": "exposed secrets",
        "command_injection": "command injection",
        "dependency": "vulnerable dependency",
    }
    return mapping.get(topic or "", "a security weakness")


def _fallback_content(finding: Finding, lang: str) -> dict[str, str]:
    severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    topic = _human_topic(finding, lang)

    if lang == "no":
        impact_map = {
            "critical": "Kritisk risiko: Dette kan gi full kompromittering av system eller data.",
            "high": "Høy risiko: Dette kan gi uautorisert tilgang, datatyveri eller konto-overtakelse.",
            "medium": "Moderat risiko: Dette bør utbedres for å redusere angrepsflaten.",
            "low": "Lav risiko: Dette er som regel hardening og bør planlegges utbedret.",
            "info": "Informasjon: Dette er et observasjonsfunn som bør vurderes manuelt.",
        }
        return {
            "title": finding.title,
            "description": f"Dette funnet handler om {topic}. Bekreft først om funnet er relevant i din applikasjon.",
            "impact": impact_map.get(severity, impact_map["medium"]),
            "recommendation": (
                "1. Verifiser funnet manuelt i aktuell kode eller endpoint.\n"
                "2. Utbedre koden eller konfigurasjonen på stedet funnet peker til.\n"
                "3. Kjør en ny skanning for å bekrefte at problemet er løst."
            ),
            "attack_scenario": (
                "En angriper kan prøve ulike input eller forespørsler mot denne delen av systemet. "
                "Hvis validering/beskyttelse mangler, kan angriperen utnytte svakheten."
            ),
        }

    impact_map = {
        "critical": "Critical risk: This can lead to full system or data compromise.",
        "high": "High risk: This can lead to unauthorized access, data theft, or account takeover.",
        "medium": "Moderate risk: This should be fixed to reduce attack surface.",
        "low": "Low risk: This is usually hardening and should be addressed in planning.",
        "info": "Informational: This is an observation that should be reviewed manually.",
    }
    return {
        "title": finding.title,
        "description": f"This finding is about {topic}. First confirm whether it is relevant in your application.",
        "impact": impact_map.get(severity, impact_map["medium"]),
        "recommendation": (
            "1. Manually verify the finding in the referenced code or endpoint.\n"
            "2. Fix the specific code or configuration issue.\n"
            "3. Run a new scan to confirm the issue is resolved."
        ),
        "attack_scenario": (
            "An attacker can try crafted input or requests against this part of the system. "
            "If validation or protections are missing, the weakness may be exploited."
        ),
    }


def get_localized_finding_content(finding: Finding, lang: str | None) -> dict[str, str]:
    """Return finding content localized to selected language with simple wording."""
    selected_lang = normalize_language(lang)
    kb_content = KnowledgeBase.get_content(finding, selected_lang)
    fallback = _fallback_content(finding, selected_lang)

    return {
        "title": kb_content.get("title", fallback["title"]),
        "description": kb_content.get("description", fallback["description"]),
        "impact": kb_content.get("impact", fallback["impact"]),
        "recommendation": kb_content.get("recommendation", fallback["recommendation"]),
        "attack_scenario": kb_content.get("attack_scenario", fallback["attack_scenario"]),
    }


def localize_tool_message(message: str, lang: str | None) -> str:
    """Localize common tool status messages."""
    if not message:
        return ""

    selected_lang = normalize_language(lang)
    if selected_lang == "en":
        return message

    text = message
    replacements: list[tuple[str, str]] = [
        ("not installed", "ikke installert"),
        ("not available", "ikke tilgjengelig"),
        ("timed out", "tidsavbrudd"),
        ("failed", "feilet"),
        ("error", "feil"),
        ("permission denied", "mangler tilgang"),
        ("completed", "fullført"),
        ("skipped", "hoppet over"),
    ]
    for src, dst in replacements:
        text = text.replace(src, dst)
        text = text.replace(src.capitalize(), dst.capitalize())
    return text
