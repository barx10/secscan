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

_NORWEGIAN_FINDING_OVERRIDES: dict[str, dict[str, str]] = {
    "privacy policy not found": {
        "title": "Personvernerklæring ikke funnet",
        "description": "Skanningen fant ingen tydelig lenke til personvernerklæring eller privacy policy på de undersøkte sidene.",
        "impact": "HØY: Brukere får ikke tydelig informasjon om hvordan personopplysninger samles inn, brukes, lagres eller deles.",
        "recommendation": (
            "1. Legg inn en tydelig lenke til personvernerklæringen i footer eller hovednavigasjon.\n"
            "2. Beskriv formål, behandlingsgrunnlag, lagringstid, tredjeparter og brukerrettigheter.\n"
            "3. Sørg for at erklæringen er enkel å finne fra alle relevante sider."
        ),
        "attack_scenario": "En bruker, kunde eller revisor finner ikke informasjon om behandlingen av personopplysninger og kan derfor ikke forstå eller kontrollere hvordan data brukes.",
    },
    "privacy contact information missing": {
        "title": "Kontaktinformasjon for personvern mangler",
        "description": "Skanningen fant ingen tydelig personvernkontakt, DPO-adresse eller annen kontaktkanal for personvernhenvendelser.",
        "impact": "MEDIUM: Brukere vet ikke hvor de skal sende forespørsler om innsyn, sletting eller andre GDPR-rettigheter.",
        "recommendation": (
            "1. Publiser en tydelig kontaktadresse for personvern eller personvernombud.\n"
            "2. Legg kontaktinformasjonen i personvernerklæringen og gjerne også i footer.\n"
            "3. Beskriv hvordan brukere kan sende forespørsler og hvor raskt de får svar."
        ),
        "attack_scenario": "En bruker prøver å utøve sine rettigheter, men finner ingen tydelig kontaktkanal for personvernrelaterte henvendelser.",
    },
    "terms and conditions not found": {
        "title": "Vilkår og betingelser ikke funnet",
        "description": "Skanningen kunne ikke bekrefte at nettstedet lenker til vilkår, bruksvilkår eller terms and conditions.",
        "impact": "LAV: Brukere kan mangle kontraktsmessig informasjon om bruk av tjenesten, ansvar og vilkår.",
        "recommendation": (
            "1. Legg inn en tydelig lenke til vilkår eller bruksvilkår.\n"
            "2. Sørg for at siden er tilgjengelig fra relevante innloggings- og registreringsflater.\n"
            "3. Hold vilkårene oppdatert og konsistente med personvernerklæringen."
        ),
        "attack_scenario": "En bruker registrerer seg eller tar i bruk tjenesten uten å finne tydelige vilkår for bruk, ansvar og behandlingsforhold.",
    },
    "missing anti-clickjacking header": {
        "title": "Manglende anti-clickjacking-header",
        "description": "Svaret mangler beskyttelse mot clickjacking. Siden bør sende enten Content-Security-Policy med `frame-ancestors` eller `X-Frame-Options`.",
        "impact": "MEDIUM: En angriper kan forsøke å laste siden i en skjult frame og lure brukeren til å klikke på handlinger de ikke forstår.",
        "recommendation": (
            "1. Sett `Content-Security-Policy: frame-ancestors` eller `X-Frame-Options`.\n"
            "2. Bruk `DENY` hvis siden aldri skal vises i frame, eller `SAMEORIGIN` hvis det er et legitimt behov.\n"
            "3. Kontroller at beskyttelsen er aktiv på alle relevante sider."
        ),
        "attack_scenario": "En angriper bygger en side som legger applikasjonen i en usynlig frame og lokker brukeren til å klikke på skjulte knapper eller handlinger.",
    },
    "content security policy (csp) header not set": {
        "title": "Content-Security-Policy-header mangler",
        "description": "Siden sender ikke Content-Security-Policy-headeren. Denne headeren begrenser hvilke skript, stiler, bilder og andre ressurser nettleseren får laste.",
        "impact": "LAV: Manglende CSP gjør det enklere å utnytte XSS og andre innholdsbaserte angrep dersom en annen svakhet finnes.",
        "recommendation": (
            "1. Innfør en streng Content-Security-Policy for nettstedet.\n"
            "2. Begrens `script-src`, `style-src`, `img-src` og andre kilder til det som faktisk brukes.\n"
            "3. Rull ut policyen gradvis med rapportering før streng håndheving hvis nødvendig."
        ),
        "attack_scenario": "Hvis en angriper finner et sted å injisere innhold, vil manglende CSP gjøre det lettere å få nettleseren til å kjøre uønsket kode.",
    },
    "x-content-type-options header missing": {
        "title": "X-Content-Type-Options-header mangler",
        "description": "Applikasjonen setter ikke `X-Content-Type-Options: nosniff`. Da kan enkelte nettlesere forsøke å gjette innholdstype i stedet for å stole på deklarert type.",
        "impact": "LAV: Dette kan gjøre det lettere for enkelte nettlesere å tolke innhold på en uønsket måte.",
        "recommendation": (
            "1. Sett `X-Content-Type-Options: nosniff` på alle HTML-, script- og andre relevante responser.\n"
            "2. Sørg samtidig for at `Content-Type` alltid settes korrekt.\n"
            "3. Verifiser headerne med en ny skanning etter endring."
        ),
        "attack_scenario": "En nettleser gjetter feil innholdstype for en respons, og dette kan åpne for uønsket tolkning av innholdet.",
    },
    "modern web application": {
        "title": "Moderne webapplikasjon",
        "description": "Applikasjonen ser ut til å være en moderne webapplikasjon med dynamisk frontend. Dette er et informasjonsfunn fra skanneren.",
        "impact": "INFORMASJON: Dette er i seg selv ikke et sikkerhetsproblem, men forteller hvordan applikasjonen oppfører seg teknisk.",
        "recommendation": "Ingen direkte endring er nødvendig. Bruk funnet som kontekst dersom du vil kjøre mer målrettet dynamisk testing.",
        "attack_scenario": "Ingen direkte angrepsbane følger av dette alene; funnet beskriver bare applikasjonstypen.",
    },
    "byok architecture detected – verify keys stay client-side": {
        "title": "BYOK-arkitektur oppdaget – bekreft at ingen nøkler sendes til server",
        "description": "Applikasjonen ser ut til å bruke BYOK-modell (Bring Your Own Key). Det ble ikke observert vanlig innlogging eller tydelig server-side autentisering, eller brukergrensesnittet ber brukeren oppgi API-nøkkel direkte.",
        "impact": "LAV: Klassiske konto- og slettingsfunn kan være mindre relevante, men det må bekreftes at nøkler ikke lekker til backend, logger eller tredjeparter.",
        "recommendation": "Bekreft at API-nøkler forblir på klientsiden, ikke logges server-side, og bare sendes til backend hvis dette er eksplisitt dokumentert og nødvendig.",
        "attack_scenario": "En feilimplementert BYOK-flyt kan føre til at klientnøkler sendes til backend eller havner i logger, telemetri eller tredjepartsintegrasjoner uten at dette er tydelig dokumentert.",
    },
    "api key stored in localstorage": {
        "title": "API-nøkkel i localStorage – XSS-eksponering",
        "description": "En API-nøkkel ser ut til å være lagret i localStorage. localStorage er tilgjengelig for alt JavaScript på siden, så et XSS-angrep kan eksfiltrere nøkkelen. Risikoen reduseres hvis CSP er satt, men lagringsmønsteret er fortsatt eksponert.",
        "impact": "MEDIUM: En angriper som oppnår script-kjøring i nettleseren kan hente ut nøkkelen og bruke den utenfor applikasjonen.",
        "recommendation": "Vurder sessionStorage for kortere levetid, eller krypter nøkkelen med Web Crypto API før lagring. Kombiner dette med CSP-herding og nøkkelrotasjon.",
        "attack_scenario": "En angriper finner XSS på en side, leser API-nøkkelen fra localStorage og sender den til et eksternt endepunkt for videre misbruk.",
    },
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
            "privacy_rights": "manglende brukerrettigheter",
            "command_injection": "kommandoinjeksjon",
            "dependency": "sårbar avhengighet",
        }
        return mapping.get(topic or "", "en sikkerhetssvakhet")

    mapping = {
        "sql_injection": "SQL injection",
        "xss": "cross-site scripting (XSS)",
        "secrets": "exposed secrets",
        "privacy_rights": "missing privacy rights controls",
        "command_injection": "command injection",
        "dependency": "vulnerable dependency",
    }
    return mapping.get(topic or "", "a security weakness")


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _localized_override_content(finding: Finding, lang: str) -> dict[str, str]:
    if lang != "no":
        return {}
    title_key = finding.title.strip().lower()
    description_lower = finding.description.lower()

    if title_key == "content security policy (csp) header not set" and "byok context:" in description_lower:
        return {
            "title": "Content-Security-Policy-header mangler",
            "description": "Siden sender ikke Content-Security-Policy-headeren. I denne BYOK-applikasjonen ser det også ut til at API-nøkkel lagres i localStorage, så manglende CSP gjør et eventuelt XSS-funn mer alvorlig fordi nøkkelen kan leses direkte av injisert JavaScript.",
            "impact": "MEDIUM: Manglende CSP øker XSS-risikoen rundt API-nøkkelen som ligger i nettleseren, og gjør nøkkeltyveri lettere dersom angriperen får script-kjøring.",
            "recommendation": (
                "1. Prioriter en streng Content-Security-Policy for nettstedet først.\n"
                "2. Begrens `script-src`, `connect-src` og andre kilder til eksplisitt godkjente domener.\n"
                "3. Reduser deretter videre eksponering ved å revurdere lagring av nøkkel i localStorage og innføre nøkkelrotasjon."
            ),
            "attack_scenario": "En angriper finner en XSS-vei, leser API-nøkkelen fra localStorage og sender den ut av applikasjonen fordi nettleseren mangler CSP som kunne ha begrenset script-kjøring eller eksfiltrasjon.",
        }

    if title_key == "privacy contact information missing" and "byok context:" in description_lower:
        return {
            "title": "Kontaktinformasjon for personvern mangler",
            "description": "Skanningen fant ingen tydelig personvernkontakt, DPO-adresse eller annen kontaktkanal for personvernhenvendelser. Dette er fortsatt relevant for en BYOK-app uten kontoer fordi hosting, logger, reverse proxy, feilsøking eller andre tredjeparter kan behandle IP-adresser og diagnostiske metadata.",
            "impact": "MEDIUM: Brukere mangler et tydelig kontaktpunkt for spørsmål om logger, metadata, underleverandører, overføringer eller andre personvernforhold som fortsatt kan gjelde i en BYOK-løsning.",
            "recommendation": (
                "1. Publiser en tydelig kontaktadresse for personvern eller personvernombud.\n"
                "2. Beskriv hvilke drifts- eller tredjepartsleverandører som kan motta metadata selv om appen ikke har tradisjonelle brukerkontoer.\n"
                "3. Legg kontaktinformasjonen i personvernerklæringen og gjerne også i footer."
            ),
            "attack_scenario": "En bruker ønsker å spørre om logger, diagnostikk eller tredjepartsbehandling, men finner ingen tydelig kanal for personvernrelaterte henvendelser.",
        }

    return _NORWEGIAN_FINDING_OVERRIDES.get(title_key, {})


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
    override_content = _localized_override_content(finding, selected_lang)
    kb_content = KnowledgeBase.get_content(finding, selected_lang)
    fallback = _fallback_content(finding, selected_lang)

    return {
        "title": _first_non_empty(
            override_content.get("title"),
            finding.title,
            kb_content.get("title"),
            fallback["title"],
        ),
        "description": _first_non_empty(
            override_content.get("description"),
            finding.description,
            kb_content.get("description"),
            fallback["description"],
        ),
        "impact": _first_non_empty(
            override_content.get("impact"),
            finding.impact,
            kb_content.get("impact"),
            fallback["impact"],
        ),
        "recommendation": _first_non_empty(
            override_content.get("recommendation"),
            finding.recommendation,
            kb_content.get("recommendation"),
            fallback["recommendation"],
        ),
        "attack_scenario": _first_non_empty(
            override_content.get("attack_scenario"),
            finding.attack_scenario,
            kb_content.get("attack_scenario"),
            fallback["attack_scenario"],
        ),
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
