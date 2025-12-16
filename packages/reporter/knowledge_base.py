"""Security knowledge base for user-friendly explanations."""

from typing import Dict, Any

class KnowledgeBase:
    """Knowledge base for security findings."""

    @staticmethod
    def get_content(finding: Any, lang: str = "en") -> Dict[str, str]:
        """Get user-friendly content for a finding."""
        # Normalize language
        lang = lang.lower() if lang else "en"
        
        # Detect topic based on finding data
        topic = KnowledgeBase._detect_topic(finding)
        
        if not topic or topic not in TOPICS:
            return {}

        content = TOPICS[topic].get(lang, TOPICS[topic]["en"])
        return content

    @staticmethod
    def _detect_topic(finding: Any) -> str | None:
        """Detect the security topic from finding details."""
        text = (f"{finding.title} {finding.description}").lower()
        
        if "sql" in text and "injection" in text:
            return "sql_injection"
        if "xss" in text or "cross-site scripting" in text:
            return "xss"
        if "secret" in text or "credential" in text or "password" in text or "key" in text or "token" in text:
            return "secrets"
        if "command" in text and "injection" in text:
            return "command_injection"
        if "dependency" in text or "vulnerab" in text:
            # Check if it's a dependency issue
            if finding.evidence and finding.evidence.tool == "trivy" and "npm" in str(finding.evidence.raw_output):
                return "dependency"
            if finding.category == "dependencies":
                return "dependency"
                
        return None

TOPICS = {
    "sql_injection": {
        "en": {
            "title": "SQL Injection",
            "description": "The application allows untrusted user input to interfere with database queries. This is like letting a stranger write their own orders in a restaurant kitchen.",
            "impact": "CRITICAL: Attackers can read, modify, or delete your entire database. They can often bypass login screens and take over administrator accounts.",
            "recommendation": (
                "1. **Never** concatenate strings to build SQL queries.\n"
                "2. Use 'parameterized queries' or 'prepared statements'. This ensures user input is treated as text, not code.\n"
                "3. Use an ORM (Object Relational Mapper) if possible, as they handle this protection automatically."
            ),
            "attack_scenario": "1. Attacker finds a search box.\n2. Attacker types `admin' --`.\n3. The database interprets this as: 'Log me in as admin and ignore password'.\n4. Attacker is logged in as admin."
        },
        "no": {
            "title": "SQL-injeksjon (Database-sårbarhet)",
            "description": "Programmet ditt tar imot tekst fra en bruker og sender det rett til databasen uten å sjekke det først. Dette er som å la en fremmed skrive hva de vil i bankboken din.",
            "impact": "KRITISK: En angriper kan stjele alle passord, slette hele databasen, eller logge inn som administrator uten passord.",
            "recommendation": (
                "1. **Aldri** lim sammen tekst for å lage databasespørringer.\n"
                "2. Bruk 'parameterized queries' (forhåndsdefinerte spørringer). Dette forteller databasen hva som er kode og hva som er data.\n"
                "3. Hvis du bruker biblioteker (IRM), sjekk at du bruker funksjonene deres riktig for å hente data."
            ),
            "attack_scenario": "1. Angriper finner et søkefelt på nettsiden.\n2. Angriper skriver inn `admin' --` i feltet.\n3. Databasen tolker dette som: 'Logg meg inn som admin, og ignorer resten av sjekkene (passordet)'.\n4. Angriperen er nå logget inn som sjefen i systemet."
        }
    },
    "xss": {
        "en": {
            "title": "Cross-Site Scripting (XSS)",
            "description": "The application displays user input on a web page without cleaning it first. This allows attackers to run malicious scripts in other users' browsers.",
            "impact": "HIGH: Attackers can steal users' login sessions, hijack accounts, or deface your website.",
            "recommendation": (
                "1. Sanitize all user input before displaying it.\n"
                "2. Use modern frontend frameworks (React, Vue, Angular) which protect against this by default.\n"
                "3. Enable Content Security Policy (CSP) headers to block unauthorized scripts."
            ),
            "attack_scenario": "1. Attacker posts a comment containing `<script>steal_password()</script>`.\n2. Victim views the comment.\n3. Victim's browser runs the code.\n4. Attacker gets the victim's password."
        },
        "no": {
            "title": "Cross-Site Scripting (XSS)",
            "description": "Nettsiden din viser tekst fra brukere direkte uten å 'vaske' den først. Dette gjør at hackere kan lure nettleseren til å kjøre skadelig kode hos dine besøkende.",
            "impact": "HØY: Angripere kan stjele innloggingen til brukerne dine, ta over kontoer, eller endre innholdet på nettsiden din.",
            "recommendation": (
                "1. Sørg for at all tekst fra brukere blir 'vasket' (sanitized) før den vises på skjermen.\n"
                "2. I React: Unngå å bruke `dangerouslySetInnerHTML` med mindre du er 100% sikker.\n"
                "3. Bruk sikkerhetsheadere (CSP) for å nekte ukjente skript å kjøre."
            ),
            "attack_scenario": "1. Angriper legger inn en kommentar som inneholder ondsinnet kode (JavaScript).\n2. En vanlig bruker besøker siden og ser kommentaren.\n3. Brukerens nettleser tror koden er trygg og kjører den.\n4. Koden sender brukerens innloggings-cookie til angriperen."
        }
    },
    "secrets": {
        "en": {
            "title": "Exposed Secrets / Credentials",
            "description": "A password, API key, or token was found directly in the code. Code should be public/shared, secrets must be private.",
            "impact": "CRITICAL: Anyone with access to the code can use these credentials to access your systems, databases, or paid services.",
            "recommendation": (
                "1. **Delete** the secret from the code immediately.\n"
                "2. Rotate (change) the password/key, as it is considered compromised.\n"
                "3. Use 'Environment Variables' (.env files) to store secrets, and do not upload .env files to GitHub."
            ),
            "attack_scenario": "1. Attacker finds `AWS_KEY=12345` in your code on GitHub.\n2. Attacker uses this key to start 1000 expensive servers on your account.\n3. You receive a huge bill."
        },
        "no": {
            "title": "Passord eller nøkler i koden",
            "description": "Vi fant et passord, en API-nøkkel eller en hemmelighet skrevet rett i koden din. Kode deles ofte med andre, men hemmeligheter må holdes skjult.",
            "impact": "KRITISK: Alle som ser koden (eller har tilgang til Git-historikken) kan misbruke disse tilgangene. De kan stjele data eller koste deg penger.",
            "recommendation": (
                "1. **Slett** hemmeligheten fra koden umiddelbart.\n"
                "2. Bytt passordet/nøkkelen med en gang (vi må anta at hackere har sett det).\n"
                "3. Bruk 'Miljøvariabler' (.env filer) for å lagre hemmeligheter lokalt, og ikke last opp disse filene."
            ),
            "attack_scenario": "1. Angriper finner `API_KEY=12345` i koden din på GitHub.\n2. Angriperen bruker nøkkelen til å hente ut alle kundedataene dine.\n3. Angriperen selger dataene på det mørke nettet."
        }
    },
    "dependency": {
        "en": {
            "title": "Vulnerable Software Dependency",
            "description": "You are using a third-party library or package that has known security holes. It's like having a strong door lock but using a broken window.",
            "impact": "VARIES: Depending on the specific flaw, attackers might crash your app or take control of it solely because you use this library.",
            "recommendation": (
                "1. Update the affected library to the 'Fixed Version' detected.\n"
                "2. Run `npm update` or `pip install --upgrade`.\n"
                "3. If no fix exists yet, consider looking for an alternative library."
            ),
            "attack_scenario": "1. A hacker knows that `library-v1.0` has a flaw.\n2. They scan the internet for sites using `library-v1.0`.\n3. They find your site and use a pre-made tool to exploit the flaw."
        },
        "no": {
            "title": "Sårbarhet i programvarebibliotek",
            "description": "Du bruker en ferdig kode-pakke (bibliotek) som har kjente sikkerhetshull. Selv om din kode er trygg, kan denne pakken åpne døren for hackere.",
            "impact": "VARIERER: Avhengig av feilen kan dette føre til alt fra at appen krasjer til at hackere tar over serveren.",
            "recommendation": (
                "1. Oppdater biblioteket til versjonen som er foreslått (Fixed Version).\n"
                "2. Kjør `npm update` eller tilsvarende kommando.\n"
                "3. Sjekk jevnlig for oppdateringer til alle biblioteker du bruker."
            ),
            "attack_scenario": "1. En hacker vet at `pakke-v1.0` har en feil.\n2. De finner ut at du bruker denne pakken.\n3. De sender en spesiell forespørsel som utnytter feilen i pakken for å ta over systemet ditt."
        }
    }
}
