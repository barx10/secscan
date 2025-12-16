# SecScan

Security vulnerability scanner for applications and AI-constructed websites.

## Features

- **Secrets Scanning**: Detect hardcoded secrets, API keys, and credentials using gitleaks
- **Dependency Scanning**: Find vulnerable dependencies using osv-scanner and trivy
- **SAST**: Static analysis with semgrep for code vulnerabilities
- **Config Scanning**: Detect misconfigurations in Dockerfiles, Kubernetes manifests, Terraform, etc.
- **Web Scanning**: Baseline web application security scanning with OWASP ZAP
- **SBOM Generation**: Generate Software Bill of Materials with syft

## Quick Start

### Installation

```bash
pip install -e .
```

### Check Available Tools

```bash
secscan check-tools
```

### Scan a Repository

```bash
# Full scan with table output
secscan scan ./my-project

# Generate HTML report
secscan scan ./my-project -f html -o report.html

# Generate JSON report
secscan scan ./my-project -f json -o report.json

# Scan specific types only
secscan scan ./my-project -t secrets -t deps

# Fail on high severity (for CI)
secscan scan ./my-project --fail-on high
```

### Scan a Zip File

```bash
secscan scan ./source.zip -o report.html -f html
```

### Scan a URL

```bash
secscan scan https://example.com -t web
```

## API Usage

Start the API server:

```bash
uvicorn apps.api.main:app --reload
```

### Endpoints

- `POST /scans` - Create a new scan
- `GET /scans/{scan_id}` - Get scan status
- `GET /scans/{scan_id}/report` - Get scan report (JSON)
- `GET /scans/{scan_id}/report.html` - Get scan report (HTML)
- `GET /tools` - List available scanner tools
- `POST /scans/upload` - Upload and scan a zip file

## Configuration

Create `.secscan.yaml` in your project:

```yaml
scan:
  types:
    - secrets
    - deps
    - sast
    - config
  severity_threshold: info
  fail_on_severity: high
  exclude:
    - "**/node_modules/**"
    - "**/venv/**"

tools:
  semgrep:
    rulesets:
      - auto
      - p/security-audit
```

## Required Tools

Install the scanner tools:

| Tool | Installation |
|------|-------------|
| gitleaks | `brew install gitleaks` |
| semgrep | `pip install semgrep` |
| trivy | `brew install trivy` |
| osv-scanner | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| syft | `brew install syft` |
| ZAP | `docker pull ghcr.io/zaproxy/zaproxy:stable` |

## Architecture

```
secscan/
├── apps/
│   ├── api/          # FastAPI web API
│   ├── cli/          # Typer CLI application
│   └── worker/       # Background scan worker
├── packages/
│   ├── core/         # Core models, pipeline, scoring
│   ├── adapters/     # Scanner tool adapters
│   ├── reporter/     # JSON/HTML report generators
│   └── storage/      # SQLite/PostgreSQL storage
└── configs/          # Default configuration
```

## Finding Format

All findings follow a standardized format:

```json
{
  "id": "uuid",
  "title": "SQL Injection in user query",
  "severity": "high",
  "category": "sast",
  "confidence": "high",
  "description": "...",
  "evidence": {
    "tool": "semgrep",
    "file_path": "src/db.py",
    "line_start": 42,
    "snippet": "..."
  },
  "impact": "...",
  "attack_scenario": "...",
  "recommendation": "...",
  "patch": {
    "diff": "..."
  },
  "references": ["..."],
  "risk_score": 85.5
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues meeting threshold |
| 1 | Issues found meeting failure threshold |
| 2 | Scan failed |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy .

# Linting
ruff check .
```

## License

MIT
