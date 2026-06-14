# SENTINEL — AI-Powered Cybersecurity Intelligence Platform

SENTINEL orchestrates 50+ security tools across a resumable 13-stage pipeline, explains every finding in plain language via AI, and learns from every scan through persistent memory.

**100% local · Zero telemetry · Free AI backends (Ollama/Gemini/Groq/OpenRouter)**

## Quick Start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Start the daemon
python3 server.py

# 3. Open the UI
open http://localhost:8766

# Or run a headless scan:
python3 agent.py example.com
```

## CLI Usage

```bash
python3 agent.py <target> [options]

Options:
  --severity <list>       critical,high,medium (default)
  --stages <list>         Comma-separated stages (default: all)
  --enable-intrusive      Enable SQLMap, Nikto, SSTI scanners
  --ai-delay <seconds>    Add delay between AI calls (avoid rate limits)
  --no-ai                 Disable AI analysis
  --skip-check            Skip tool availability check
  --output-dir <path>     Output directory (default: ~/.sentinel/scans/)
  -y                      Auto-accept legal disclaimer (CI/headless mode)
```

## Pipeline Stages

| Stage | Tools | Description |
|-------|-------|-------------|
| VALIDATE | — | Target validation, scope check, legal disclaimer |
| RECON | subfinder, amass, assetfinder, dnsx | Subdomain enumeration + DNS resolution |
| PROBE | httpx | Live host detection, status codes, tech fingerprint |
| CRAWL | katana, gospider, gau, waybackurls | URL discovery from crawling + archives |
| FUZZ | ffuf, feroxbuster | Directory, parameter and vhost fuzzing |
| PORTSCAN | nmap, masscan, rustscan | Fast port and service discovery |
| SCAN | nuclei, dalfox | Template-based vulnerability scanning |
| INJECT | sqlmap, nikto, commix, ssrfmap | Intrusive injection testing (opt-in) |
| SECRETS | trufflehog, gitleaks | Secret and credential exposure scanning |
| CLOUD | s3scanner | Cloud/S3 misconfiguration checks |
| PROTO | testssl, smuggler | SSL/TLS, HTTP smuggling, WebSocket |
| AI_ENRICH | — | AI explanations, PoC, remediation per finding |
| REPORT | — | Markdown + HTML + JSON + CSV report generation |

## AI Backends (all free)

Priority cascade: **Ollama (local) → Gemini → Groq → OpenRouter → None**

```bash
# Ollama (recommended — fully private)
ollama pull mistral

# Gemini (Google free tier, 1500 req/day)
export GEMINI_API_KEY="your_key"
# Get key: https://aistudio.google.com/apikey

# Groq (free tier, fast inference)
export GROQ_API_KEY="your_key"

# OpenRouter (multi-model free tier)
export OPENROUTER_API_KEY="your_key"
```

## Required External Tools

SENTINEL orchestrates 7+ external tools that must be installed separately.
The agent checks for these at startup and warns if any are missing.

### Core Tools (required for full pipeline)

| Tool | Purpose | Install |
|------|---------|---------|
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host detection & tech fingerprint | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [ffuf](https://github.com/ffuf/ffuf) | Directory & parameter fuzzing | `go install -v github.com/ffuf/ffuf/v2@latest` |
| [katana](https://github.com/projectdiscovery/katana) | Web crawling | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| [nmap](https://nmap.org) | Port & service discovery | `sudo apt install nmap` |
| [gospider](https://github.com/jaeles-project/gospider) | Spider/crawler | `go install -v github.com/jaeles-project/gospider@latest` |

### Optional but Recommended

| Tool | Purpose | Install |
|------|---------|---------|
| [dalfox](https://github.com/hahwul/dalfox) | XSS scanner | `go install -v github.com/hahwul/dalfox/v2@latest` |
| [gau](https://github.com/lc/gau) | URL discovery from archives | `go install -v github.com/lc/gau/v2/cmd/gau@latest` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanning | `go install -v github.com/gitleaks/gitleaks/v8@latest` |
| [Amass](https://github.com/OWASP/Amass) | Advanced subdomain enum | `go install -v github.com/OWASP/Amass/v4/...@master` |
| [sqlmap](https://sqlmap.org) | SQL injection testing (intrusive) | `sudo apt install sqlmap` |

### Wordlists

```bash
sudo apt install seclists   # or download from: https://github.com/danielmiessler/SecLists
```

### Verify Installation

```bash
python3 agent.py --skip-check  # skips tool check
# or just run and SENTINEL will report missing tools
```

## Configuration

Copy the example config:

```bash
mkdir -p ~/.sentinel
cp config.example.toml ~/.sentinel/config.toml
# Edit to customize
```

Environment variables override the config file:

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_DIR` | `~/.sentinel` | Data directory for scans, DB, config |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `GROQ_API_KEY` | — | Groq API key |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `WS_HOST` | `127.0.0.1` | WebSocket bind address |
| `HTTP_HOST` | `127.0.0.1` | HTTP bind address |
| `SENTINEL_WORDLIST` | — | Path to custom wordlist for fuzzing |
| `SECLISTS_HOME` | `/usr/share/seclists` | SecLists installation directory |

## Output

Per-scan directory: `~/.sentinel/scans/{target}_{timestamp}/`

- `findings.db` — All findings in SQLite
- `scan_state.json` — Current stage for resume support
- `report_{timestamp}.md` — Markdown report
- `stage_outputs/` — Raw tool output per stage

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design document covering:
- Memory & learning system (4-layer architecture)
- Tool orchestration and plugin system
- Privacy engine (scope enforcer, PII scrubber, retention)
- AI backend abstraction and prompt library
- Report engine (Markdown, HTML, JSON, CSV, PDF)

## Legal

Only scan targets you have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions.
