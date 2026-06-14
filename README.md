<div align="center">
  <h1>SENTINEL</h1>
  <p><strong>Uncensored AI Cybersecurity Agent</strong></p>
  <p>48 tools · 13-stage pipeline · AI-powered · Self-healing · Local-first</p>
</div>

---

## Install

```bash
curl -sL https://raw.githubusercontent.com/SoukoX/SENTINEL/main/install.sh | bash
```

**Requirements:** Linux x86_64, Python 3.10+ *(only needed if running from source)*  
**No Python required for the binary.** Just a terminal.

---

## Quick Start

```bash
sentinel example.com                      # Full scan
sentinel example.com --stages recon,scan  # Specific stages
sentinel --help                           # All options
```

---

## Features

- **Uncensored** — no restrictions, no gatekeeping
- **48 security tools** — recon to exploitation
- **13-stage pipeline** — resumable, self-healing
- **AI explanations** — every finding explained in plain language
- **Persistent memory** — learns from every scan
- **Fully local** — zero telemetry, no data leaves your machine
- **Free AI backends** — Ollama, Cerebras, OpenRouter, OpenCode

---

## External Tools

SENTINEL orchestrates 48 tools. Install the core ones:

```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
sudo apt install nmap
```

---

## Configuration

```bash
mkdir -p ~/.sentinel
```

AI keys are set via environment variables:

| Variable | Backend |
|----------|---------|
| `OLLAMA_URL` | Local Ollama (default: http://localhost:11434) |
| `CEREBRAS_API_KEY` | Cerebras |
| `OPENROUTER_API_KEY` | OpenRouter |
| `OPENCODE_API_KEY` | OpenCode Zen |

---

## Legal

Only scan targets you have written authorization to test. Unauthorized scanning is illegal.
