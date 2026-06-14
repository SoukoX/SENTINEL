<div align="center">
  <h1>SENTINEL</h1>
  <p><strong>Uncensored AI Cybersecurity Agent</strong></p>
  <p>48 tools · 13-stage pipeline · AI-powered · Self-healing · Local</p>
</div>

---

## Install

```bash
curl -sL https://raw.githubusercontent.com/SoukoX/SENTINEL/main/install.sh | bash
```

**No Python required.** Single binary downloads from GitHub Releases.

---

## Usage

```bash
sentinel
# Open http://localhost:8766
```

Chat interface — type a target, SENTINEL runs the full pipeline with real-time progress.

---

## Features

- **Uncensored** — no restrictions, no gatekeeping
- **48 security tools** — recon to exploitation
- **13-stage pipeline** — resumable, self-healing
- **AI explanations** — every finding in plain language
- **Persistent memory** — learns from every scan
- **Fully local** — zero telemetry, no data leaves your machine
- **Free AI backends** — Ollama, Cerebras, OpenRouter, OpenCode

---

## External Tools

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
# nmap: sudo pacman -S nmap  (Arch)  or  sudo apt install nmap  (Debian)
```

---

## Legal

Only scan targets you have written authorization to test.
