<div align="center">
  <h1>SENTINEL</h1>
  <p><strong>Uncensored AI Cybersecurity Agent</strong></p>
  <p>
    <a href="https://github.com/SoukoX/SENTINEL/releases"><img src="https://img.shields.io/github/v/release/SoukoX/SENTINEL?style=flat-square" alt="Release"></a>
    <a href="https://github.com/SoukoX/SENTINEL/stargazers"><img src="https://img.shields.io/github/stars/SoukoX/SENTINEL?style=flat-square" alt="Stars"></a>
    <a href="https://github.com/SoukoX/SENTINEL/issues"><img src="https://img.shields.io/github/issues/SoukoX/SENTINEL?style=flat-square" alt="Issues"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
    <a href="https://github.com/SoukoX/SENTINEL/actions"><img src="https://img.shields.io/github/actions/workflow/status/SoukoX/SENTINEL/build.yml?style=flat-square" alt="Build"></a>
  </p>
  <p>
    <code>curl -sL https://raw.githubusercontent.com/SoukoX/SENTINEL/main/install.sh | bash</code>
  </p>
  <p><strong>One command. Zero dependencies. Full AI-powered pentesting.</strong></p>
</div>

---

## Why SENTINEL?

Most security tools are dumb — they scan, dump results, and make you dig through raw output. 
SENTINEL is an **AI-native agent** that thinks, explains, and adapts.

| Problem | SENTINEL Solution |
|---------|-------------------|
| Raw tool output you have to interpret | **AI explains every finding** in plain English with remediation steps |
| Tedious multi-tool workflows | **48 tools orchestrated** across a single 13-stage pipeline |
| Brittle scanners that fail silently | **Self-healing pipeline** — resumes from failures, not from scratch |
| Your data leaves your machine | **100% local** — zero telemetry, no cloud dependency |
| Expensive AI subscriptions | **Free backends** — Ollama, Cerebras, OpenRouter, OpenCode |
| Restrictive "ethics" filters | **Uncensored** — no gatekeeping, no refusal |

---

## Features

|  |  |  |
|---|---|---|
| **🧠 AI-Native Intelligence** | **⚡ 48 Tools, One Pipeline** | **🔄 Self-Healing** |
| Natural language chat interface | Recon → exploitation → reporting | Crashes don't kill your scan |
| AI generates & interprets commands | AI orchestrates every tool | Auto-retry, adapt, resume |
| Learns from every scan | No scripting glue needed | Interrupt & continue later |
| **🔒 Zero Trust Architecture** | **💸 Free AI Backends** | **🚀 One-Click Install** |
| 100% local, zero telemetry | Ollama, Cerebras, OpenRouter, OpenCode | Single binary, no Python |
| No API keys required | All free tiers, no subscription | `curl ... \| bash` and done |
| Your data never leaves | Works offline with Ollama | Works on Linux & macOS |

---

## Quick Start

```bash
# Install (single binary, no Python required)
curl -sL https://raw.githubusercontent.com/SoukoX/SENTINEL/main/install.sh | bash

# Run
sentinel

# Open in browser
http://localhost:8766
```

Type a target domain or IP. Watch SENTINEL work through 13 stages in real time.

---

## Pipeline Stages

```
1.  Target Validation       8.  Port Scanning
2.  Passive Recon           9.  Service Fingerprinting
3.  Subdomain Enumeration   10. Vulnerability Scanning
4.  Technology Detection    11. Fuzzing
5.  DNS Enumeration         12. Exploitation
6.  WHOIS / ASN Lookup      13. Reporting & Remediation
7.  Crawling
```

Each stage feeds into the next. AI orchestrates which tools to run and in what order.

---

## Required External Tools

SENTINEL orchestrates these — install them for the full pipeline:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
# nmap: sudo pacman -S nmap  (Arch)  or  sudo apt install nmap  (Debian)
```

---

## Screenshots

<!-- Add screenshots here once available -->

---

## Use Cases

- **Bug bounty hunters** — automate recon and initial exploitation
- **Pentesters** — accelerate assessments with AI-assisted analysis
- **Red teams** — persistent target profiling across engagements
- **Security researchers** — analyze infrastructure at scale
- **CTF players** — automated enumeration with smart explanations

---

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

You don't need to read source code to make SENTINEL better.

### 🐛 Report Bugs
Found a crash, false positive, or weird behavior? [Open an issue](https://github.com/SoukoX/SENTINEL/issues/new?template=bug_report.md) — include your OS, version, and steps to reproduce.

### 💡 Suggest Features
Have an idea for a new tool, pipeline stage, or AI backend? [Open a feature request](https://github.com/SoukoX/SENTINEL/issues/new?template=feature_request.md).

### 📖 Improve Documentation
Fix a typo, add examples, or write a tutorial. Submit a PR against `README.md` or `install.sh`.

### 🎨 UI/Frontend
The web UI lives in `ui/`. Improvements to the interface are always welcome.

### 🌍 Spread the Word
- ⭐ Star the repo
- Share on Twitter / Reddit / LinkedIn
- Write a blog post about your experience
- Mention SENTINEL in your security tool lists

### ☕ Sponsorship
If SENTINEL saves you time or helps your work, consider [sponsoring the project](https://github.com/sponsors/SoukoX).

---

## Community

- [Discussions](https://github.com/SoukoX/SENTINEL/discussions) — ask questions, share findings, connect with users
- [Issues](https://github.com/SoukoX/SENTINEL/issues) — bug reports & feature requests

---

## Legal

Only scan targets you have written authorization to test.
