<div align="center">
  <h1>SENTINEL</h1>
  <p><strong>Uncensored AI Cybersecurity Agent</strong></p>
  <p>
    <a href="https://github.com/SoukoX/SENTINEL/releases"><img src="https://img.shields.io/github/v/release/SoukoX/SENTINEL?style=flat-square" alt="Release"></a>
    <a href="https://github.com/SoukoX/SENTINEL/stargazers"><img src="https://img.shields.io/github/stars/SoukoX/SENTINEL?style=flat-square" alt="Stars"></a>
    <a href="https://github.com/SoukoX/SENTINEL/issues"><img src="https://img.shields.io/github/issues/SoukoX/SENTINEL?style=flat-square" alt="Issues"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  </p>
  <p>48 tools · 13-stage pipeline · AI-powered · Self-healing · Local</p>
</div>

---

## Install

```bash
curl -sL https://raw.githubusercontent.com/SoukoX/SENTINEL/main/install.sh | bash
```

**No Python required.** Single binary downloads from [GitHub Releases](https://github.com/SoukoX/SENTINEL/releases).

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

## How to Contribute

You don't need to read source code to make SENTINEL better.

### 🐛 Report Bugs
Found a crash, false positive, or weird behavior? [Open an issue](https://github.com/SoukoX/SENTINEL/issues/new?template=bug_report.md) — include your OS, version, and steps to reproduce.

### 💡 Suggest Features
Have an idea for a new tool, pipeline stage, or AI backend? [Open a feature request](https://github.com/SoukoX/SENTINEL/issues/new?template=feature_request.md).

### 📖 Improve Documentation
Fix a typo, add examples, or write a tutorial. Submit a PR against `README.md` or `install.sh`.

### 🎨 UI/Frontend
The web UI (`ui.html`, `ui_phase2.js`) is part of this repo. Improvements to the interface are always welcome.

### 🌍 Spread the Word
- Star the repo
- Share on Twitter / Reddit / LinkedIn
- Write a blog post about your experience
- Mention SENTINEL in your security tool lists

### 🧪 Test & Report
Try SENTINEL on different targets and environments. Open issues for any edge cases you find.

### ☕ Sponsorship
If SENTINEL saves you time or helps your work, consider [sponsoring the project](https://github.com/sponsors/SoukoX).

---

## Community

- [Discussions](https://github.com/SoukoX/SENTINEL/discussions) — ask questions, share findings, connect with users
- [Issues](https://github.com/SoukoX/SENTINEL/issues) — bug reports & feature requests

---

## Legal

Only scan targets you have written authorization to test.
