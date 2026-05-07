<div align="center">

# CHANNA'S OMNISCAN-AI

### The Ultimate Bug Hunter's Suite

#### Aggressive Infiltration Edition &nbsp;·&nbsp; v2.5

*An async, AI-augmented reconnaissance framework for the modern web-security era.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![asyncio](https://img.shields.io/badge/asyncio-powered-00A1D6)](https://docs.python.org/3/library/asyncio.html)
[![aiohttp](https://img.shields.io/badge/aiohttp-3.9%2B-2C5BB4)](https://docs.aiohttp.org/)
[![Rich UI](https://img.shields.io/badge/UI-Rich-FF4081)](https://rich.readthedocs.io/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.5-success.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

<sub><strong>Secrets</strong> &bull; <strong>Nuclei</strong> &bull; <strong>Subdomains</strong> &bull; <strong>AI-guided XSS</strong> &bull; <strong>AI-Mutator</strong> &bull; <strong>Zero-Day Hunter</strong> &bull; <strong>IDOR</strong> &bull; <strong>Deep JS</strong> &bull; <strong>Cloud / Paths / Ports</strong> &bull; <strong>Dashboard</strong> &bull; <strong>PDF / JSON</strong></sub>

<br/>

<em>Developed by <strong>Channa Sandeepa</strong> &bull; OmniScan-AI v2.5 (Aggressive Infiltration Edition) &bull; &copy; 2026</em>

</div>

---

> [!WARNING]
> ### Responsible Use Disclaimer
>
> **OmniScan-AI is an offensive-security tool intended for authorized testing only.**
>
> - Run it **only** against systems you own or have **explicit, written permission** to test (e.g., an in-scope bug-bounty program or internal staging).
> - `--xss` and `--idor` actively mutate request parameters and send real traffic. Respect rate limits, fragile endpoints, and WAFs.
> - Unauthorized scanning, probing, or exploitation of third-party systems is illegal in most jurisdictions.
> - The author assumes **no liability** for misuse. *Think twice, document your scope, then scan.*

---

## Table of contents

- [Why OmniScan-AI](#why-omniscan-ai)
- [New in v2.5](#new-in-v25)
- [Feature matrix](#feature-matrix)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [CLI flags reference](#cli-flags-reference)
- [Reports](#reports)
- [Project structure](#project-structure)
- [Tech stack](#tech-stack)
- [License & Credits](#license--credits)

---

## Why OmniScan-AI

Traditional recon tools are fast but dumb, or smart but painful to read. **OmniScan-AI** glues them together with three ideas that matter in 2026:

1. **One command, many scanners.** Secrets, deep JS analysis, subdomain recon, reflected XSS, IDOR, cloud exposure, path brute, TCP ports, optional **Nuclei** templates, **Zero-Day Hunter** heuristics, and more run concurrently in a single async pipeline.
2. **AI-guided offense.** The built-in `AIAuditor` ships WAF-bypass mutation logic that rewrites XSS payloads (case mixing, HTML/URL entities, tag splitting, null bytes, SVG/event-handler tricks) before they hit the target — *no external LLM required*. **AI-Mutator** extends this with per-parameter variant rows when slots are discovered.
3. **Professional output.** Every scan can produce branded `.txt`, `.json`, and `.pdf` reports in `reports/<target>/`, with structured sections (including Nuclei) for automation. Your signature is on every page.

---

## New in v2.5

**OmniScan-AI v2.5 — Aggressive Infiltration Edition** adds depth across scanning, mutation, and operations:

| Highlight | What you get |
|-----------|----------------|
| **Nuclei integration** | Advanced vulnerability scanning powered by **[ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei)** and **9,000+** community templates — enable with `--nuclei` (requires the `nuclei` binary on your `PATH`). Results appear in the Rich console, **JSON** (`nuclei_results`), **PDF**, and the live dashboard loot stream. |
| **Zero-Day Hunter** | Heuristic **logic-flaw** and fuzz-style signals via `--zero-day` (authorized targets only; see `--help` and module notes for scope / HWID where applicable). |
| **AI-Mutator** | **`--ai-mutate`** generates smart **WAF-bypass payload variants** from discovered parameter slots (combine with `--params` and/or `--xss`). |
| **Real-time dashboard** | Web-based monitoring with **Flask** and **Socket.IO**: run `python dashboard.py` and open the UI; scan subprocesses use `OMNISCAN_DASHBOARD=1` for structured events, logs, and loot. |
| **Professional reporting** | **Enhanced PDF and JSON** exports — executive summary lines for Nuclei, dedicated PDF section *“Nuclei Vulnerability Scan”*, and richer machine-readable fields for downstream tooling. |

---

## Feature matrix

| # | Module | Flag | What it does | Severity tiers |
|---|--------|------|--------------|----------------|
| 1 | **Secret Finder** | *(always on)* | Async pull of every `<script>` + external JS; regex-scans for AWS, GCP, Firebase, Slack, Stripe, GitHub PATs, Mailgun, Heroku, Twilio, JWTs, private keys, and more. | High / Medium / Low |
| 2 | **Deep JS Analyzer** | `--js` | Concurrently crawls **every** linked JS asset, extracting API endpoints (`fetch`, `axios`, `XMLHttpRequest.open`, raw `/api/*` paths) *and* secrets. | High / Medium / Low |
| 3 | **Subdomain Scanner** | `--subdomain` | Probes a curated wordlist over the apex host, reports `alive`/`status`/`scheme`. | - |
| 4 | **XSS Scanner + AI Mutations** | `--xss` `--ai` | Injects reflected-XSS payloads into GET params and forms. Combine with `--ai` to auto-generate **12 WAF-bypass variants per payload**. | Medium |
| 5 | **IDOR Scanner** | `--idor` | Discovers numeric IDs in query params (`id`, `user_id`, `order_id`, ...) and path segments (`/users/42`). Probes neighbouring IDs and flags **Critical** when HTTP 200 returns different PII (emails, phones, `"name"`/`"email"`/`"username"` fields). | **Critical** / High / Info |
| 6 | **Cloud Scanner** | `--cloud` | Enumerates candidate S3 / Azure Blob / GCS / DigitalOcean Spaces buckets against the target hostname. | High / Medium / Low |
| 7 | **Path Bruter** | `--brute` | Tries sensitive paths (`.git/`, `.env`, `/admin`, backups, CI/CD, debug endpoints). | High / Medium / Low |
| 8 | **Port Scanner** | `--port` | Fast async TCP-connect sweep of a curated common-service port list. | Medium |
| 9 | **AI Auditor** | `--ai` | Renders the prompt-injection playbook for testing AI chat interfaces; also drives the XSS mutation engine. | - |
| 10 | **Nuclei Engine** | `--nuclei` | Invokes the external `nuclei` CLI (JSONL), template-driven findings merged into reports and dashboard loot. | info → critical |
| 11 | **Zero-Day Hunter** | `--zero-day` | Heuristic logic-flaw / fuzz pass (authorized use). | Varies |
| 12 | **AI-Mutator** | `--ai-mutate` | Variant payloads from discovered slots (`--params` / `--xss` workflows). | Varies |
| 13 | **Logic scan** | `--logic-scan` | Lightweight post-pass triage (e.g. IDOR / price-style heuristics from other modules’ signals). | Varies |
| 14 | **PDF Reporter** | `--pdf` | Branded multi-page PDF with your signature in every page header **and** footer. Implicitly enables `--report`. | - |

---

## Installation

> Requires **Python 3.10+**.

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/OmniScan-AI.git
cd OmniScan-AI

# 2. Create an isolated virtual environment (recommended)
python -m venv .venv

# Activate it
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

Dependencies (from `requirements.txt`):

| Library | Purpose |
|---------|---------|
| `aiohttp` | Async HTTP client powering every scanner |
| `beautifulsoup4` | HTML parsing for `<script>`/form discovery |
| `requests` | Legacy sync fallback |
| `rich` | Banner, progress bars, tables, panels |
| `fpdf2` | Branded PDF report generation |
| `flask`, `flask-socketio` | Real-time web dashboard (`dashboard.py`) |

---

## Quick start

```bash
# Minimal: run the secret scanner against one target
python main.py --url example.com

# Strong recon + Nuclei templates + branded exports (Nuclei must be on PATH)
python main.py --url example.com --xss --idor --js --nuclei --report --pdf
```

> `--url` accepts bare hostnames; `https://` is prepended automatically.

---

## Usage

### Full scan (recommended for bug-bounty recon)

```bash
python main.py --url example.com --xss --idor --js --nuclei --report --pdf
```

This single command will:

- Scrape `<script>` tags + run **Deep JS Analysis** on every linked `.js` asset (`--js`).
- Probe GET parameters and forms for **reflected XSS** (`--xss`).
- Hunt for **IDOR** on every numeric id in the URL (`--idor`).
- Run **Nuclei** against the target (`--nuclei`; install [nuclei](https://github.com/projectdiscovery/nuclei/releases) and ensure it is on `PATH`).
- Save branded `.txt`, `.json`, and `.pdf` reports into `reports/<target>/` (`--report --pdf`).

### Maximum coverage

```bash
python main.py --url example.com --subdomain --xss --ai --idor --cloud --brute --port --js --nuclei --zero-day --ai-mutate --report --pdf
```

Adds subdomain discovery, AI-guided WAF-bypass XSS mutations, **Nuclei** templates, **Zero-Day Hunter** heuristics, **AI-Mutator** variants (with discovered slots), cloud bucket enumeration, sensitive-path brute, and TCP port scanning.

### Other common recipes

```bash
# Just the AI prompt-injection playbook (for AI-chat interfaces)
python main.py --url chat.example.com --ai

# Nuclei-only pass + machine-readable JSON (binary must be on PATH)
python main.py --url https://example.com --nuclei --report

# Zero-Day Hunter + deep JS + parameter discovery (authorized scope only)
python main.py --url example.com --zero-day --js --params --report

# IDOR-only against a deep link that exposes a numeric ID
python main.py --url "https://api.example.com/users/42" --idor --report

# Full-spectrum recon + branded PDF only (no text report)
python main.py --url example.com --subdomain --xss --ai --cloud --brute --port --js --idor --nuclei --pdf
```

---

## CLI flags reference

| Flag | Description |
|------|-------------|
| `--url TARGET` | **Required.** Target URL or hostname; `https://` is prepended automatically. |
| `--ai` | Print the AI/LLM prompt-injection playbook *and* auto-mutate XSS payloads when combined with `--xss`. |
| `--subdomain` | Probe common subdomains derived from the apex host. |
| `--xss` | Probe URL query parameters and GET forms for reflected-XSS payloads. |
| `--idor` | IDOR scanner for numeric IDs in query params / path segments. Flags **Critical** on PII drift. |
| `--js` | Deep JS analyzer - concurrently crawl every linked script for endpoints and secrets. |
| `--cloud` | Enumerate candidate public cloud buckets (S3 / Azure / GCP / DO). |
| `--brute` | Brute common sensitive paths (`.git`, `.env`, `/admin`, CI/CD, backups, debug). |
| `--params` | **Hidden parameter probe** (GET / POST / JSON) — feeds Zero-Day Hunter, AI-Mutator slots, and logic scan. |
| `--port` | TCP-connect scan over a curated list of common service ports. |
| `--nuclei` | Run **ProjectDiscovery Nuclei** against `--url` (subprocess); JSONL findings in console, reports, and dashboard loot. |
| `--zero-day` | Enable **Zero-Day Hunter** heuristic / fuzz pass (authorized testing only). |
| `--ai-mutate` | **AI-Mutator**: generate payload variants from discovered parameter slots. |
| `--logic-scan` | Run logic-style triage over signals from other modules. |
| `--report` | Save results as `.txt` *and* `.json` under `reports/<target>/`. |
| `--pdf` | Also render a branded `.pdf`. Auto-enables `--report`. Requires `fpdf2`. |
| `--version` | Print version and exit. |
| `-h`, `--help` | Show the help screen and exit. |

> **Dashboard:** run `python dashboard.py` for the Flask + Socket.IO UI. Scans started from the dashboard set `OMNISCAN_DASHBOARD=1` on the child process so logs and loot stream to the browser.

---

## Reports

All artefacts land in `reports/<target-slug>/omniscan_<UTC-timestamp>.{txt,json,pdf}`:

```
reports/
└── example_com/
    ├── omniscan_20260421_120950.txt    # human-readable, sectioned
    ├── omniscan_20260421_120950.json   # machine-parseable
    └── omniscan_20260421_120950.pdf    # branded, multi-page
```

Every report is **signed**:

> *Developed by Channa Sandeepa &bull; OmniScan-AI v2.5 (Aggressive Infiltration Edition) &bull; &copy; 2026*

In the PDF, this signature is rendered in the header **and** footer of every page (hardcoded in `modules/report_generator.py`).

---

## Project structure

```
OmniScan-AI/
├── main.py                       # CLI entrypoint + orchestrator
├── dashboard.py                  # Flask + Socket.IO: live logs, loot, scan control
├── templates/
│   └── index.html                # Dashboard SPA shell
├── modules/
│   ├── __init__.py
│   ├── ai_auditor.py             # Prompt-injection payloads + XSS WAF-bypass mutator
│   ├── ai_mutator.py             # AI-Mutator: slot-driven payload variants
│   ├── cloud_scanner.py          # S3 / Azure / GCP / DO bucket enumeration
│   ├── idor_scanner.py           # Numeric-ID discovery + Critical-on-PII-drift logic
│   ├── js_analyzer.py            # Deep JS endpoint + secret crawler
│   ├── nuclei_engine.py          # Subprocess wrapper for ProjectDiscovery Nuclei (-jsonl)
│   ├── path_bruter.py            # Sensitive-path brute forcer
│   ├── port_scanner.py           # Async TCP port sweep
│   ├── report_generator.py       # .txt / .json / branded .pdf reporting
│   ├── secret_finder.py          # Regex-based secret scanner (core)
│   ├── subdomain_scanner.py      # Subdomain discovery
│   ├── zero_day_hunter.py        # Zero-Day Hunter heuristics
│   └── xss_scanner.py            # Reflected-XSS prober
├── reports/                      # Generated scan outputs (git-ignored)
├── requirements.txt
├── LICENSE                       # GNU GPL-3.0
└── README.md                     # You are here
```

---

## Tech stack

- **Python 3.10+** - modern type hints, structural pattern matching-ready.
- **`asyncio` + `aiohttp`** - concurrency-first, one event loop orchestrating every scanner.
- **`asyncio.Semaphore`** - per-scanner rate limiting (default 8-12 parallel requests).
- **`rich`** - ANSI banner, colour-coded tables, live progress bars, clickable links.
- **`beautifulsoup4`** - HTML parsing, script/form discovery.
- **`fpdf2`** - custom `FPDF` subclass with a branded running header + footer.
- **Flask + Flask-SocketIO** - optional real-time dashboard (`dashboard.py`).
- **Nuclei (external)** - template scanner invoked via subprocess when using `--nuclei`; install separately and keep templates updated.
- **Regex-first design** - every signature is auditable; no opaque ML weights.

---

## License & Credits

### Developed by

> **Channa Sandeepa**
> *Offensive-security tooling &bull; Bug-bounty automation &bull; Python async engineering*

### License

This project is licensed under the **[GNU General Public License v3.0](LICENSE)**.

```
Copyright (C) 2026 Channa Sandeepa

OmniScan-AI is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.
```

See the full text in [`LICENSE`](LICENSE).

---

<div align="center">

<sub><strong>OmniScan-AI v2.5</strong> (Aggressive Infiltration Edition) &bull; Developed by <strong>Channa Sandeepa</strong> &bull; &copy; 2026 &bull; Licensed under <strong>GPL-3.0</strong></sub>

<br/>

<em>Hack responsibly. Document your scope. Sign your work.</em>

</div>
