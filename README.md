# 🔐 PASSEC — Credential Hygiene Auditor

**PASSEC** is a terminal-based password auditor that goes beyond simple entropy math: it detects *why* a password is weak (common passwords, l33t-speak, keyboard walks, dates, dictionary words), estimates realistic crack times across multiple attacker profiles, checks real-world breach exposure via Have I Been Pwned, scores compliance against NIST 800-63B / PCI-DSS, and generates strong passwords or diceware passphrases.

```
██████╗  █████╗ ███████╗███████╗███████╗ ██████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝
██████╔╝███████║███████╗███████╗█████╗  ██║
██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██║
██║     ██║  ██║███████║███████║███████╗╚██████╗
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝
```

> **Status:** actively developed personal security tool. See [Disclaimer](#-disclaimer).

---

## ✨ Features

- **Pattern-aware weakness detection** (zxcvbn-lite) — flags common passwords, l33t-speak substitutions (`P@ssw0rd` → `password`), keyboard walks (`qwerty`, `asdfgh`), sequential runs, repeated characters, dictionary words, and embedded dates/years — not just raw character-set entropy.
- **Realistic crack-time estimation** — models guesses against four attacker profiles (throttled online, unthrottled online, offline slow-hash/bcrypt, offline fast-hash/GPU) instead of one generic "time to crack" number.
- **Breach checking via Have I Been Pwned** — uses the HIBP k-anonymity API (only a truncated SHA-1 hash prefix is ever sent — your real password never leaves your machine), with caching and retry/backoff.
- **Compliance scoring** — checks passwords against **NIST SP 800-63B** (length + breach screening, no arbitrary composition rules) and **PCI-DSS v4.0** (Req 8.3.6) requirements.
- **Batch auditing** — load a CSV/TXT list of passwords, audit them all with threaded HIBP lookups, see a strength-distribution summary, and export a full JSON or CSV report.
- **Secure generation** — cryptographically secure random passwords (`secrets` module, guaranteed character-class coverage) or diceware-style passphrases with entropy estimates.
- **Rich terminal UI** — cyberpunk orange-on-black themed menus, panels, tables, and progress bars.
- **Offline-first** — the Quick Check and Generate features work with zero network calls; breach checking is opt-in and degrades gracefully if `requests` isn't installed.

---

## 🚀 Getting Started

### Requirements

- Python 3.8+
- Windows, macOS, or Linux

### Installation

```bash
git clone https://github.com/<your-username>/passec.git
cd passec
pip install -r requirements.txt
```

### Run it

```bash
python passec.py
```

You'll land on an interactive menu — no CLI flags to remember.

---

## 🧰 Menu Options

| Option | What it does |
|---|---|
| **1. Quick Check** | Instant offline strength scoring — pattern analysis + brute-force entropy, no network needed. |
| **2. Deep Analysis** | Everything Quick Check does, plus a Have I Been Pwned breach lookup. |
| **3. Batch Audit** | Load a whole CSV/TXT password list, audit every entry (with optional threaded HIBP checks), see a strength distribution, and export a JSON/CSV report. |
| **4. Generate** | Create a cryptographically secure random password or a diceware-style passphrase, with an entropy estimate. |
| **5. Policy Check** | Verify a password against **NIST 800-63B** and **PCI-DSS v4.0** compliance rules. |
| **h. Help** | In-app summary of all menu options. |
| **q. Quit** | Exit. |

---

## 📊 How scoring works

1. **Pattern analysis** looks for the *reason* a password would fall quickly — an exact match against a common-password list, a l33t-speak variant of one, a dictionary word, a keyboard walk, a sequential run, a repeated-character run, or an embedded date/year.
2. **Crack-time modeling** takes the *weakest* explanation (pattern match or brute force, whichever yields fewer effective guesses) and converts it into estimated crack times across four attacker profiles — because a 16-character password that's just a common phrase can still fall in seconds against a targeted guesser, even though raw entropy math would call it "strong."
3. **Breach status** (Deep Analysis / Batch / Policy Check) folds in whether the exact password has appeared in a known breach corpus via HIBP.
4. **Compliance frameworks** apply their own independent pass/fail rules (NIST cares about length + breach status; PCI-DSS cares about length + character variety).

---

## ⚙️ Dependencies

| Package | Required? | Purpose |
|---|---|---|
| `rich` | ✅ Required | Powers the entire terminal UI |
| `requests` | Optional | Needed for Have I Been Pwned breach checks (Deep Analysis, Batch Audit, Policy Check). Without it, PASSEC still runs — breach checks are skipped with a clear message. |

Install both with:

```bash
pip install -r requirements.txt
```

---

## 📁 Batch audit input format

Batch Audit accepts:
- A **`.txt`** file with one password per line, or
- A **`.csv`** file with a `password` column (or the first column, if unlabeled)

Exported reports (`passec_report_<timestamp>.json` / `.csv`) are written to whatever path you choose and are **not** committed to this repo — see `.gitignore`.

---

## 🗺️ Roadmap ideas

- [ ] Swap the 150-word demo diceware list for the full EFF 7,776-word long wordlist
- [ ] Config file for custom common-password/dictionary lists
- [ ] Additional compliance frameworks (ISO 27001, HIPAA)
- [ ] Non-interactive/scriptable mode (`--check`, `--batch <file>` flags) for CI pipelines

Have another idea? Open an issue!

---

## 🤝 Contributing

Contributions are welcome! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions and guidelines before opening a PR.

## 🔒 Security

Found a security issue in PASSEC itself? See **[SECURITY.md](SECURITY.md)**.

## ⚠️ Disclaimer

PASSEC is an educational/personal security auditing tool. Breach-check results depend entirely on the Have I Been Pwned corpus at the time of the check — a password not found there isn't a guarantee it's safe, only that it isn't in that specific dataset. Always use a dedicated password manager for real credential storage; don't paste production passwords into any tool (including this one) on a machine you don't trust.

## 📄 License

Released under the [MIT License](LICENSE) — Copyright (c) 2025 Praveen K.
