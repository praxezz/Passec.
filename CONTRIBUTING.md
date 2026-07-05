# Contributing to PASSEC

Thanks for your interest in improving PASSEC! Contributions are welcome — new pattern detectors, policy frameworks, generator improvements, and documentation fixes all help.

## Getting started

1. Fork the repo and clone your fork.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Create a branch for your change: `git checkout -b feature/my-improvement`.

## Running it

```bash
python passec.py
```

Walk through each menu option (Quick Check, Deep Analysis, Batch Audit, Generate, Policy Check) to confirm your change didn't break the others.

## Guidelines

- Keep offline features (Quick Check, Generate, pattern analysis) working with **zero network calls** — breach checking is the only feature allowed to touch the network, and it must stay optional/gracefully degrading if `requests` isn't installed.
- Never log, print, or export a raw password anywhere except directly back to the user in the terminal — batch audit reports should store hashes/scores, not plaintext, wherever possible.
- New pattern detectors go in `PatternAnalyzer`; keep each one cheap (no heavy computation per password) since batch audits can process large lists.
- Match the existing Rich-based UI style (`console.print`, `Panel`, `Table`) rather than raw `print()`.
- If you add a new compliance framework, follow the `PolicyChecker.check_nist_800_63b` / `check_pci_dss` pattern (return a dict with `framework`, `compliant`, `checks`).

## Reporting bugs / suggesting features

Open a GitHub Issue with your OS/Python version, the menu option you used, and what happened vs. what you expected.

## Security issues

See [SECURITY.md](SECURITY.md).
