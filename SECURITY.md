# Security

PASSEC handles real passwords (even if only in memory, briefly), so if you spot a way it could leak, log, or mishandle credentials, I'd like to know.

## Found a problem?

- Open an issue on this repo, or
- Reach out to the maintainer directly (see profile) if it's something sensitive you'd rather not put in a public issue.

When you do, please include:
- PASSEC version / commit hash
- OS and Python version
- Steps to reproduce
- What actually happened vs. what you expected

## Scope notes

- PASSEC only sends a truncated SHA-1 prefix (k-anonymity) to the Have I Been Pwned API — full passwords never leave the machine. If you find a path where that's not true, that's worth flagging.
- Generated passwords/passphrases use `secrets`, not `random` — anything that weakens that guarantee is in scope too.
