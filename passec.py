#!/usr/bin/env python3
"""
PASSEC  
Credential Hygiene Auditor — Strength, Breach & Compliance Scoring
Author: Praveen K
"""

import re
import io
import csv
import json
import math
import time
import string
import secrets
import hashlib
import argparse
import unicodedata
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn,
)
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.align import Align
from rich.rule import Rule
from rich.box import HEAVY, ROUNDED

# ─────────────────────────────────────────────────────────────────────────
# THEME — cyberpunk orange-on-black
# ─────────────────────────────────────────────────────────────────────────

PASSEC_THEME = Theme({
    "accent":    "bold dark_orange",
    "accent2":   "orange3",
    "banner2":   "bold cyan",
    "good":      "bold spring_green3",
    "warn":      "bold yellow3",
    "bad":       "bold red3",
    "critical":  "bold white on red3",
    "dim":       "grey58",
    "title":     "bold dark_orange on grey11",
    "border":    "dark_orange",
})

console = Console(theme=PASSEC_THEME)

BANNER = r"""
██████╗  █████╗ ███████╗███████╗███████╗ ██████╗    
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝    
██████╔╝███████║███████╗███████╗█████╗  ██║         
██╔═══╝ ██╔══██║╚════██║╚════██║██╔══╝  ██║         
██║     ██║  ██║███████║███████║███████╗╚██████╗     
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝      
"""

# ─────────────────────────────────────────────────────────────────────────
# STATIC INTELLIGENCE — common passwords, l33t map, keyboard layout, diceware
# ─────────────────────────────────────────────────────────────────────────

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "696969", "shadow",
    "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "hunter", "buster", "soccer", "harley", "batman",
    "andrew", "tigger", "sunshine", "iloveyou", "fuckyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
    "starwars", "klaster", "112233", "george", "asshole", "computer",
    "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass", "maggie",
    "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese",
    "amanda", "summer", "love", "ashley", "6969", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas",
    "austin", "thunder", "taylor", "matrix", "mobilemail", "mom",
    "monitor", "monitoring", "montana", "moon", "moscow", "password1",
    "welcome", "admin", "login", "root", "changeme", "passw0rd",
    "qwerty123", "letmein1", "welcome1", "P@ssw0rd", "Password1",
    "Admin@123", "iloveyou1", "sunshine1", "football1", "baseball1",
]
COMMON_PASSWORD_SET = {p.lower() for p in COMMON_PASSWORDS}

DICTIONARY_WORDS = [
    "love", "hate", "life", "money", "family", "friend", "school",
    "college", "office", "work", "india", "chennai", "bangalore",
    "cricket", "movie", "music", "happy", "angel", "prince", "princess",
    "tiger", "lion", "eagle", "phoenix", "dragon", "ninja", "warrior",
    "hero", "master", "king", "queen", "star", "sky", "ocean", "river",
    "mountain", "forest", "flower", "summer", "winter", "spring",
    "autumn", "monday", "friday", "sunday", "welcome", "hello", "test",
    "temp", "default", "guest", "user", "admin", "system", "server",
]

LEET_MAP = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e", "6": "g",
    "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t",
    "+": "t", "2": "z",
}

KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

# Compact diceware-style wordlist for the passphrase generator.
# NOTE: curated 150-word demo set — swap in the full 7,776-word EFF long
# wordlist for production-grade passphrase entropy.
DICEWARE_WORDS = """
anchor anvil apple arrow aspen atlas badge banjo basil beacon beetle
bison blade blaze bloom bluff bolt boulder branch breeze bridge bronze
bubble buckle bumble burrow cactus camel candle canyon carbon cascade
cedar cinder circuit clover coast comet compass copper coral cosmic
cotton crater cricket crimson crystal current dagger delta desert
diamond ditch dolphin domino dragon drift dune eagle ember ensign
falcon feather fern flint forest forge fossil fringe frost galaxy
garnet geode glacier glider granite gravel grove harbor harvest hawk
hazel hearth hemlock heron hollow honey hornet husky iguana indigo
ivory jade jasper jester jigsaw jungle juniper kettle kiwi lagoon
lantern larch lattice lemon lichen linen lodge lotus lynx magma mango
maple marsh meadow meteor mint mosaic moss myrtle nebula nectar nettle
nomad oasis obelisk onyx opal orbit orchid osprey otter oxide paddle
panther papyrus parcel pebble phoenix pigeon pine pixel plateau plume
pond poplar prairie prism puma quarry quartz quiver rapid raven reef
relic ridge rocket rogue rustic saddle sage sapphire savanna scarlet
shale shard shore sierra silver sizzle sleigh sloth solar sparrow
spruce stallion summit swift talon tangerine tavern tempest thicket
thistle thorn thunder timber topaz torch trellis tundra turquoise
umber velvet vessel violet vortex walnut warden wasp wharf willow
wisteria wolf wren yonder zephyr zenith
""".split()


# ─────────────────────────────────────────────────────────────────────────
# PATTERN ANALYZER — zxcvbn-lite: dictionary, l33t, keyboard walks, dates
# ─────────────────────────────────────────────────────────────────────────

def leet_normalize(password: str) -> str:
    """Reverse common l33t substitutions so 'P@ssw0rd' -> 'password'."""
    return "".join(LEET_MAP.get(ch, ch) for ch in password.lower())


def keyboard_walk_length(password: str) -> int:
    """Return the length of the longest adjacent-key run, e.g. 'qwerty' or 'asdfgh'."""
    pw = password.lower()
    best = 1
    for row in KEYBOARD_ROWS:
        for i in range(len(pw) - 1):
            run = 1
            k = i
            while k + 1 < len(pw):
                a, b = pw[k], pw[k + 1]
                pos_a, pos_b = row.find(a), row.find(b)
                if pos_a != -1 and pos_b != -1 and abs(pos_a - pos_b) == 1:
                    run += 1
                    k += 1
                else:
                    break
            best = max(best, run)
    return best


@dataclass
class PatternMatch:
    kind: str
    detail: str
    guess_estimate: int  # rough number of guesses this pattern would take to hit


class PatternAnalyzer:
    """Lightweight zxcvbn-style pattern detector — finds the *reason* a
    password is weak instead of only measuring raw character-set entropy."""

    @staticmethod
    def analyze(password: str) -> list:
        matches = []
        pw_lower = password.lower()
        normalized = leet_normalize(password)

        if pw_lower in COMMON_PASSWORD_SET:
            rank = COMMON_PASSWORDS.index(
                next(p for p in COMMON_PASSWORDS if p.lower() == pw_lower)
            ) + 1
            matches.append(PatternMatch(
                "common_password",
                f"Exact match in top breached-password list (rank ~#{rank})",
                rank,
            ))
        elif normalized in COMMON_PASSWORD_SET:
            matches.append(PatternMatch(
                "leet_common_password",
                "l33t-speak variant of a well-known common password",
                500,
            ))

        for word in DICTIONARY_WORDS:
            if word in pw_lower or word in normalized:
                matches.append(PatternMatch(
                    "dictionary_word",
                    f"Contains dictionary word '{word}'",
                    len(DICTIONARY_WORDS) * 100,
                ))
                break

        walk = keyboard_walk_length(password)
        if walk >= 4:
            matches.append(PatternMatch(
                "keyboard_walk",
                f"Contains a {walk}-character keyboard-adjacent sequence",
                10 ** 3,
            ))

        if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def)', pw_lower):
            matches.append(PatternMatch(
                "sequential", "Contains an ascending sequential run", 10 ** 3,
            ))

        rep = re.search(r'(.)\1{2,}', password)
        if rep:
            matches.append(PatternMatch(
                "repeated_chars",
                f"Repeated character run: '{rep.group(0)}'",
                10 ** 2,
            ))

        if re.search(r'(19\d{2}|20\d{2})', password):
            matches.append(PatternMatch(
                "date_year", "Contains a 4-digit year (birth year / anniversary?)", 200,
            ))
        if re.search(r'\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\b', password):
            matches.append(PatternMatch(
                "date_ddmm", "Contains a date-like DDMM/MMDD sequence", 400,
            ))

        return matches


# ─────────────────────────────────────────────────────────────────────────
# CRACK-TIME MODEL — multi-attacker-profile estimate (zxcvbn-style guesses)
# ─────────────────────────────────────────────────────────────────────────

ATTACK_PROFILES = {
    "Online (throttled, 100/hr)":        100 / 3600,
    "Online (unthrottled, 10/sec)":      10,
    "Offline - slow hash (bcrypt, 10k/s)": 10_000,
    "Offline - fast hash (MD5/GPU, 10^10/s)": 10_000_000_000,
}


class CrackModel:
    @staticmethod
    def charset_size(password: str) -> int:
        size = 0
        if re.search(r'[a-z]', password): size += 26
        if re.search(r'[A-Z]', password): size += 26
        if re.search(r'[0-9]', password): size += 10
        if re.search(r'[^a-zA-Z0-9]', password): size += 32
        return size or 1

    @staticmethod
    def brute_force_entropy(password: str) -> float:
        charset = CrackModel.charset_size(password)
        return round(len(password) * math.log2(charset), 2) if password else 0.0

    @staticmethod
    def estimate_guesses(password: str, patterns: list) -> tuple:
        """Return (guesses, entropy_bits, dominant_reason). Pattern matches
        drastically cut down effective guesses versus pure brute force —
        this is the key thing naive entropy calculators get wrong."""
        brute_force_guesses = 2 ** CrackModel.brute_force_entropy(password)

        if not patterns:
            return brute_force_guesses, CrackModel.brute_force_entropy(password), "brute force (no known pattern)"

        weakest = min(patterns, key=lambda m: m.guess_estimate)
        effective_guesses = min(brute_force_guesses, weakest.guess_estimate)
        effective_entropy = math.log2(max(effective_guesses, 1))
        return effective_guesses, round(effective_entropy, 2), weakest.detail

    @staticmethod
    def crack_time_all_profiles(guesses: float) -> dict:
        return {name: CrackModel._format_seconds(guesses / rate)
                for name, rate in ATTACK_PROFILES.items()}

    @staticmethod
    def _format_seconds(seconds: float) -> str:
        if seconds < 1:
            return "instantly"
        units = [
            (31536000 * 100, "centuries"),
            (31536000, "years"),
            (2592000, "months"),
            (86400, "days"),
            (3600, "hours"),
            (60, "minutes"),
            (1, "seconds"),
        ]
        for unit_seconds, label in units:
            if seconds >= unit_seconds:
                value = seconds / unit_seconds
                if label == "centuries" and value > 1000:
                    return "essentially uncrackable"
                return f"{value:,.1f} {label}"
        return "instantly"


# ─────────────────────────────────────────────────────────────────────────
# BREACH CHECKER — HIBP k-anonymity API, with cache + retry/backoff
# ─────────────────────────────────────────────────────────────────────────

class BreachChecker:
    _cache = {}

    @classmethod
    def check(cls, password: str, retries: int = 2) -> tuple:
        """Returns (is_breached, count, error_message_or_None)."""
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        if prefix in cls._cache:
            hashes = cls._cache[prefix]
        else:
            try:
                import requests
            except ImportError:
                return False, 0, "'requests' not installed — skipping breach check"

            hashes = None
            for attempt in range(retries + 1):
                try:
                    resp = requests.get(
                        f"https://api.pwnedpasswords.com/range/{prefix}",
                        headers={"Add-Padding": "true"},
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        hashes = resp.text.split("\r\n")
                        cls._cache[prefix] = hashes
                        break
                    else:
                        time.sleep(0.5 * (attempt + 1))
                except Exception:
                    time.sleep(0.5 * (attempt + 1))

            if hashes is None:
                return False, 0, "breach check failed (network/API issue)"

        for line in hashes:
            if ":" not in line:
                continue
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return True, int(count), None
        return False, 0, None

    @classmethod
    def check_batch(cls, passwords: list, max_workers: int = 8, progress_cb=None) -> dict:
        """Threaded breach lookup for batch audits. Returns {password: (bool, count, err)}."""
        results = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(cls.check, pw): pw for pw in passwords}
            for fut in as_completed(futures):
                pw = futures[fut]
                try:
                    results[pw] = fut.result()
                except Exception as e:
                    results[pw] = (False, 0, str(e))
                if progress_cb:
                    progress_cb()
        return results


# ─────────────────────────────────────────────────────────────────────────
# POLICY COMPLIANCE — NIST 800-63B & PCI-DSS v4.0 checks
# ─────────────────────────────────────────────────────────────────────────

class PolicyChecker:
    @staticmethod
    def check_nist_800_63b(password: str, is_breached: bool) -> dict:
        """NIST SP 800-63B (2017/2020 digital identity guidelines) checks.
        NIST intentionally does NOT require composition rules or expiry —
        it requires length + breach screening instead."""
        checks = {
            "Minimum 8 characters": len(password) >= 8,
            "Recommended 15+ characters": len(password) >= 15,
            "Not found in known breach corpus": not is_breached,
            "No composition rule required (informational)": True,
            "Supports Unicode/spaces (assumed, not enforceable here)": True,
        }
        compliant = checks["Minimum 8 characters"] and checks["Not found in known breach corpus"]
        return {"framework": "NIST SP 800-63B", "compliant": compliant, "checks": checks}

    @staticmethod
    def check_pci_dss(password: str) -> dict:
        """PCI-DSS v4.0 password requirements (Req 8.3.6): 12+ chars (or 8+
        with compensating controls) with numeric + alphabetic characters."""
        has_alpha = bool(re.search(r'[a-zA-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        checks = {
            "Minimum 12 characters (v4.0)": len(password) >= 12,
            "Minimum 8 characters (legacy fallback)": len(password) >= 8,
            "Contains alphabetic characters": has_alpha,
            "Contains numeric characters": has_digit,
        }
        compliant = checks["Minimum 12 characters (v4.0)"] and has_alpha and has_digit
        return {"framework": "PCI-DSS v4.0 (Req 8.3.6)", "compliant": compliant, "checks": checks}


# ─────────────────────────────────────────────────────────────────────────
# GENERATOR — cryptographically secure passwords & diceware passphrases
# ─────────────────────────────────────────────────────────────────────────

class PasswordGenerator:
    @staticmethod
    def random_password(length: int = 16, use_symbols: bool = True) -> str:
        alphabet = string.ascii_letters + string.digits
        if use_symbols:
            alphabet += "!@#$%^&*()-_=+[]{}"
        while True:
            pw = "".join(secrets.choice(alphabet) for _ in range(length))
            # Guarantee at least one of each required class
            if (re.search(r'[a-z]', pw) and re.search(r'[A-Z]', pw)
                    and re.search(r'[0-9]', pw)):
                return pw

    @staticmethod
    def passphrase(num_words: int = 5, separator: str = "-", capitalize: bool = True,
                    add_number: bool = True) -> str:
        words = [secrets.choice(DICEWARE_WORDS) for _ in range(num_words)]
        if capitalize:
            words = [w.capitalize() for w in words]
        phrase = separator.join(words)
        if add_number:
            phrase += str(secrets.randbelow(90) + 10)
        return phrase

    @staticmethod
    def passphrase_entropy_bits(num_words: int) -> float:
        return round(num_words * math.log2(len(DICEWARE_WORDS)), 2)


# ─────────────────────────────────────────────────────────────────────────
# AUDIT ENGINE — ties pattern analysis + crack model + breach + policy
# together into a single scored report
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class AuditResult:
    password_length: int
    score: int                      # 0-100
    strength: str
    patterns: list = field(default_factory=list)
    entropy_bits: float = 0.0
    dominant_reason: str = ""
    crack_times: dict = field(default_factory=dict)
    is_breached: bool = False
    breach_count: int = 0
    breach_error: Optional[str] = None
    nist: dict = field(default_factory=dict)
    pci: dict = field(default_factory=dict)


class AuditEngine:
    @staticmethod
    def quick(password: str) -> AuditResult:
        """Offline-only: patterns + brute-force entropy. No network calls."""
        patterns = PatternAnalyzer.analyze(password)
        guesses, entropy, reason = CrackModel.estimate_guesses(password, patterns)
        crack_times = CrackModel.crack_time_all_profiles(guesses)
        score = AuditEngine._score(password, patterns, entropy, is_breached=False)
        strength = AuditEngine._strength_label(score)
        return AuditResult(
            password_length=len(password), score=score, strength=strength,
            patterns=patterns, entropy_bits=entropy, dominant_reason=reason,
            crack_times=crack_times,
        )

    @staticmethod
    def deep(password: str) -> AuditResult:
        """Full audit: patterns + crack model + HIBP + NIST/PCI compliance."""
        patterns = PatternAnalyzer.analyze(password)
        guesses, entropy, reason = CrackModel.estimate_guesses(password, patterns)
        crack_times = CrackModel.crack_time_all_profiles(guesses)
        is_breached, breach_count, breach_err = BreachChecker.check(password)

        score = AuditEngine._score(password, patterns, entropy, is_breached)
        strength = AuditEngine._strength_label(score)

        nist = PolicyChecker.check_nist_800_63b(password, is_breached)
        pci = PolicyChecker.check_pci_dss(password)

        return AuditResult(
            password_length=len(password), score=score, strength=strength,
            patterns=patterns, entropy_bits=entropy, dominant_reason=reason,
            crack_times=crack_times, is_breached=is_breached,
            breach_count=breach_count, breach_error=breach_err,
            nist=nist, pci=pci,
        )

    @staticmethod
    def _score(password: str, patterns: list, entropy: float, is_breached: bool) -> int:
        score = 0
        length = len(password)

        # Length (0-30)
        score += min(30, (length / 20) * 30)

        # Char diversity (0-20)
        types = sum(bool(re.search(p, password)) for p in
                    [r'[a-z]', r'[A-Z]', r'[0-9]', r'[^a-zA-Z0-9]'])
        score += types * 5

        # Effective entropy after pattern deduction (0-35)
        score += min(35, (entropy / 80) * 35)

        # Uniqueness ratio (0-15)
        if length:
            score += (len(set(password)) / length) * 15

        # Heavy penalty for concrete weak patterns
        penalty_kinds = {"common_password", "leet_common_password", "keyboard_walk"}
        if any(p.kind in penalty_kinds for p in patterns):
            score = min(score, 20)

        if is_breached:
            score = min(score, 15)

        return max(0, min(100, round(score)))

    @staticmethod
    def _strength_label(score: int) -> str:
        if score >= 85: return "Very Strong"
        if score >= 70: return "Strong"
        if score >= 50: return "Moderate"
        if score >= 30: return "Weak"
        return "Very Weak"


STRENGTH_STYLE = {
    "Very Strong": "good", "Strong": "good", "Moderate": "warn",
    "Weak": "bad", "Very Weak": "critical",
}


# ─────────────────────────────────────────────────────────────────────────
# BATCH AUDITOR — CSV/TXT ingestion, threaded breach lookups, report export
# ─────────────────────────────────────────────────────────────────────────

class BatchAuditor:
    @staticmethod
    def load_passwords(path: str) -> list:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"No such file: {path}")

        passwords = []
        if p.suffix.lower() == ".csv":
            with open(p, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                col = None
                if reader.fieldnames:
                    for cand in ("password", "Password", "PASSWORD"):
                        if cand in reader.fieldnames:
                            col = cand
                            break
                    col = col or reader.fieldnames[0]
                for row in reader:
                    val = row.get(col, "").strip()
                    if val:
                        passwords.append(val)
        else:
            with open(p, encoding="utf-8", errors="ignore") as f:
                passwords = [line.strip() for line in f if line.strip()]
        return passwords

    @staticmethod
    def run(passwords: list, check_breaches: bool, progress: Progress, task_id) -> list:
        results = []
        breach_lookup = {}

        if check_breaches:
            def bump():
                progress.advance(task_id, 0.5)
            breach_lookup = BreachChecker.check_batch(passwords, progress_cb=bump)

        for pw in passwords:
            if check_breaches:
                result = AuditEngine.quick(pw)
                is_b, count, err = breach_lookup.get(pw, (False, 0, None))
                result.is_breached, result.breach_count, result.breach_error = is_b, count, err
                if is_b:
                    result.score = min(result.score, 15)
                    result.strength = AuditEngine._strength_label(result.score)
                progress.advance(task_id, 0.5)
            else:
                result = AuditEngine.quick(pw)
                progress.advance(task_id, 1)
            results.append((pw, result))
        return results

    @staticmethod
    def summarize(results: list) -> dict:
        total = len(results)
        if total == 0:
            return {}
        scores = [r.score for _, r in results]
        breached = sum(1 for _, r in results if r.is_breached)
        strength_counts = {}
        for _, r in results:
            strength_counts[r.strength] = strength_counts.get(r.strength, 0) + 1
        return {
            "total_passwords": total,
            "average_score": round(sum(scores) / total, 1),
            "min_score": min(scores),
            "max_score": max(scores),
            "breached_count": breached,
            "breached_pct": round(breached / total * 100, 1),
            "strength_distribution": strength_counts,
        }

    @staticmethod
    def export_json(results: list, summary: dict, out_path: str):
        payload = {
            "generated_at": datetime.now().isoformat(),
            "tool": "PASSEC",
            "summary": summary,
            "entries": [
                {
                    "password_masked": pw[:2] + "*" * max(0, len(pw) - 2),
                    "length": r.password_length,
                    "score": r.score,
                    "strength": r.strength,
                    "entropy_bits": r.entropy_bits,
                    "dominant_reason": r.dominant_reason,
                    "is_breached": r.is_breached,
                    "breach_count": r.breach_count,
                }
                for pw, r in results
            ],
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    @staticmethod
    def export_csv(results: list, out_path: str):
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["password_masked", "length", "score", "strength",
                              "entropy_bits", "dominant_reason", "is_breached", "breach_count"])
            for pw, r in results:
                masked = pw[:2] + "*" * max(0, len(pw) - 2)
                writer.writerow([masked, r.password_length, r.score, r.strength,
                                  r.entropy_bits, r.dominant_reason, r.is_breached, r.breach_count])


# ─────────────────────────────────────────────────────────────────────────
# UI — Rich dashboard rendering
# ─────────────────────────────────────────────────────────────────────────

def show_banner():
    lines = BANNER.splitlines()
    styles = ["accent", "banner2"]
    for i, line in enumerate(lines):
        if not line.strip():
            console.print()
            continue
        console.print(Align.left(Text(line, style=styles[i % 2])))
    console.print(Align.left(Text("", style="dim")))
    console.print(Rule(style="border"))


def render_result(result: AuditResult, password_len: int, mode: str):
    style = STRENGTH_STYLE.get(result.strength, "dim")

    bar_width = 36
    filled = int((result.score / 100) * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    header = Table.grid(expand=True)
    header.add_column(justify="left")
    header.add_column(justify="right")
    header.add_row(
        Text(f"Strength: {result.strength}", style=f"bold {style}"),
        Text(f"Score: {result.score}/100", style=f"bold {style}"),
    )
    header.add_row(Text(bar, style=style), "")

    console.print(Panel(header, title="[title] PASSEC RESULT [/]", border_style="border", box=HEAVY))

    # Technical details table
    tech = Table(box=ROUNDED, border_style="border", show_header=False, expand=True)
    tech.add_column(style="accent2", ratio=1)
    tech.add_column(ratio=2)
    tech.add_row("Password length", f"{password_len} characters")
    tech.add_row("Effective entropy", f"{result.entropy_bits} bits")
    tech.add_row("Weakest link", result.dominant_reason or "none detected")
    console.print(tech)

    # Crack time by attacker profile
    if result.crack_times:
        ct = Table(title="Estimated Crack Time by Attacker Profile", box=ROUNDED,
                   border_style="border", header_style="title")
        ct.add_column("Attack Scenario", style="accent2")
        ct.add_column("Time to Crack")
        for profile, time_str in result.crack_times.items():
            ct.add_row(profile, time_str)
        console.print(ct)

    # Pattern findings
    if result.patterns:
        pt = Table(title="Weakness Patterns Detected", box=ROUNDED,
                   border_style="border", header_style="title")
        pt.add_column("Type", style="warn")
        pt.add_column("Detail")
        for p in result.patterns:
            pt.add_row(p.kind, p.detail)
        console.print(pt)
    else:
        console.print(Panel("No known weak patterns detected", style="good", border_style="border"))

    # Breach info (deep mode only)
    if mode == "deep":
        if result.breach_error:
            console.print(Panel(f"⚠ {result.breach_error}", style="warn", border_style="border"))
        elif result.is_breached:
            console.print(Panel(
                f"🚨 CRITICAL: found in {result.breach_count:,} known data breaches.\n"
                f"Change this password immediately and check anywhere else it's reused.",
                style="critical", border_style="bad", title="BREACH ALERT",
            ))
        else:
            console.print(Panel("✓ Not found in known breach corpus (HIBP)", style="good", border_style="border"))

        # Compliance
        comp = Table(title="Policy Compliance", box=ROUNDED, border_style="border", header_style="title")
        comp.add_column("Framework", style="accent2")
        comp.add_column("Result")
        for framework in (result.nist, result.pci):
            status = "[good]✓ COMPLIANT[/]" if framework["compliant"] else "[bad]✗ NON-COMPLIANT[/]"
            comp.add_row(framework["framework"], status)
        console.print(comp)

        for framework in (result.nist, result.pci):
            detail = Table(box=None, show_header=False, padding=(0, 1))
            detail.add_column(style="dim")
            detail.add_column()
            for check_name, passed in framework["checks"].items():
                mark = "[good]✓[/]" if passed else "[bad]✗[/]"
                detail.add_row(mark, check_name)
            console.print(Panel(detail, title=framework["framework"], border_style="border"))

    if result.score < 60:
        console.print(Panel(
            "• Use 16+ characters, ideally a passphrase\n"
            "• Avoid dictionary words, names, dates, and keyboard walks\n"
            "• Never reuse a password found in a breach\n"
            "• Consider PASSEC's built-in generator (menu option 4)",
            title="💡 Recommendations", style="accent2", border_style="border",
        ))

    console.print(Rule(style="border"))


def render_batch_summary(summary: dict):
    t = Table(title="Batch Audit Summary", box=HEAVY, border_style="border", header_style="title")
    t.add_column("Metric", style="accent2")
    t.add_column("Value")
    t.add_row("Total passwords audited", str(summary["total_passwords"]))
    t.add_row("Average score", f"{summary['average_score']}/100")
    t.add_row("Score range", f"{summary['min_score']} – {summary['max_score']}")
    t.add_row("Found in breaches", f"{summary['breached_count']} ({summary['breached_pct']}%)")
    console.print(t)

    dist = Table(title="Strength Distribution", box=ROUNDED, border_style="border", header_style="title")
    dist.add_column("Strength")
    dist.add_column("Count")
    for strength, count in summary["strength_distribution"].items():
        style = STRENGTH_STYLE.get(strength, "dim")
        dist.add_row(f"[{style}]{strength}[/]", str(count))
    console.print(dist)


# ─────────────────────────────────────────────────────────────────────────
# MENU ACTIONS
# ─────────────────────────────────────────────────────────────────────────

def action_quick_check():
    pw = Prompt.ask("[accent]Enter password to check[/]", password=False)
    if not pw:
        console.print("[warn]No password entered.[/]")
        return
    with console.status("[accent]Analyzing offline...[/]", spinner="dots"):
        result = AuditEngine.quick(pw)
    render_result(result, len(pw), mode="quick")


def action_deep_analysis():
    pw = Prompt.ask("[accent]Enter password to check[/]", password=False)
    if not pw:
        console.print("[warn]No password entered.[/]")
        return
    with console.status("[accent]Running pattern analysis + HIBP breach check...[/]", spinner="dots"):
        result = AuditEngine.deep(pw)
    render_result(result, len(pw), mode="deep")


def action_batch_audit():
    path = Prompt.ask("[accent]Path to password list (.csv or .txt)[/]")
    try:
        passwords = BatchAuditor.load_passwords(path)
    except Exception as e:
        console.print(f"[bad]Failed to load file: {e}[/]")
        return

    if not passwords:
        console.print("[warn]No passwords found in file.[/]")
        return

    console.print(f"[accent2]Loaded {len(passwords)} passwords.[/]")
    check_breaches = Confirm.ask("Check against HIBP breach corpus? (needs internet)", default=True)

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="accent"), TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(), console=console,
    ) as progress:
        task_id = progress.add_task("Auditing passwords...", total=len(passwords))
        results = BatchAuditor.run(passwords, check_breaches, progress, task_id)

    summary = BatchAuditor.summarize(results)
    render_batch_summary(summary)

    if Confirm.ask("Export report to file?", default=True):
        fmt = Prompt.ask("Format", choices=["json", "csv"], default="json")
        default_name = f"passec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        out_path = Prompt.ask("Output path", default=default_name)
        if fmt == "json":
            BatchAuditor.export_json(results, summary, out_path)
        else:
            BatchAuditor.export_csv(results, out_path)
        console.print(f"[good]✓ Report saved to {out_path}[/]")


def action_generate_password():
    kind = Prompt.ask("Generate a [accent]random password[/] or [accent]passphrase[/]?",
                       choices=["password", "passphrase"], default="passphrase")
    if kind == "password":
        length = IntPrompt.ask("Length", default=16)
        symbols = Confirm.ask("Include symbols?", default=True)
        pw = PasswordGenerator.random_password(length, symbols)
        entropy = CrackModel.brute_force_entropy(pw)
    else:
        n = IntPrompt.ask("Number of words", default=5)
        pw = PasswordGenerator.passphrase(n)
        entropy = PasswordGenerator.passphrase_entropy_bits(n)

    console.print(Panel(
        Text(pw, style="bold good", justify="center"),
        title="Generated Credential", border_style="good",
    ))
    console.print(f"[dim]Estimated entropy: {entropy} bits[/]")
    console.print("[warn]Store this in a password manager — don't reuse it anywhere else.[/]")


def action_policy_check():
    pw = Prompt.ask("[accent]Enter password to check against compliance frameworks[/]")
    if not pw:
        console.print("[warn]No password entered.[/]")
        return
    is_breached, count, err = False, 0, None
    if Confirm.ask("Also check breach status (needed for full NIST check)?", default=True):
        with console.status("[accent]Checking HIBP...[/]"):
            is_breached, count, err = BreachChecker.check(pw)

    nist = PolicyChecker.check_nist_800_63b(pw, is_breached)
    pci = PolicyChecker.check_pci_dss(pw)

    for framework in (nist, pci):
        status = "[good]✓ COMPLIANT[/]" if framework["compliant"] else "[bad]✗ NON-COMPLIANT[/]"
        detail = Table(box=ROUNDED, show_header=False, border_style="border")
        detail.add_column(style="dim")
        detail.add_column()
        for name, passed in framework["checks"].items():
            mark = "[good]✓[/]" if passed else "[bad]✗[/]"
            detail.add_row(mark, name)
        console.print(Panel(detail, title=f"{framework['framework']}  —  {status}", border_style="border"))

    if err:
        console.print(f"[warn]Note: {err}[/]")


def action_help():
    help_table = Table(box=ROUNDED, show_header=False, border_style="border", padding=(0, 1))
    help_table.add_column(style="accent", justify="right")
    help_table.add_column()
    help_table.add_row("1.", "Quick Check — instant offline strength scoring, no network needed.")
    help_table.add_row("2.", "Deep Analysis — pattern detection plus a Have I Been Pwned breach lookup.")
    help_table.add_row("3.", "Batch Audit — scan a whole CSV/TXT list of passwords and export a report.")
    help_table.add_row("4.", "Generate — create a strong random password or diceware-style passphrase.")
    help_table.add_row("5.", "Policy Check — verify a password against NIST 800-63B and PCI-DSS rules.")
    help_table.add_row("h.", "Help — show this screen.")
    console.print(Panel(
        help_table,
        title="[title] PASSEC HELP [/]",
        subtitle="Enter a menu number/letter at the prompt to run that action",
        border_style="border",
    ))
   


MENU_ACTIONS = {
    "1": ("Quick Check (offline, instant)", action_quick_check),
    "2": ("Deep Analysis (patterns + HIBP breach check)", action_deep_analysis),
    "3": ("Batch Audit (CSV/TXT file → report)", action_batch_audit),
    "4": ("Generate secure password / passphrase", action_generate_password),
    "5": ("Policy Compliance Check (NIST 800-63B / PCI-DSS)", action_policy_check),
    "h": ("Know To Use", action_help),
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="passec.py",
        description="PASSEC : check strength, "
                     "scan for breaches, batch-audit lists, generate passphrases, "
                     "and check compliance against NIST 800-63B / PCI-DSS.",
        epilog="Type 'h' at the main menu for an in-app help screen.",
        add_help=False,
    )
    return parser.parse_args()


def main():
    parse_args()
    console.clear()
    show_banner()

    while True:
        console.print()
        menu = Table.grid(padding=(0, 2))
        menu.add_column(style="accent", justify="right")
        menu.add_column()
        for i, (key, (label, _)) in enumerate(MENU_ACTIONS.items()):
            color = "banner2" if i % 2 == 0 else "accent2"
            menu.add_row(f"{key}.", f"[{color}]{label}[/]")
        menu.add_row("q.", "[accent2]Quit[/]")
        console.print(Panel.fit(menu, title="[title] MAIN MENU [/]", border_style="border"))

        choice = Prompt.ask("[accent]Select an option[/]").strip().lower()

        if choice in ("q", "quit", "exit"):
            console.print("\n[accent]Stay secure. 🛡[/]\n")
            break

        action = MENU_ACTIONS.get(choice)
        if not action:
            console.print("[warn]Invalid option — try again.[/]")
            continue

        try:
            action[1]()
        except KeyboardInterrupt:
            console.print("\n[warn]Cancelled.[/]")
        except Exception as e:
            console.print(f"[bad]Unexpected error: {e}[/]")


if __name__ == "__main__":
    main()