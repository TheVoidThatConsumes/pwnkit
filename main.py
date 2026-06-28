"""
main.py - Password Security Toolkit

Portfolio Demonstration Project

Features:
- MD5, SHA-1 and SHA-256 hashing
- bcrypt and Argon2id hashing
- Password strength analysis
- Local breach database lookup
- Dictionary attack simulation
- PNG security report (saved to reports/)

Required files:
    pwned/breached_sha1.txt       (SHA-1 hashes, one per line)
    wordlist/wordlist.txt         (passwords, one per line)

Install:
    pip install bcrypt argon2-cffi matplotlib

Usage:
    python main.py hash    <password>
    python main.py crack   <password>
    python main.py breach  <password>
    python main.py report  <password>
"""

import hashlib
import math
import sys
from pathlib import Path
from datetime import datetime

import bcrypt
from argon2 import PasswordHasher

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ============================================================
# CONFIG
# ============================================================

BREACH_FILE   = Path("pwned/breached_sha1.txt")
WORDLIST_FILE = Path("wordlist/wordlist.txt")
REPORTS_DIR   = Path("reports")

# Creates folders on first run so nothing crashes
Path("pwned").mkdir(exist_ok=True)
Path("wordlist").mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

argon2 = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)

# Cached in memory after first load
BREACHED_HASHES = None
WORDLIST        = None


# ============================================================
# DATABASE LOADERS
# ============================================================

def load_breach_database():
    if not BREACH_FILE.exists():
        print(f"\n[!] Missing breach database: {BREACH_FILE.resolve()}\n")
        return set()
    print("[+] Loading breach database...")
    with open(BREACH_FILE, "r", encoding="utf-8") as f:
        hashes = {line.strip() for line in f if line.strip()}
    print(f"[+] Loaded {len(hashes):,} breach hashes")
    return hashes


def load_wordlist():
    if not WORDLIST_FILE.exists():
        print(f"\n[!] Missing wordlist: {WORDLIST_FILE.resolve()}\n")
        return set()
    print("[+] Loading wordlist...")
    with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as f:
        words = {line.strip() for line in f if line.strip()}
    print(f"[+] Loaded {len(words):,} passwords")
    return words


def get_breach_db():
    global BREACHED_HASHES
    if BREACHED_HASHES is None:
        BREACHED_HASHES = load_breach_database()
    return BREACHED_HASHES


def get_wordlist():
    global WORDLIST
    if WORDLIST is None:
        WORDLIST = load_wordlist()
    return WORDLIST


# ============================================================
# HASH FUNCTIONS
# ============================================================

def md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

def sha1_hash(password):
    return hashlib.sha1(password.encode()).hexdigest().upper()

def sha256_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def bcrypt_hash(password):
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(12)).decode()

def argon2_hash(password):
    return argon2.hash(password)


# ============================================================
# PASSWORD STRENGTH
# ============================================================

def strength(password):
    pool = 0
    if any(c.islower()     for c in password): pool += 26
    if any(c.isupper()     for c in password): pool += 26
    if any(c.isdigit()     for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 32

    entropy = round(len(password) * math.log2(pool), 1) if pool else 0

    if   entropy < 28: return entropy, "Very Weak",  "#E24B4A"
    elif entropy < 36: return entropy, "Weak",        "#EF9F27"
    elif entropy < 50: return entropy, "Moderate",    "#378ADD"
    elif entropy < 70: return entropy, "Strong",      "#1D9E75"
    else:              return entropy, "Very Strong",  "#085041"


# ============================================================
# BREACH + CRACK
# ============================================================

def is_breached(password):
    return sha1_hash(password) in get_breach_db()

def crack(password):
    wl = get_wordlist()
    if not wl:
        return None
    return password if password in wl else None


# ============================================================
# COMMANDS
# ============================================================

def cmd_hash(password):
    print("\nPassword Hash Output")
    print("-" * 60)
    print(f"Length   : {len(password)}")
    print(f"MD5      : {md5_hash(password)}")
    print(f"SHA-1    : {sha1_hash(password)}")
    print(f"SHA-256  : {sha256_hash(password)}")
    if len(password.encode()) > 72:
        print("\n[!] Warning: bcrypt only uses the first 72 bytes.")
    print(f"bcrypt   : {bcrypt_hash(password)}")
    print(f"Argon2id : {argon2_hash(password)}")
    print()


def cmd_crack(password):
    wl = get_wordlist()
    if not wl:
        print("\n[!] No wordlist — add one to wordlist/wordlist.txt\n")
        return
    result = crack(password)
    print("\nDictionary Attack Simulation")
    print("-" * 60)
    if result:
        print("FOUND in wordlist — this password is too weak.")
    else:
        print("Not found in wordlist.")
    print()


def cmd_breach(password):
    print("\nBreach Check")
    print("-" * 60)
    if is_breached(password):
        print("FOUND in breach database — do not use this password.")
    else:
        print("Not found in breach database.")
    print()


# ============================================================
# REPORT
# ============================================================

def cmd_report(password, filename=None):
    entropy, rating, colour = strength(password)
    breached = is_breached(password)
    cracked  = crack(password)

    if breached or cracked:
        verdict, v_col = "HIGH RISK",     "#E24B4A"
    elif entropy < 50:
        verdict, v_col = "MODERATE RISK", "#EF9F27"
    else:
        verdict, v_col = "LOW RISK",      "#1D9E75"

    # Default filename includes timestamp so reports don't overwrite each other
    if filename is None:
        stamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{stamp}.png"

    output = REPORTS_DIR / filename

    # ── figure ────────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 10))
    fig.patch.set_facecolor("#0C2340")
    ax.set_facecolor("#0C2340")
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 14)
    ax.axis("off")

    C_WHITE = "#E6F1FB"
    C_MUTED = "#85B7EB"
    C_LINE  = "#1A3A5C"

    def row(y, label, value, val_col=C_WHITE):
        ax.text(0.4, y, label, fontsize=9,  color=C_MUTED, va="center")
        ax.text(9.6, y, value, fontsize=9,  color=val_col,
                va="center", ha="right", fontweight="bold")
        ax.axhline(y - 0.35, xmin=0.04, xmax=0.96,
                   color=C_LINE, linewidth=0.5)

    # Header
    ax.text(5, 13.3, "pwnkit",
            fontsize=22, color=C_WHITE, ha="center", fontweight="bold")
    ax.text(5, 12.85, "Password Security Report",
            fontsize=10, color=C_MUTED, ha="center")
    ax.text(5, 12.45, datetime.now().strftime("%d %b %Y  %H:%M"),
            fontsize=8, color=C_MUTED, ha="center")
    ax.axhline(12.2, color=C_LINE, linewidth=1)

    # Password
    ax.text(0.4, 11.85, "Password", fontsize=8, color=C_MUTED)
    ax.text(0.4, 11.5,
            password[:48] + ("..." if len(password) > 48 else ""),
            fontsize=13, color=C_WHITE, fontweight="bold")
    ax.axhline(11.15, color=C_LINE, linewidth=1)

    # Strength
    ax.text(0.4, 10.8, "STRENGTH",
            fontsize=8, color=C_MUTED, fontweight="bold")
    row(10.35, "Rating",  rating,              colour)
    row(9.75,  "Entropy", f"{entropy} bits")
    row(9.15,  "Length",  f"{len(password)} characters")

    classes = []
    if any(c.islower()     for c in password): classes.append("lowercase")
    if any(c.isupper()     for c in password): classes.append("uppercase")
    if any(c.isdigit()     for c in password): classes.append("digits")
    if any(not c.isalnum() for c in password): classes.append("symbols")
    row(8.55, "Character classes",
        ", ".join(classes) if classes else "none")
    ax.axhline(8.15, color=C_LINE, linewidth=1)

    # Crack test
    ax.text(0.4, 7.8, "CRACK TEST",
            fontsize=8, color=C_MUTED, fontweight="bold")
    if cracked:
        row(7.35, "Wordlist", "FOUND — too weak", "#E24B4A")
    else:
        row(7.35, "Wordlist", "Not found", "#1D9E75")
    ax.axhline(6.95, color=C_LINE, linewidth=1)

    # Breach check
    ax.text(0.4, 6.6, "BREACH CHECK",
            fontsize=8, color=C_MUTED, fontweight="bold")
    if breached:
        row(6.15, "Local database", "FOUND — compromised", "#E24B4A")
    else:
        row(6.15, "Local database", "Not found", "#1D9E75")
    ax.axhline(5.75, color=C_LINE, linewidth=1)

    # Hashes
    ax.text(0.4, 5.4, "HASHES",
            fontsize=8, color=C_MUTED, fontweight="bold")
    row(4.95, "MD5",      md5_hash(password)[:40] + "...",    "#EF9F27")
    row(4.35, "SHA-256",  sha256_hash(password)[:40] + "...", "#EF9F27")
    row(3.75, "bcrypt",   bcrypt_hash(password)[:40] + "...", "#1D9E75")
    row(3.15, "Argon2id", argon2_hash(password)[:40] + "...", "#1D9E75")
    ax.axhline(2.75, color=C_LINE, linewidth=1)

    # Verdict
    ax.text(0.4, 2.4, "OVERALL VERDICT",
            fontsize=8, color=C_MUTED, fontweight="bold")
    ax.text(5, 1.8, verdict,
            fontsize=20, color=v_col, ha="center", fontweight="bold")

    # Footer
    ax.axhline(0.55, color=C_LINE, linewidth=0.5)
    ax.text(5, 0.3,
            "for authorised security testing only — only test passwords you own",
            fontsize=7, color=C_MUTED, ha="center")

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches="tight", facecolor="#0C2340")
    plt.close()

    print(f"\nReport saved → {output}\n")


# ============================================================
# MAIN
# ============================================================

USAGE = """
Password Security Toolkit

Usage:
    python main.py hash    <password>
    python main.py crack   <password>
    python main.py breach  <password>
    python main.py report  <password>
    python main.py report  <password> filename.png
"""


def main():
    if len(sys.argv) < 3:
        print(USAGE)
        return

    command  = sys.argv[1]
    password = sys.argv[2]

    if command == "hash":
        cmd_hash(password)
    elif command == "crack":
        cmd_crack(password)
    elif command == "breach":
        cmd_breach(password)
    elif command == "report":
        filename = sys.argv[3] if len(sys.argv) > 3 else None
        cmd_report(password, filename)
    else:
        print(f"\nUnknown command: {command}")
        print(USAGE)


if __name__ == "__main__":
    main()
