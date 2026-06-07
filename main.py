"""
main.py - Password Security Toolkit

Portfolio Demonstration Project

Features:
- MD5, SHA-1 and SHA-256 hashing
- bcrypt hashing
- Argon2id hashing
- Password strength analysis
- Local breach database lookup
- Dictionary attack simulation
- PNG security report generation

Required files:
    breached_sha1_500k.txt
    wordlist.txt

Install:
    pip install bcrypt argon2-cffi matplotlib

Usage:
    python main.py hash <password>
    python main.py breach <password>
    python main.py crack <password>
    python main.py report <password>
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

BREACH_FILE = Path("pwned/breached_sha1.txt")
WORDLIST_FILE = Path("wordlist/wordlist.txt")

argon2 = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1
)

BREACHED_HASHES = None
WORDLIST = None


# ============================================================
# DATABASE LOADERS
# ============================================================

def load_breach_database():

    if not BREACH_FILE.exists():

        print(
            f"\n[!] Missing breach database:\n"
            f"    {BREACH_FILE.resolve()}\n"
        )

        return set()

    print("[+] Loading breach database...")

    with open(
        BREACH_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        hashes = {
            line.strip()
            for line in f
            if line.strip()
        }

    print(
        f"[+] Loaded {len(hashes):,} breach hashes"
    )

    return hashes


def load_wordlist():

    if not WORDLIST_FILE.exists():

        print(
            f"\n[!] Missing wordlist:\n"
            f"    {WORDLIST_FILE.resolve()}\n"
        )

        return set()

    print("[+] Loading wordlist...")

    with open(
        WORDLIST_FILE,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        words = {
            line.strip()
            for line in f
            if line.strip()
        }

    print(
        f"[+] Loaded {len(words):,} passwords"
    )

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

    return hashlib.md5(
        password.encode()
    ).hexdigest()


def sha1_hash(password):

    return hashlib.sha1(
        password.encode()
    ).hexdigest().upper()


def sha256_hash(password):

    return hashlib.sha256(
        password.encode()
    ).hexdigest()


# ============================================================
# PASSWORD STRENGTH
# ============================================================

def strength(password):

    pool = 0

    if any(c.islower() for c in password):
        pool += 26

    if any(c.isupper() for c in password):
        pool += 26

    if any(c.isdigit() for c in password):
        pool += 10

    if any(not c.isalnum() for c in password):
        pool += 32

    entropy = (
        round(
            len(password) * math.log2(pool),
            1
        )
        if pool
        else 0
    )

    if entropy < 28:
        return entropy, "Very Weak", "#E24B4A"

    elif entropy < 36:
        return entropy, "Weak", "#EF9F27"

    elif entropy < 50:
        return entropy, "Moderate", "#378ADD"

    elif entropy < 70:
        return entropy, "Strong", "#1D9E75"

    else:
        return entropy, "Very Strong", "#085041"


# ============================================================
# BREACH CHECK
# ============================================================

def is_breached(password):

    return (
        sha1_hash(password)
        in get_breach_db()
    )


# ============================================================
# DICTIONARY ATTACK SIMULATION
# ============================================================

def crack(password):

    return (
        password
        if password in get_wordlist()
        else None
    )


# ============================================================
# HASH COMMAND
# ============================================================

def cmd_hash(password):

    print("\nPassword Analysis")
    print("-" * 60)

    print(
        f"Length   : {len(password)}"
    )

    print(
        f"MD5      : {md5_hash(password)[:16]}..."
    )

    print(
        f"SHA-1    : {sha1_hash(password)[:16]}..."
    )

    print(
        f"SHA-256  : {sha256_hash(password)[:16]}..."
    )

    if len(password.encode()) > 72:

        print(
            "\n[!] Warning:"
            " bcrypt only uses the first 72 bytes."
        )

    bcrypt_result = bcrypt.hashpw(
        password.encode()[:72],
        bcrypt.gensalt(12)
    ).decode()

    print(
        f"bcrypt   : {bcrypt_result}"
    )

    argon_result = argon2.hash(password)

    print(
        f"Argon2id : {argon_result}"
    )

    print()


# ============================================================
# CRACK COMMAND
# ============================================================

def cmd_crack(password):

    result = crack(password)

    print("\nDictionary Attack Simulation")
    print("-" * 60)

    print(
        f"Length   : {len(password)}"
    )

    if result:

        print(
            "Password exists in the loaded wordlist."
        )

    else:

        print(
            "Password not found in the loaded wordlist."
        )

    print()


# ============================================================
# BREACH COMMAND
# ============================================================

def cmd_breach(password):

    print("\nBreach Check")
    print("-" * 60)

    print(
        f"Length   : {len(password)}"
    )

    if is_breached(password):

        print(
            "FOUND in breach database."
        )

    else:

        print(
            "Not found."
        )

    print()


# ============================================================
# REPORT COMMAND
# ============================================================

def cmd_report(
    password,
    output="report.png"
):

    entropy, rating, colour = strength(password)

    breached = is_breached(password)
    cracked = crack(password)

    if breached or cracked:

        verdict = "HIGH RISK"
        verdict_colour = "#E24B4A"

    elif entropy < 50:

        verdict = "MODERATE RISK"
        verdict_colour = "#EF9F27"

    else:

        verdict = "LOW RISK"
        verdict_colour = "#1D9E75"

    fig, ax = plt.subplots(
        figsize=(8, 8)
    )

    ax.axis("off")

    ax.text(
        0.5,
        0.95,
        "Password Security Report",
        ha="center",
        fontsize=18
    )

    lines = [
        f"Generated : {datetime.now()}",
        "",
        f"Length    : {len(password)}",
        f"Entropy   : {entropy}",
        f"Rating    : {rating}",
        f"Breached  : {breached}",
        f"Wordlist  : {bool(cracked)}",
        "",
        f"Verdict   : {verdict}"
    ]

    y = 0.85

    for line in lines:

        ax.text(
            0.05,
            y,
            line
        )

        y -= 0.07

    ax.text(
        0.5,
        0.08,
        verdict,
        fontsize=20,
        ha="center",
        color=verdict_colour
    )

    plt.savefig(
        output,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"\nReport saved -> {output}\n"
    )


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
"""


def main():

    if len(sys.argv) < 3:

        print(USAGE)
        return

    command = sys.argv[1]
    password = sys.argv[2]

    if command == "hash":

        cmd_hash(password)

    elif command == "crack":

        cmd_crack(password)

    elif command == "breach":

        cmd_breach(password)

    elif command == "report":

        output = (
            sys.argv[3]
            if len(sys.argv) > 3
            else "report.png"
        )

        cmd_report(
            password,
            output
        )

    else:

        print(
            f"Unknown command: {command}"
        )


if __name__ == "__main__":
    main()