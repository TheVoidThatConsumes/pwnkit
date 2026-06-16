# pwnkit — Password Security Toolkit

A command-line tool that tests how safe a password is.  
Built as a cybersecurity portfolio project.

---

## What it does

| Command | What it checks |
|---|---|
| `hash` | Shows the password hashed in MD5, SHA-1, SHA-256, bcrypt, and Argon2id |
| `crack` | Tests whether the password appears in a common password wordlist |
| `breach` | Checks whether the password appears in a known data breach database |
| `report` | Runs all checks and saves a full analysis as a PNG file |

---

## Requirements

- Python 3.10 or higher
- The following packages:

```bash
pip install -r requirements.txt
```

---

## Setup

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Already included are demo data files for demo or educational purposes, but you can add your own to:
   - `pwned/breached_sha1.txt` — for a larger SHA-1 breach hash list  
     Download free from [haveibeenpwned.com/Passwords](https://haveibeenpwned.com/Passwords)
   - `wordlist/wordlist.txt` — for a larger password wordlist  
     Example: [SecLists rockyou](https://github.com/danielmiessler/SecLists)

---

## Usage

Open a terminal in the project folder and run:

```bash
python main.py hash    "yourpassword"
python main.py crack   "yourpassword"
python main.py breach  "yourpassword"
python main.py report  "yourpassword"
python main.py report  "yourpassword" myreport.png
```

Reports are saved to the `reports/` folder automatically.

---

## Example output

```
Password Hash Output
------------------------------------------------------------
Length   : 8
MD5      : 5f4dcc3b5aa765d61d8327deb882cf99
SHA-1    : 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
SHA-256  : 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
bcrypt   : $2b$12$...
Argon2id : $argon2id$...
```

```
Breach Check
------------------------------------------------------------
FOUND in breach database — do not use this password.
```

---

## How the checks work

**Hashing**  
Converts the password into a scrambled string using different algorithms. MD5 and SHA-256 are fast — an attacker can test millions per second. bcrypt and Argon2id are intentionally slow, making brute-force attacks impractical. This is why modern systems use them for password storage.

**Crack test**  
Checks whether the password appears as-is in a wordlist of commonly used passwords. If it does, an attacker would find it almost instantly.

**Breach check**  
Converts the password to a SHA-1 hash and checks it against a local copy of known breached password hashes. Nothing is sent over the internet — the check runs entirely offline.

**Report**  
Combines all three checks into a single PNG file with a colour-coded verdict: low risk, moderate risk, or high risk.

---

## Ethical use

This tool is for **authorised security testing only**.  
Only test passwords that belong to you.  
Do not use this tool to test or crack passwords without explicit permission.

---

## Skills demonstrated

- Python scripting and CLI design
- Cryptographic hashing (MD5, SHA-1, SHA-256, bcrypt, Argon2id)
- Offline breach database lookup
- Dictionary attack simulation
- Data visualisation with matplotlib
- Secure coding practices

---

## Author:
    Davide Obi  
    [github.com/TheVoidThatConsumes](https://github.com/TheVoidThatConsumes)