#!/usr/bin/env python3
"""
vul.py - combined vulnerable examples for testing CodeQL exclusions

Usage:
    python vul.py sql "<username>"
    python vul.py cmd "<directory_or_payload>"
    python vul.py subprocess "<directory_or_payload>"
    python vul.py secret
    python vul.py all

Notes:
- Intended for local/demo use only with disposable test DBs.
- Do NOT run destructive payloads; use harmless proof-of-concept inputs only.
"""

import sqlite3
import os
import sys
import subprocess
from pathlib import Path

# ----------------------------
# 1) Hardcoded secret example
# ----------------------------
# This demonstrates a secret hard-coded in source code (bad practice).
API_KEY = "AKIAFAKEEXAMPLEKEY12345"   # <-- hardcoded secret (vulnerable)
DB_PASSWORD = "P@ssw0rdEXAMPLE!"      # <-- hardcoded credential (vulnerable)

def hardcoded_secret_vuln():
    """Prints hardcoded secrets (vulnerable sample)."""
    print("[HARDSECRET] Using API_KEY:", API_KEY)
    print("[HARDSECRET] Using DB_PASSWORD:", DB_PASSWORD)
    # (In real apps, secrets should be read from env vars or secret managers)


# ----------------------------
# 2) SQL Injection (sqlite)
# ----------------------------
DB_SQL = "vuln_test.db"

def init_sql_db():
    """Create a small users table for the demo (idempotent)."""
    if Path(DB_SQL).exists():
        Path(DB_SQL).unlink()
    conn = sqlite3.connect(DB_SQL)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT INTO users (username, password) VALUES ('alice', 's3cr3t')")
    cur.execute("INSERT INTO users (username, password) VALUES ('bob', 'hunter2')")
    conn.commit()
    conn.close()
    print("[SQL] Initialized DB:", DB_SQL)

def sql_injection_vuln(username):
    """
    VULNERABLE: constructs SQL via f-string with user input.
    CodeQL should detect taint flow from `username` to `execute`.
    """
    conn = sqlite3.connect(DB_SQL)
    cur = conn.cursor()
    # Vulnerable string concatenation / interpolation:
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    print("[SQL] Executing (vulnerable):", query)
    try:
        cur.execute(query)   # <- tainted SQL executed directly
        rows = cur.fetchall()
        print("[SQL] Rows:", rows)
    except Exception as e:
        print("[SQL] Error executing query:", e)
    finally:
        conn.close()

# ----------------------------
# 3) OS Command Injection
# ----------------------------

def cmd_injection_vuln(arg):
    """
    VULNERABLE: uses os.system with concatenated user input.
    Example payload to demonstrate (harmless): "some_dir; echo INJECTED"
    """
    cmd = "ls -la " + arg
    print("[CMD(os.system)] Running:", cmd)
    # This executes the string in a shell -> injection possible
    os.system(cmd)

def subprocess_injection_vuln(arg):
    """
    VULNERABLE: uses subprocess.run with shell=True and user input placed into command.
    Example payload (harmless): "some_dir; echo INJECTED"
    """
    cmd = f"ls -la {arg}"
    print("[CMD(subprocess shell=True)] Running:", cmd)
    # shell=True makes the shell interpret special characters -> vulnerable
    subprocess.run(cmd, shell=True)


# ----------------------------
# Small driver / CLI
# ----------------------------
def usage():
    print(__doc__)

def run_all():
    print("=== Running all vulnerable demos ===\n")
    print("1) Hardcoded secret demo")
    hardcoded_secret_vuln()
    print("\n2) SQL injection demo (init + vuln query)")
    init_sql_db()
    print("-> safe example: python vul.py sql alice")
    print("-> injection example: python vul.py sql \"' OR '1'='1\"")
    print("Running injection example now with payload: \"' OR '1'='1\"")
    sql_injection_vuln("' OR '1'='1")
    print("\n3) Command injection (os.system) demo")
    print("-> example payload: \"nonexistent; echo INJECTED\"")
    cmd_injection_vuln("nonexistent; echo INJECTED")
    print("\n4) Command injection (subprocess shell=True) demo")
    subprocess_injection_vuln("nonexistent; echo INJECTED")
    print("\n=== Done ===")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "sql":
        init_sql_db()
        username = sys.argv[2] if len(sys.argv) > 2 else "alice"
        sql_injection_vuln(username)

    elif cmd == "cmd":
        if len(sys.argv) < 3:
            print("Usage: python vul.py cmd \"<directory_or_payload>\"")
            sys.exit(1)
        target = sys.argv[2]
        cmd_injection_vuln(target)

    elif cmd == "subprocess":
        if len(sys.argv) < 3:
            print("Usage: python vul.py subprocess \"<directory_or_payload>\"")
            sys.exit(1)
        target = sys.argv[2]
        subprocess_injection_vuln(target)

    elif cmd == "secret":
        hardcoded_secret_vuln()

    elif cmd == "all":
        run_all()

    else:
        print("Unknown command:", cmd)
        usage()
        sys.exit(1)
