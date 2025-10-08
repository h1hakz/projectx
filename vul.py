# vuln.py
import sqlite3
import sys
from pathlib import Path

DB = "test_vuln.db"

def init_db():
    # create a small users table
    if Path(DB).exists():
        Path(DB).unlink()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT INTO users (username, password) VALUES ('alice', 's3cr3t')")
    cur.execute("INSERT INTO users (username, password) VALUES ('bob', 'hunter2')")
    conn.commit()
    conn.close()

def find_user_unsafe(username):
    # VULNERABLE: building SQL via f-string (taint sink)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    print("[DEBUG] Executing query:", query)
    cur.execute(query)         # <-- tainted string executed directly
    rows = cur.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    init_db()
    if len(sys.argv) < 2:
        print("Usage: python vuln.py <username>")
        print("Examples:")
        print("  python vuln.py alice")
        print("  python vuln.py \"' OR '1'='1\"   # demonstrates injection")
        sys.exit(1)

    username = sys.argv[1]
    rows = find_user_unsafe(username)
    print("Result rows:", rows)
