import sqlite3
import sys

DB = "test.db"

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    # seed
    cur.execute("INSERT INTO users (username, password) VALUES ('alice','s3cr3t')")
    cur.execute("INSERT INTO users (username, password) VALUES ('bob','hunter2')")
    conn.commit()
    conn.close()

def find_user_unsafe(username):
    # **VULNERABLE**: direct string interpolation into SQL
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    print("[DEBUG] running query:", query)
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vuln.py <username>")
        print("Try user: alice")
        print("Try injection: ' OR '1'='1")
        sys.exit(1)

    init_db()
    user = sys.argv[1]
    result = find_user_unsafe(user)
    print("Result rows:", result)
