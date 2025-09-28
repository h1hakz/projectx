from flask import Flask, request, escape
import sqlite3
import subprocess
import hashlib

app = Flask(__name__)

# --- Hardcoded secret (should be flagged) ---
app.config['SECRET_KEY'] = 'this-is-a-hardcoded-secret'

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    # Weak hash example
    hashed_pass = hashlib.md5("password123".encode()).hexdigest()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', hashed_pass))
    conn.commit()
    conn.close()

init_db()

# --- Vulnerable Route 1: SQL Injection ---
@app.route('/user')
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('example.db')
    c = conn.cursor()

    # ❌ Vulnerable: f-string directly into SQL
    query = f"SELECT username FROM users WHERE username = '{username}'"
    c.execute(query)
    user = c.fetchone()
    conn.close()

    if user:
        return f"<h1>User Found: {escape(user[0])}</h1>"
    return "<h1>User not found.</h1>", 404

# --- Vulnerable Route 2: Command Injection ---
@app.route('/ping')
def ping_host():
    host = request.args.get('host')

    # ❌ Vulnerable: subprocess with shell=True
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return f"<pre>{escape(result.decode())}</pre>"

if __name__ == '__main__':
    app.run(debug=True)
