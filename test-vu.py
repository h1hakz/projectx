from flask import Flask, request, escape
import sqlite3
import subprocess
import hashlib

app = Flask(__name__)

# --- Database Setup ---
# WARNING: For demonstration purposes only.
def init_db():
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    # Drop table if it exists to ensure a clean state on restart
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    # Add a dummy user
    hashed_pass = hashlib.md5("strongpassword123".encode()).hexdigest() # Weak hash
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', hashed_pass))
    conn.commit()
    conn.close()

init_db()

# --- Vulnerable Routes ---

## 1. SQL Injection Vulnerability
# This route is vulnerable to SQL injection because it directly formats
# the user input into the SQL query string.
# Example exploit: /user?username=' OR 1=1 --
@app.route('/user')
def get_user():
    username = request.args.get('username')
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    
    # VULNERABLE LINE: User input is directly embedded in the query.
    query = f"SELECT username FROM users WHERE username = '{username}'"
    c.execute(query)
    
    user = c.fetchone()
    conn.close()
    
    if user:
        return f"<h1>User Found: {escape(user[0])}</h1>"
    else:
        return "<h1>User not found.</h1>", 404

## 2. Command Injection Vulnerability
# This route allows running a command-line utility (ping) with user-provided input.
# An attacker can inject additional commands.
# Example exploit: /ping?host=8.8.8.8; ls -la
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    
    # VULNERABLE LINE: User input is passed to a shell command.
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    
    return f"<pre>{escape(result.decode())}</pre>"

## 3. Hardcoded Secret / Insecure Default
# A hardcoded secret key is used, which is bad practice.
# Semgrep should be able to detect this.
app.config['SECRET_KEY'] = 'a-very-insecure-hardcoded-secret-key' 

if __name__ == '__main__':
    # Running in debug mode is also a security risk in production.
    app.run(debug=True)
