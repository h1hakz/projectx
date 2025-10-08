import hashlib
import os
import pickle
import sqlite3
import subprocess
import xml.etree.ElementTree as ET

import requests
from flask import Flask, request, escape, session, redirect

app = Flask(__name__)

# A05: Security Misconfiguration - Hardcoded secret key
app.config['SECRET_KEY'] = 'a-hardcoded-and-predictable-secret-key'

# --- Database Setup ---
def init_db():
    if os.path.exists('test.db'):
        os.remove('test.db')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL
        )
    ''')
    # A02: Cryptographic Failures - Use of a weak hashing algorithm (MD5)
    hashed_pass = hashlib.md5("password123".encode()).hexdigest()
    c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ('admin', hashed_pass, 1))
    c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", ('user', hashed_pass, 0))
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return "<h1>Vulnerable App Home</h1><p>Visit different endpoints to test vulnerabilities.</p>"

# --- A03: Injection (SQL Injection) ---
@app.route('/user_search')
def user_search():
    username = request.args.get('username')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    # VULNERABLE: Direct string formatting into a SQL query
    query = f"SELECT username FROM users WHERE username = '{username}'"
    c.execute(query)
    user = c.fetchone()
    conn.close()
    if user:
        return f"<h1>User Found: {escape(user[0])}</h1>"
    return "<h1>User not found.</h1>"

# --- A03: Injection (Command Injection) ---
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    # VULNERABLE: User input is passed directly to a shell command
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return f"<pre>{escape(result.decode())}</pre>"

# --- A01: Broken Access Control ---
@app.route('/admin')
def admin_panel():
    # VULNERABLE: Checks if 'username' is in session, but not if they are an admin
    if 'username' in session:
        return f"<h1>Welcome to the admin panel, {session['username']}!</h1>"
    return "<h1>Access Denied: You must be logged in.</h1>", 403

# --- A07: Identification and Authentication Failures & A09: Logging Failures ---
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    
    # A02: Still uses weak MD5 for comparison
    hashed_pass = hashlib.md5(password.encode()).hexdigest()
    
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_pass))
    user = c.fetchone()
    
    if user:
        session['username'] = user[0]
        # A09: Security Logging and Monitoring Failures - No log of successful login
        return redirect('/admin')
    else:
        # A09: Security Logging and Monitoring Failures - Failed login is not logged
        # A07: Username enumeration is possible due to a generic error message
        return "<h1>Invalid credentials</h1>", 401

# --- A08: Software and Data Integrity Failures (Insecure Deserialization) ---
@app.route('/deserialize')
def deserialize_data():
    data = request.args.get('data')
    if data:
        try:
            # VULNERABLE: Deserializing user-provided data with pickle can lead to RCE
            deserialized_object = pickle.loads(bytes.fromhex(data))
            return f"<h1>Deserialized object: {deserialized_object}</h1>"
        except Exception as e:
            return f"<h1>Error: {e}</h1>"
    return "<h1>Provide hex-encoded data to deserialize.</h1>"

# --- A10: Server-Side Request Forgery (SSRF) ---
@app.route('/fetch_url')
def fetch_url():
    url = request.args.get('url')
    if url:
        try:
            # VULNERABLE: Fetches any URL provided by the user, including internal ones
            response = requests.get(url, timeout=3)
            return f"<h1>Content from {escape(url)}:</h1><pre>{escape(response.text)}</pre>"
        except requests.exceptions.RequestException as e:
            return f"<h1>Failed to fetch URL: {e}</h1>"
    return "<h1>Provide a URL to fetch.</h1>"

# --- A05: Security Misconfiguration (XML External Entity - XXE) ---
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    if xml_data:
        try:
            # VULNERABLE: The default XML parser is susceptible to XXE attacks
            root = ET.fromstring(xml_data)
            return f"<h1>Parsed XML element: {root.tag}</h1>"
        except ET.ParseError as e:
            return f"<h1>XML Parse Error: {e}</h1>"
    return "<h1>POST XML data to this endpoint.</h1>"


# --- A06: Vulnerable and Outdated Components ---
# This cannot be demonstrated in a single file without external dependencies.
# Example: If this app used a known vulnerable version of Flask, like Flask 0.10,
# it would fall under this category. Always keep dependencies up to date.

if __name__ == '__main__':
    # A05: Security Misconfiguration - Running in debug mode
    app.run(debug=True)
