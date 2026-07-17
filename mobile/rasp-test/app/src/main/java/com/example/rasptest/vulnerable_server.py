from flask import Flask, request
import subprocess
import sqlite3

app = Flask(__name__)

# Hardcoded password — triggers hardcoded-password rule
DB_PASSWORD = "SuperSecret123!"

@app.route("/query")
def query():
    name = request.args.get("name")
    # SQL injection via string concatenation
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cursor.fetchall()

@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection
    result = subprocess.call(["ping", "-c", "1", host])
    return str(result)

@app.route("/read")
def read_file():
    path = request.args.get("path")
    # Path traversal
    with open("/var/data/" + path) as f:
        return f.read()

@app.route("/eval")
def unsafe_eval():
    code = request.args.get("code")
    result = eval(code)
    return str(result)
