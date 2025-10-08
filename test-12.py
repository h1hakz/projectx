rom flask import Flask, request, escape
import sqlite3
import os

app = Flask(__name__)

# --- VULNERABILITY 1: Hardcoded Credentials ---
# The SECRET_KEY is a sensitive value that should not be stored directly in the code.
# CodeQL will flag this as a "Hard-coded credential".
app.config['SECRET_KEY'] = 'super-secret-key-that-should-not-be-here'

# --- Database Setup (for demonstration purposes) ---
def init_db():
    # Remove the database if it exists to start fresh
    if os.path.exists('test.db'):
        os.remove('test.db')
        
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            email TEXT NOT NULL
        )
    ''')
    c.execute("INSERT INTO users (username, email) VALUES (?, ?)", ('admin', 'admin@example.com'))
    conn.commit()
    conn.close()

init_db()

# --- VULNERABILITY 2: SQL Injection ---
@app.route('/user')
def get_user_data():
    """
    This route is vulnerable to SQL Injection. It takes a 'username' parameter
    from the URL and inserts it directly into the SQL query.
    
    Example of a malicious request:
    /user?username=' OR 1=1 --
    """
    username = request.args.get('username')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()

    # The f-string formatting allows an attacker to inject malicious SQL.
    # CodeQL will flag this as "SQL query built from user-controlled sources".
    query = f"SELECT email FROM users WHERE username = '{username}'"
    
    try:
        c.execute(query)
        user = c.fetchone()
    except sqlite3.Error as e:
        return f"<h1>Database Error: {e}</h1>", 500
    finally:
        conn.close()

    if user:
        return f"<h1>Email for {escape(username)}: {escape(user[0])}</h1>"
    else:
        return "<h1>User not found.</h1>", 404

# --- VULNERABILITY 3: Flask Debug Mode Enabled ---
if __name__ == '__main__':
    # Running the app with debug=True is insecure in a production environment.
    # It can expose a debugger and allow an attacker to execute arbitrary code.
    # CodeQL will flag this as "Flask app is run in debug mode".
    app.run(debug=True)
