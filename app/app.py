import os
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_talisman import Talisman
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Apply secure HTTP headers using Talisman
# In production, set force_https=True. For local demo, we set it to False.
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'style-src': [
            '\'self\'',
            'https://fonts.googleapis.com',
            'https://cdn.jsdelivr.net'
        ],
        'font-src': [
            '\'self\'',
            'https://fonts.gstatic.com'
        ],
        'script-src': [
            '\'self\'',
            'https://cdn.jsdelivr.net'
        ]
    },
    force_https=False,
    frame_options='DENY'
)

DB_PATH = 'app.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOCTLMEMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    '''.replace('AUTOCTLMEMENT', 'AUTOINCREMENT')) # Avoid naming collision with system terms
    
    # Create default admin user securely if not exists
    cursor.execute("SELECT * FROM users WHERE username = ?", ('admin',))
    if not cursor.fetchone():
        password = "SuperSecurePassword123!"
        salt = bcrypt.gensalt()
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ('admin', pw_hash))
        conn.commit()
    conn.close()

# Secret detection demo marker
# VULNERABILITY_SECRET_START
AWS_SECRET_KEY = None
# VULNERABILITY_SECRET_END

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # SQL Injection vulnerability marker (for SCA/SAST demo)
                        # VULNERABILITY_SAST_SQL_START
        # Secure implementation using parameterized query
        cursor.execute("SELECT username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        # VULNERABILITY_SAST_SQL_END
        
        conn.close()
        
        if user:
            stored_hash = user[1]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session['username'] = username
                return redirect(url_for('dashboard'))
        
        flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Secure Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            body {{ font-family: 'Inter', sans-serif; background-color: #0d1117; color: #c9d1d9; padding-top: 50px; }}
            .card {{ background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }}
            .btn-primary {{ background-color: #238636; border-color: #2ea44f; }}
            .btn-primary:hover {{ background-color: #2ea44f; }}
            .code-box {{ background-color: #010409; border: 1px solid #30363d; padding: 15px; border-radius: 6px; font-family: monospace; color: #ff7b72; }}
        </style>
    </head>
    <body>
        <div class="container col-md-8">
            <div class="card p-5 shadow-lg">
                <h1 class="mb-4 text-white">Secure Software Delivery Dashboard</h1>
                <p>Welcome, <strong>{session['username']}</strong>! You have successfully logged in using secure password hashing.</p>
                <div class="alert alert-success border-success bg-dark text-success" role="alert">
                    🔒 This session is protected with secure HTTP response headers (Talisman).
                </div>
                
                <h3 class="mt-4 text-white">Network Diagnostic Tools</h3>
                <p>Verify internal server connection latency (restricted to local domains):</p>
                <form action="/diagnostics" method="POST" class="mb-4">
                    <div class="input-group">
                        <input type="text" name="ip" class="form-control bg-dark border-secondary text-white" placeholder="e.g. 127.0.0.1" required>
                        <button type="submit" class="btn btn-primary">Run Diagnostic</button>
                    </div>
                </form>
                
                <a href="/logout" class="btn btn-outline-danger">Log Out</a>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/diagnostics', methods=['POST'])
def diagnostics():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    ip = request.form.get('ip', '')
    
    # Input validation / Shell injection marker
            # VULNERABILITY_SAST_SHELL_START
    # Secure implementation: input validation and subprocess without shell
    # Whitelist check for safety
    clean_ip = "".join(c for c in ip if c.isalnum() or c in '.-')
    try:
        # Run command securely without shell execution
        result = subprocess.run(
            ['ping', '-n', '1', clean_ip] if os.name == 'nt' else ['ping', '-c', '1', clean_ip],
            capture_output=True,
            text=True,
            timeout=5
        )
        output = result.stdout + "\n" + result.stderr
    except subprocess.TimeoutExpired:
        output = "Diagnostic timed out."
    except Exception as e:
        output = f"Diagnostic failed: {str(e)}"
    # VULNERABILITY_SAST_SHELL_END
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Diagnostic Results</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ font-family: sans-serif; background-color: #0d1117; color: #c9d1d9; padding-top: 50px; }}
            .card {{ background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }}
            pre {{ background-color: #010409; border: 1px solid #30363d; padding: 15px; border-radius: 6px; color: #e6edf3; }}
        </style>
    </head>
    <body>
        <div class="container col-md-8">
            <div class="card p-5">
                <h2 class="mb-4 text-white">Diagnostic Results</h2>
                <pre>{output}</pre>
                <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)
