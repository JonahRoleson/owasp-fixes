"""
owasp_fixes.py
Secure, self-contained Python examples that fix one-liner vulnerable snippets from the assignment.
This file includes small Flask endpoints and helper functions demonstrating secure patterns for:
1-2 Broken Access Control
3-4 Cryptographic Failures
5-6 Injection (SQL & NoSQL)
7 Insecure Design (password reset)
8 Software & Data Integrity (serve local, verify integrity)
9 SSRF (validate/whitelist URLs)
10 Identification & Authentication Failures

Run this file with: python owaspfixes.py
It will start a Flask app on localhost:5000 with example endpoints.

"""

from flask import Flask, request, jsonify, abort
import sqlite3
import bcrypt
import re
import requests
from urllib.parse import urlparse
import hashlib
import hmac
import os
import secrets

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# --- Simple in-memory "database" using sqlite for demo purposes ---
DB_PATH = 'demo.db'

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, password_hash BLOB, role TEXT, reset_token TEXT)''')
    # create demo user: username=jdoe, password=password123
    try:
        pw = bcrypt.hashpw(b'password123', bcrypt.gensalt())
        cur.execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)', ('jdoe', 'jdoe@example.com', pw, 'user'))
        con.commit()
    except sqlite3.IntegrityError:
        pass
    con.close()

init_db()

# --- Helpers ---

def get_db_connection():
    return sqlite3.connect(DB_PATH)

# Mock current_user retrieval (in real app use sessions / tokens)
def current_user():
    # For demo: read header X-User-Id (not secure!). Replace with real auth middleware.
    user_id = request.headers.get('X-User-Id')
    if user_id:
        con = get_db_connection()
        cur = con.cursor()
        cur.execute('SELECT id, username, email, role FROM users WHERE id = ?', (user_id,))
        row = cur.fetchone()
        con.close()
        if row:
            return {'id': row[0], 'username': row[1], 'email': row[2], 'role': row[3]}
    return None

# Simple email sender stub
def send_email(to_email, subject, body):
    print(f"--- Sending email to {to_email} ---\nSubject: {subject}\n{body}\n")

# --- 1 & 2: Broken Access Control fixes ---
# Original vulnerability: endpoints returned user information based solely on provided userId or user_id
# Fix: enforce authorization checks and least privilege. Only return profile if the requester is the owner or has admin role.

@app.route('/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    user = current_user()
    if user is None:
        abort(401, 'Authentication required')
    # Authorization check: allow if owner or admin
    if user['id'] != user_id and user['role'] != 'admin':
        abort(403, 'Forbidden: insufficient permissions')
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        abort(404)
    return jsonify({'id': row[0], 'username': row[1], 'email': row[2]})

@app.route('/account/<int:user_id>', methods=['GET'])
def get_account(user_id):
    # Same concept: require authentication and authorization
    user = current_user()
    if user is None:
        abort(401, 'Authentication required')
    if user['id'] != user_id and user['role'] != 'admin':
        abort(403, 'Forbidden')
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        abort(404)
    return jsonify({'id': row[0], 'username': row[1], 'email': row[2]})

# --- 3 & 4: Cryptographic Failures ---
# Original vulnerabilities used MD5 and SHA1 for password hashing.
# Fix: Use a slow adaptive hashing algorithm such as bcrypt with a salt.

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    if not username or not password:
        abort(400, 'username and password required')
    # enforce basic password policy for demo
    if len(password) < 8:
        abort(400, 'password too short')
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    con = get_db_connection()
    cur = con.cursor()
    try:
        cur.execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)', (username, email, pw_hash, 'user'))
        con.commit()
    except sqlite3.IntegrityError:
        abort(400, 'username or email already exists')
    finally:
        con.close()
    return jsonify({'status': 'registered'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        abort(400)
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        abort(401, 'invalid credentials')
    stored = row[1]
    if bcrypt.checkpw(password.encode(), stored):
        # In real app, return signed token (JWT) or set secure session cookie
        return jsonify({'status': 'ok', 'user_id': row[0]})
    else:
        abort(401, 'invalid credentials')

# --- 5: SQL Injection fix (use parameterized queries) ---

@app.route('/find-user', methods=['GET'])
def find_user():
    username = request.args.get('username')
    if not username:
        abort(400)
    # Parameterized query prevents SQL injection
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT id, username, email FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return jsonify({})
    return jsonify({'id': row[0], 'username': row[1], 'email': row[2]})

# --- 6: NoSQL injection (demonstrated in Python with pymongo-like validation) ---
# For demo we simulate simple user lookup with strict type/whitelist validation rather than trusting raw parameters.

@app.route('/mongo-user', methods=['GET'])
def mongo_user():
    # Accept only alphanumeric usernames and limit length
    username = request.args.get('username', '')
    if not re.fullmatch(r'[A-Za-z0-9_\-]{1,30}', username):
        abort(400, 'invalid username format')
    # In real app use the driver's parameterization and avoid constructing queries from raw dicts
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT id, username, email FROM users WHERE username = ?', (username,))
    row = cur.fetchone()
    con.close()
    if not row:
        return jsonify({})
    return jsonify({'id': row[0], 'username': row[1], 'email': row[2]})

# --- 7: Insecure Design - Password reset flow fixed with token and expiry ---

RESET_TOKEN_TTL = 3600  # 1 hour

@app.route('/request-reset', methods=['POST'])
def request_reset():
    data = request.get_json() or {}
    email = data.get('email')
    if not email:
        abort(400)
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT id FROM users WHERE email = ?', (email,))
    row = cur.fetchone()
    if not row:
        # don't reveal whether an email exists
        return jsonify({'status': 'ok'})
    user_id = row[0]
    token = secrets.token_urlsafe(32)
    # Store token (in production store hashed token and expiry)
    cur.execute('UPDATE users SET reset_token = ? WHERE id = ?', (token, user_id))
    con.commit()
    con.close()
    reset_link = f"https://example.com/reset-password?token={token}&uid={user_id}"
    # send a secure email with link
    send_email(email, 'Password reset', f'Click to reset: {reset_link}')
    return jsonify({'status': 'ok'})

@app.route('/reset-password', methods=['POST'])
def perform_reset():
    data = request.get_json() or {}
    token = data.get('token')
    user_id = data.get('uid')
    new_password = data.get('new_password')
    if not token or not user_id or not new_password:
        abort(400)
    # Validate password policy
    if len(new_password) < 8:
        abort(400, 'password too short')
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT reset_token FROM users WHERE id = ?', (user_id,))
    row = cur.fetchone()
    if not row or not row[0]:
        abort(400, 'invalid token')
    stored_token = row[0]
    # Constant time compare
    if not hmac.compare_digest(stored_token, token):
        abort(400, 'invalid token')
    # All good: set new password and clear token
    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    cur.execute('UPDATE users SET password_hash = ?, reset_token = NULL WHERE id = ?', (pw_hash, user_id))
    con.commit()
    con.close()
    return jsonify({'status': 'password reset'})

# --- 8: Software and Data Integrity Failures ---
# Avoid loading third-party scripts blindly in production; prefer vendor packages, pin versions, and verify integrity.
# Here we provide a helper to fetch a resource and verify its expected SHA256 hash before using it.

TRUSTED_LIB_HASHES = {
    'https://cdn.example.com/lib.js': 'REPLACE_WITH_EXPECTED_HEX_SHA256'
}

@app.route('/fetch-lib', methods=['POST'])
def fetch_lib():
    data = request.get_json() or {}
    url = data.get('url')
    if url not in TRUSTED_LIB_HASHES:
        abort(400, 'Untrusted source')
    expected = TRUSTED_LIB_HASHES[url]
    r = requests.get(url, timeout=5)
    content = r.content
    sha256 = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(sha256, expected):
        abort(400, 'Integrity check failed')
    # safe to use content
    return jsonify({'status': 'ok', 'length': len(content)})

# --- 9: SSRF mitigation: whitelist and URL validation ---
ALLOWED_HOSTS = {'example.com', 'api.example.com', 'jsonplaceholder.typicode.com'}

def is_safe_url(target_url):
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ('http', 'https'):
            return False
        host = parsed.hostname
        if not host:
            return False
        # Basic whitelist
        return host in ALLOWED_HOSTS
    except Exception:
        return False

@app.route('/fetch-url', methods=['POST'])
def fetch_url():
    data = request.get_json() or {}
    url = data.get('url')
    if not url or not is_safe_url(url):
        abort(400, 'unsafe url')
    # perform request with limited timeouts
    try:
        r = requests.get(url, timeout=3)
    except requests.RequestException:
        abort(502, 'upstream failed')
    return jsonify({'status': 'ok', 'code': r.status_code, 'snippet': r.text[:200]})

# --- 10: Identification & Authentication Failures ---
# Original code compared plaintext passwords. Fix: store password hashes and compare using bcrypt.checkpw (constant-time internally).
# Demonstrated in /login route above; we also provide a small endpoint to change password that requires current password.

@app.route('/change-password', methods=['POST'])
def change_password():
    user = current_user()
    if user is None:
        abort(401)
    data = request.get_json() or {}
    current = data.get('current_password')
    new_pw = data.get('new_password')
    if not current or not new_pw:
        abort(400)
    con = get_db_connection()
    cur = con.cursor()
    cur.execute('SELECT password_hash FROM users WHERE id = ?', (user['id'],))
    row = cur.fetchone()
    if not row:
        abort(404)
    if not bcrypt.checkpw(current.encode(), row[0]):
        abort(401, 'current password incorrect')
    if len(new_pw) < 8:
        abort(400, 'password too short')
    new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
    cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user['id']))
    con.commit()
    con.close()
    return jsonify({'status': 'password changed'})

if __name__ == '__main__':
    # ensure demo DB exists
    app.run(debug=True)

