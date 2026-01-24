"""
CryptoLabs Proxy - Unified Authentication Module

Provides centralized authentication for all CryptoLabs services:
- IPMI Monitor
- DC Overview
- Grafana (via auth proxy)
- Prometheus (via auth proxy)

Services can operate in two modes:
1. Standalone: Use their own authentication
2. Fleet Mode: Trust auth headers from cryptolabs-proxy
"""

import os
import secrets
import hashlib
import hmac
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Tuple

from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================================
# CONFIGURATION
# =============================================================================

AUTH_SECRET_KEY = os.environ.get('AUTH_SECRET_KEY', secrets.token_hex(32))
AUTH_TOKEN_EXPIRY_HOURS = int(os.environ.get('AUTH_TOKEN_EXPIRY_HOURS', '24'))
AUTH_HEADER_USER = 'X-Fleet-Auth-User'
AUTH_HEADER_TOKEN = 'X-Fleet-Auth-Token'
AUTH_HEADER_ROLE = 'X-Fleet-Auth-Role'
AUTH_HEADER_TIMESTAMP = 'X-Fleet-Auth-Timestamp'

# Data directory for auth database
DATA_DIR = Path(os.environ.get('AUTH_DATA_DIR', '/data/auth'))


# =============================================================================
# TOKEN MANAGEMENT
# =============================================================================

def generate_auth_token(username: str, role: str = 'admin') -> Tuple[str, int]:
    """
    Generate a signed authentication token.
    
    Returns:
        Tuple of (token, expiry_timestamp)
    """
    expiry = int(time.time()) + (AUTH_TOKEN_EXPIRY_HOURS * 3600)
    
    # Create payload
    payload = f"{username}:{role}:{expiry}"
    
    # Sign with HMAC-SHA256
    signature = hmac.new(
        AUTH_SECRET_KEY.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Token format: payload.signature (base64 encoded)
    import base64
    token = base64.urlsafe_b64encode(
        f"{payload}.{signature}".encode()
    ).decode()
    
    return token, expiry


def verify_auth_token(token: str) -> Optional[dict]:
    """
    Verify a signed authentication token.
    
    Returns:
        dict with username, role, expiry if valid, None otherwise
    """
    try:
        import base64
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        
        parts = decoded.rsplit('.', 1)
        if len(parts) != 2:
            return None
        
        payload, signature = parts
        
        # Verify signature
        expected_sig = hmac.new(
            AUTH_SECRET_KEY.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_sig):
            return None
        
        # Parse payload
        username, role, expiry = payload.split(':')
        expiry = int(expiry)
        
        # Check expiry
        if time.time() > expiry:
            return None
        
        return {
            'username': username,
            'role': role,
            'expiry': expiry
        }
        
    except Exception:
        return None


def generate_proxy_headers(username: str, role: str = 'admin') -> dict:
    """
    Generate headers to be passed to backend services.
    
    These headers allow backend services to trust the proxy's authentication.
    """
    token, expiry = generate_auth_token(username, role)
    timestamp = str(int(time.time()))
    
    return {
        AUTH_HEADER_USER: username,
        AUTH_HEADER_ROLE: role,
        AUTH_HEADER_TOKEN: token,
        AUTH_HEADER_TIMESTAMP: timestamp,
    }


# =============================================================================
# USER MANAGEMENT (Simple file-based for proxy)
# =============================================================================

def get_users_file() -> Path:
    """Get path to users file."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / 'users.json'


def load_users() -> dict:
    """Load users from file."""
    users_file = get_users_file()
    if users_file.exists():
        try:
            return json.loads(users_file.read_text())
        except Exception:
            pass
    return {}


def save_users(users: dict):
    """Save users to file."""
    users_file = get_users_file()
    users_file.write_text(json.dumps(users, indent=2))
    os.chmod(users_file, 0o600)


def create_user(username: str, password: str, role: str = 'admin') -> bool:
    """Create a new user."""
    users = load_users()
    
    if username in users:
        return False
    
    users[username] = {
        'password_hash': generate_password_hash(password),
        'role': role,
        'created_at': datetime.utcnow().isoformat(),
    }
    
    save_users(users)
    return True


def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify user credentials."""
    users = load_users()
    
    user = users.get(username)
    if not user:
        return None
    
    if check_password_hash(user['password_hash'], password):
        return {
            'username': username,
            'role': user.get('role', 'admin'),
        }
    
    return None


def change_password(username: str, old_password: str, new_password: str) -> bool:
    """Change user password."""
    users = load_users()
    
    user = users.get(username)
    if not user:
        return False
    
    if not check_password_hash(user['password_hash'], old_password):
        return False
    
    users[username]['password_hash'] = generate_password_hash(new_password)
    save_users(users)
    return True


def user_exists() -> bool:
    """Check if any user exists."""
    users = load_users()
    return len(users) > 0


def get_first_user() -> Optional[str]:
    """Get the first/primary user."""
    users = load_users()
    if users:
        return list(users.keys())[0]
    return None


# =============================================================================
# BACKEND SERVICE INTEGRATION
# =============================================================================

def verify_proxy_auth(headers: dict) -> Optional[dict]:
    """
    Verify authentication headers from the proxy.
    
    Called by backend services (IPMI Monitor, DC Overview) to verify
    that a request came through an authenticated proxy session.
    
    Args:
        headers: Request headers dict
    
    Returns:
        dict with username, role if valid, None otherwise
    """
    token = headers.get(AUTH_HEADER_TOKEN)
    username = headers.get(AUTH_HEADER_USER)
    role = headers.get(AUTH_HEADER_ROLE)
    
    if not token or not username:
        return None
    
    # Verify token
    token_data = verify_auth_token(token)
    if not token_data:
        return None
    
    # Verify username matches
    if token_data['username'] != username:
        return None
    
    return {
        'username': username,
        'role': role or token_data.get('role', 'admin'),
        'authenticated_via': 'fleet_proxy'
    }


# =============================================================================
# FLASK INTEGRATION HELPERS
# =============================================================================

def create_flask_auth_app():
    """
    Create a Flask app for the proxy authentication API.
    
    This runs alongside nginx to handle login/logout/session management.
    """
    from flask import Flask, request, jsonify, session, redirect, render_template_string
    
    app = Flask(__name__)
    app.secret_key = AUTH_SECRET_KEY
    
    # Session cookie settings
    app.config['SESSION_COOKIE_NAME'] = 'fleet_session'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=AUTH_TOKEN_EXPIRY_HOURS)
    
    LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleet Management | Login</title>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-card: #1a1a24;
            --text-primary: #f0f0f0;
            --text-secondary: #888;
            --accent-cyan: #00d4ff;
            --accent-green: #4ade80;
            --accent-red: #ef4444;
            --border-color: #2a2a3a;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            margin: 20px;
        }
        .logo { font-size: 3rem; text-align: center; margin-bottom: 10px; }
        h1 {
            text-align: center;
            background: linear-gradient(135deg, var(--accent-cyan), #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .subtitle { text-align: center; color: var(--text-secondary); margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: var(--text-secondary); }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 1rem;
        }
        .form-group input:focus {
            outline: none;
            border-color: var(--accent-cyan);
        }
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, var(--accent-cyan), #0099cc);
            color: #000;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover { transform: scale(1.02); }
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
        .setup-notice {
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid var(--accent-cyan);
            color: var(--accent-cyan);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">🚀</div>
        <h1>Fleet Management</h1>
        <p class="subtitle">CryptoLabs Infrastructure Dashboard</p>
        
        {% if first_run %}
        <div class="setup-notice">
            Welcome! Create your admin account to get started.
        </div>
        {% endif %}
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" value="{{ username or 'admin' }}" required autofocus>
            </div>
            <div class="form-group">
                <label>{% if first_run %}Create Password{% else %}Password{% endif %}</label>
                <input type="password" name="password" required>
            </div>
            {% if first_run %}
            <div class="form-group">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" required>
            </div>
            {% endif %}
            <button type="submit" class="btn">
                {% if first_run %}Create Account{% else %}Login{% endif %}
            </button>
        </form>
    </div>
</body>
</html>
'''
    
    @app.route('/auth/login', methods=['GET', 'POST'])
    def login():
        error = None
        first_run = not user_exists()
        
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            if first_run:
                # First run - create account
                confirm_password = request.form.get('confirm_password', '')
                
                if len(password) < 4:
                    error = 'Password must be at least 4 characters'
                elif password != confirm_password:
                    error = 'Passwords do not match'
                else:
                    create_user(username, password, 'admin')
                    session['logged_in'] = True
                    session['username'] = username
                    session['role'] = 'admin'
                    session.permanent = True
                    
                    # Generate token for services
                    token, _ = generate_auth_token(username, 'admin')
                    session['auth_token'] = token
                    
                    return redirect('/')
            else:
                # Normal login
                user = verify_user(username, password)
                if user:
                    session['logged_in'] = True
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session.permanent = True
                    
                    # Generate token for services
                    token, _ = generate_auth_token(user['username'], user['role'])
                    session['auth_token'] = token
                    
                    return redirect(request.args.get('next', '/'))
                else:
                    error = 'Invalid username or password'
        
        return render_template_string(LOGIN_TEMPLATE, 
                                      error=error, 
                                      first_run=first_run,
                                      username=request.form.get('username', ''))
    
    @app.route('/auth/logout')
    def logout():
        session.clear()
        return redirect('/auth/login')
    
    @app.route('/auth/check')
    def check_auth():
        """API endpoint to check authentication status."""
        if session.get('logged_in'):
            return jsonify({
                'authenticated': True,
                'username': session.get('username'),
                'role': session.get('role'),
            })
        return jsonify({'authenticated': False}), 401
    
    @app.route('/auth/token')
    def get_token():
        """Get current auth token for service integration."""
        if not session.get('logged_in'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        token = session.get('auth_token')
        if not token or not verify_auth_token(token):
            # Regenerate token
            token, _ = generate_auth_token(
                session.get('username'), 
                session.get('role', 'admin')
            )
            session['auth_token'] = token
        
        return jsonify({
            'token': token,
            'username': session.get('username'),
            'role': session.get('role'),
        })
    
    @app.route('/auth/headers')
    def get_headers():
        """Get auth headers for nginx subrequest."""
        if not session.get('logged_in'):
            return '', 401
        
        username = session.get('username')
        role = session.get('role', 'admin')
        token = session.get('auth_token')
        
        if not token or not verify_auth_token(token):
            token, _ = generate_auth_token(username, role)
            session['auth_token'] = token
        
        # Return headers as JSON for nginx auth_request
        response = app.make_response('')
        response.status_code = 200
        response.headers[AUTH_HEADER_USER] = username
        response.headers[AUTH_HEADER_ROLE] = role
        response.headers[AUTH_HEADER_TOKEN] = token
        return response
    
    return app


# =============================================================================
# INITIALIZE DEFAULT USER
# =============================================================================

def ensure_default_user():
    """Ensure at least one user exists."""
    if not user_exists():
        # Check for environment variables
        default_user = os.environ.get('FLEET_ADMIN_USER', 'admin')
        default_pass = os.environ.get('FLEET_ADMIN_PASS')
        
        if default_pass:
            create_user(default_user, default_pass, 'admin')
            return True
    return False
