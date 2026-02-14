"""
CryptoLabs Proxy - Unified Authentication Module

Provides centralized authentication for all CryptoLabs services:
- IPMI Monitor
- DC Overview
- Grafana (via auth proxy)
- Prometheus (via auth proxy)

User Roles:
- admin: Full access to all features and user management
- readwrite: Can view and modify data, but cannot manage users
- readonly: Can only view data, no modifications
- anonymous: Public access (disabled by default)

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
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Tuple, List

from werkzeug.security import generate_password_hash, check_password_hash

# Module-level logger for auth operations
logger = logging.getLogger('cryptolabs_proxy.auth')

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

# DC Watchdog SSO Configuration
# API key (sk-ipmi-xxx) from CryptoLabs subscription - enables Auto-SSO
# This key is also used as the signing secret for SSO tokens (no separate secret needed!)
WATCHDOG_API_KEY = os.environ.get('WATCHDOG_API_KEY', '')
WATCHDOG_URL = os.environ.get('WATCHDOG_URL', 'https://watchdog.cryptolabs.co.za')
WATCHDOG_SIGNUP_URL = 'https://www.cryptolabs.co.za/dc-watchdog-signup/'

def get_watchdog_api_key() -> str:
    """Get the DC Watchdog API key from environment or persistent storage."""
    # First check persistent storage (for keys obtained via OAuth callback)
    key_file = DATA_DIR / 'watchdog_api_key'
    if key_file.exists():
        try:
            key = key_file.read_text().strip()
            # Ensure file is readable by other containers sharing fleet-auth-data volume
            # (dc-overview runs as dcuser, not root)
            try:
                current_mode = key_file.stat().st_mode & 0o777
                if current_mode != 0o644:
                    os.chmod(key_file, 0o644)
            except Exception:
                pass
            return key
        except Exception:
            pass
    
    # Then check environment variable
    if WATCHDOG_API_KEY:
        return WATCHDOG_API_KEY
    
    return ''


def is_watchdog_verified() -> bool:
    """Check if DC Watchdog has been verified via SSO.
    
    On fresh install, even if the API key is in env var (from setup config),
    we require the user to complete SSO to verify the account. Only then is
    DC Watchdog shown as "enabled" in Fleet Management.
    """
    verified_file = DATA_DIR / 'watchdog_verified'
    return verified_file.exists()


def set_watchdog_verified() -> bool:
    """Mark DC Watchdog as verified after SSO completion."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        verified_file = DATA_DIR / 'watchdog_verified'
        verified_file.write_text('1')
        logger.info(f"DC Watchdog verified flag set at {verified_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to set DC Watchdog verified flag: {e}")
        return False


def save_watchdog_api_key(api_key: str) -> bool:
    """Save the DC Watchdog API key to persistent storage."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        key_file = DATA_DIR / 'watchdog_api_key'
        key_file.write_text(api_key)
        # 0644 so other containers sharing fleet-auth-data volume can read it
        # (dc-overview runs as dcuser, not root)
        os.chmod(key_file, 0o644)
        return True
    except Exception:
        return False

# Valid roles (ordered by privilege level)
VALID_ROLES = ['admin', 'readwrite', 'readonly']

# Role hierarchy for permission checks
ROLE_HIERARCHY = {
    'admin': 3,
    'readwrite': 2,
    'readonly': 1,
    'anonymous': 0
}


# =============================================================================
# SETTINGS MANAGEMENT
# =============================================================================

def get_settings_file() -> Path:
    """Get path to settings file."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / 'settings.json'


def load_settings() -> dict:
    """Load settings from file."""
    settings_file = get_settings_file()
    defaults = {
        'allow_anonymous': False,
        'anonymous_role': 'readonly',
        'require_password_change': True,
        'session_timeout_hours': 24,
        'max_login_attempts': 5,
        'lockout_duration_minutes': 15,
    }
    
    if settings_file.exists():
        try:
            saved = json.loads(settings_file.read_text())
            defaults.update(saved)
        except Exception:
            pass
    
    return defaults


def save_settings(settings: dict):
    """Save settings to file."""
    settings_file = get_settings_file()
    settings_file.write_text(json.dumps(settings, indent=2))


def get_setting(key: str, default=None):
    """Get a single setting."""
    settings = load_settings()
    return settings.get(key, default)


def set_setting(key: str, value):
    """Set a single setting."""
    settings = load_settings()
    settings[key] = value
    save_settings(settings)


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
# USER MANAGEMENT
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


def create_user(username: str, password: str, role: str = 'readonly', 
                enabled: bool = True, require_password_change: bool = False) -> bool:
    """Create a new user."""
    users = load_users()
    
    if username in users:
        return False
    
    if role not in VALID_ROLES:
        role = 'readonly'
    
    users[username] = {
        'password_hash': generate_password_hash(password),
        'role': role,
        'enabled': enabled,
        'require_password_change': require_password_change,
        'created_at': datetime.utcnow().isoformat(),
        'last_login': None,
        'login_attempts': 0,
        'locked_until': None,
    }
    
    save_users(users)
    return True


def get_user(username: str) -> Optional[dict]:
    """Get user by username."""
    users = load_users()
    user = users.get(username)
    if user:
        return {'username': username, **user}
    return None


def list_users() -> List[dict]:
    """List all users (without password hashes)."""
    users = load_users()
    result = []
    for username, data in users.items():
        result.append({
            'username': username,
            'role': data.get('role', 'readonly'),
            'enabled': data.get('enabled', True),
            'created_at': data.get('created_at'),
            'last_login': data.get('last_login'),
            'require_password_change': data.get('require_password_change', False),
        })
    return result


def update_user(username: str, role: str = None, enabled: bool = None, 
                require_password_change: bool = None) -> bool:
    """Update user properties."""
    users = load_users()
    
    if username not in users:
        return False
    
    if role is not None and role in VALID_ROLES:
        users[username]['role'] = role
    
    if enabled is not None:
        users[username]['enabled'] = enabled
    
    if require_password_change is not None:
        users[username]['require_password_change'] = require_password_change
    
    save_users(users)
    return True


def delete_user(username: str) -> bool:
    """Delete a user."""
    users = load_users()
    
    if username not in users:
        return False
    
    # Prevent deleting last admin
    admins = [u for u, d in users.items() if d.get('role') == 'admin' and d.get('enabled', True)]
    if len(admins) <= 1 and username in admins:
        return False
    
    del users[username]
    save_users(users)
    return True


def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify user credentials."""
    users = load_users()
    
    user = users.get(username)
    if not user:
        return None
    
    # Check if user is enabled
    if not user.get('enabled', True):
        return None
    
    # Check if locked out
    locked_until = user.get('locked_until')
    if locked_until:
        if datetime.fromisoformat(locked_until) > datetime.utcnow():
            return None
        else:
            # Lockout expired, reset
            users[username]['locked_until'] = None
            users[username]['login_attempts'] = 0
    
    if check_password_hash(user['password_hash'], password):
        # Successful login - update stats
        users[username]['last_login'] = datetime.utcnow().isoformat()
        users[username]['login_attempts'] = 0
        users[username]['locked_until'] = None
        save_users(users)
        
        return {
            'username': username,
            'role': user.get('role', 'readonly'),
            'require_password_change': user.get('require_password_change', False),
        }
    else:
        # Failed login - increment attempts
        attempts = user.get('login_attempts', 0) + 1
        users[username]['login_attempts'] = attempts
        
        max_attempts = get_setting('max_login_attempts', 5)
        if attempts >= max_attempts:
            lockout_mins = get_setting('lockout_duration_minutes', 15)
            users[username]['locked_until'] = (
                datetime.utcnow() + timedelta(minutes=lockout_mins)
            ).isoformat()
        
        save_users(users)
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
    users[username]['require_password_change'] = False
    save_users(users)
    return True


def admin_set_password(username: str, new_password: str) -> bool:
    """Admin reset password (no old password required)."""
    users = load_users()
    
    if username not in users:
        return False
    
    users[username]['password_hash'] = generate_password_hash(new_password)
    users[username]['require_password_change'] = True
    save_users(users)
    return True


def user_exists() -> bool:
    """Check if any user exists."""
    users = load_users()
    return len(users) > 0


def get_admin_count() -> int:
    """Count enabled admin users."""
    users = load_users()
    return len([u for u, d in users.items() 
                if d.get('role') == 'admin' and d.get('enabled', True)])


# =============================================================================
# PERMISSION HELPERS
# =============================================================================

def has_permission(user_role: str, required_role: str) -> bool:
    """Check if user role has sufficient permissions."""
    user_level = ROLE_HIERARCHY.get(user_role, 0)
    required_level = ROLE_HIERARCHY.get(required_role, 0)
    return user_level >= required_level


def can_admin(role: str) -> bool:
    """Check if role can perform admin actions."""
    return has_permission(role, 'admin')


def can_write(role: str) -> bool:
    """Check if role can perform write actions."""
    return has_permission(role, 'readwrite')


def can_read(role: str) -> bool:
    """Check if role can perform read actions."""
    return has_permission(role, 'readonly')


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
        'role': role or token_data.get('role', 'readonly'),
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
    
    # =========================================================================
    # TEMPLATES
    # =========================================================================
    
    BASE_STYLE = '''
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a24;
            --text-primary: #f0f0f0;
            --text-secondary: #888;
            --accent-cyan: #00d4ff;
            --accent-green: #4ade80;
            --accent-yellow: #fbbf24;
            --accent-red: #ef4444;
            --border-color: #2a2a3a;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 20px;
        }
        .card h2 { margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: var(--text-secondary); }
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 1rem;
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--accent-cyan);
        }
        .btn {
            padding: 12px 24px;
            background: linear-gradient(135deg, var(--accent-cyan), #0099cc);
            color: #000;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { transform: scale(1.02); }
        .btn-secondary {
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        .btn-danger { background: var(--accent-red); color: #fff; }
        .btn-sm { padding: 8px 16px; font-size: 0.85rem; }
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .success {
            background: rgba(74, 222, 128, 0.1);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
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
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
        th { color: var(--text-secondary); font-weight: 500; }
        .badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .badge-admin { background: var(--accent-cyan); color: #000; }
        .badge-readwrite { background: var(--accent-green); color: #000; }
        .badge-readonly { background: var(--accent-yellow); color: #000; }
        .badge-disabled { background: var(--text-secondary); color: #000; }
        .nav {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
        }
        .nav a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
        }
        .nav a:hover, .nav a.active {
            color: var(--text-primary);
            background: var(--bg-secondary);
        }
        .toggle {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 26px;
        }
        .toggle input { opacity: 0; width: 0; height: 0; }
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 26px;
            transition: 0.3s;
        }
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 2px;
            bottom: 2px;
            background: var(--text-secondary);
            border-radius: 50%;
            transition: 0.3s;
        }
        .toggle input:checked + .toggle-slider { background: var(--accent-cyan); }
        .toggle input:checked + .toggle-slider:before {
            transform: translateX(24px);
            background: #000;
        }
    '''
    
    LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleet Management | Login</title>
    <style>''' + BASE_STYLE + '''
        body {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            width: 100%;
            max-width: 400px;
            margin: 20px;
        }
        .logo { text-align: center; margin-bottom: 15px; }
        .logo svg { width: 80px; height: 80px; filter: drop-shadow(0 0 10px rgba(79, 195, 247, 0.4)); }
        h1 {
            text-align: center;
            background: linear-gradient(135deg, var(--accent-cyan), #00ff88);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .subtitle { text-align: center; color: var(--text-secondary); margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="card">
            <div class="logo"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><path d="M52 24c0-8.8-7.2-16-16-16-6.6 0-12.3 4-14.7 9.7C19.9 17.3 18.5 17 17 17c-5.5 0-10 4.5-10 10 0 .3 0 .7.1 1C4.1 29.4 2 32.5 2 36c0 5 4 9 9 9h7v-3H11c-3.3 0-6-2.7-6-6 0-2.6 1.7-4.9 4.1-5.7l1.4-.5-.2-1.5c0-.4-.1-.9-.1-1.3 0-3.9 3.1-7 7-7 1.3 0 2.5.4 3.5 1l1.5 1 .6-1.7C24.5 15.4 29.8 11 36 11c7.2 0 13 5.8 13 13v2h2c4.4 0 8 3.6 8 8s-3.6 8-8 8h-5v3h5c6.1 0 11-4.9 11-11 0-5.5-4.1-10.1-9.4-10.9L52 24z" fill="#4FC3F7"/><rect x="18" y="36" width="28" height="8" rx="2" fill="#4FC3F7"/><circle cx="23" cy="40" r="2" fill="#4CAF50"/><circle cx="29" cy="40" r="2" fill="#FFC107"/><rect x="38" y="38" width="5" height="4" rx="1" fill="#fff" opacity="0.5"/><rect x="18" y="46" width="28" height="8" rx="2" fill="#29B6F6"/><circle cx="23" cy="50" r="2" fill="#4CAF50"/><circle cx="29" cy="50" r="2" fill="#FFC107"/><rect x="38" y="48" width="5" height="4" rx="1" fill="#fff" opacity="0.5"/><rect x="30" y="54" width="4" height="6" fill="#29B6F6"/><rect x="24" y="58" width="16" height="4" rx="1" fill="#29B6F6"/></svg></div>
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
                <button type="submit" class="btn" style="width: 100%;">
                    {% if first_run %}Create Account{% else %}Login{% endif %}
                </button>
            </form>
        </div>
    </div>
</body>
</html>
'''

    USERS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleet Management | Users</title>
    <style>''' + BASE_STYLE + '''</style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;"><path d="M52 24c0-8.8-7.2-16-16-16-6.6 0-12.3 4-14.7 9.7C19.9 17.3 18.5 17 17 17c-5.5 0-10 4.5-10 10 0 .3 0 .7.1 1C4.1 29.4 2 32.5 2 36c0 5 4 9 9 9h7v-3H11c-3.3 0-6-2.7-6-6 0-2.6 1.7-4.9 4.1-5.7l1.4-.5-.2-1.5c0-.4-.1-.9-.1-1.3 0-3.9 3.1-7 7-7 1.3 0 2.5.4 3.5 1l1.5 1 .6-1.7C24.5 15.4 29.8 11 36 11c7.2 0 13 5.8 13 13v2h2c4.4 0 8 3.6 8 8s-3.6 8-8 8h-5v3h5c6.1 0 11-4.9 11-11 0-5.5-4.1-10.1-9.4-10.9L52 24z" fill="#4FC3F7"/><rect x="18" y="36" width="28" height="8" rx="2" fill="#4FC3F7"/><rect x="18" y="46" width="28" height="8" rx="2" fill="#29B6F6"/></svg> Dashboard</a>
            <a href="/auth/users" class="active">👥 Users</a>
            <a href="/auth/settings">⚙️ Settings</a>
            <a href="/auth/logout">Logout</a>
        </div>
        
        <h1 style="margin-bottom: 30px;">User Management</h1>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        {% if success %}
        <div class="success">{{ success }}</div>
        {% endif %}
        
        <div class="card">
            <h2>Add User</h2>
            <form method="POST" action="/auth/users/create">
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 15px; align-items: end;">
                    <div class="form-group" style="margin: 0;">
                        <label>Username</label>
                        <input type="text" name="username" required>
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label>Password</label>
                        <input type="password" name="password" required>
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label>Role</label>
                        <select name="role">
                            <option value="readonly">Read Only</option>
                            <option value="readwrite">Read/Write</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <button type="submit" class="btn">Add User</button>
                </div>
            </form>
        </div>
        
        <div class="card">
            <h2>Users ({{ users|length }})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td><strong>{{ user.username }}</strong>
                            {% if user.require_password_change %}
                            <span style="color: var(--accent-yellow); font-size: 0.8rem;" title="Must change password on next login">🔑</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if user.username != current_user %}
                            <form method="POST" action="/auth/users/{{ user.username }}/role" style="display: inline;">
                                <select name="role" onchange="this.form.submit()" style="background: var(--bg-secondary); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 4px; padding: 2px 6px; font-size: 0.85rem; cursor: pointer;">
                                    <option value="readonly" {{ 'selected' if user.role == 'readonly' }}>readonly</option>
                                    <option value="readwrite" {{ 'selected' if user.role == 'readwrite' }}>readwrite</option>
                                    <option value="admin" {{ 'selected' if user.role == 'admin' }}>admin</option>
                                </select>
                            </form>
                            {% else %}
                            <span class="badge badge-{{ user.role }}">{{ user.role }}</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if user.enabled %}
                            <span style="color: var(--accent-green);">● Enabled</span>
                            {% else %}
                            <span style="color: var(--text-secondary);">○ Disabled</span>
                            {% endif %}
                        </td>
                        <td>{{ user.last_login[:10] if user.last_login else '—' }}</td>
                        <td>
                            {% if user.username != current_user %}
                            <button type="button" class="btn btn-secondary btn-sm" onclick="toggleResetForm('{{ user.username }}')" title="Reset Password">🔑 Reset</button>
                            <form method="POST" action="/auth/users/{{ user.username }}/toggle" style="display: inline;">
                                <button type="submit" class="btn btn-secondary btn-sm">
                                    {{ 'Disable' if user.enabled else 'Enable' }}
                                </button>
                            </form>
                            <form method="POST" action="/auth/users/{{ user.username }}/delete" style="display: inline;" 
                                  onsubmit="return confirm('Delete user {{ user.username }}?')">
                                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                            </form>
                            {% else %}
                            <a href="/auth/change-password" class="btn btn-secondary btn-sm" title="Change your password">🔑 Change Password</a>
                            <span style="color: var(--text-secondary); margin-left: 4px;">(you)</span>
                            {% endif %}
                        </td>
                    </tr>
                    <tr id="reset-row-{{ user.username }}" style="display: none;">
                        <td colspan="5" style="background: var(--bg-secondary); border-top: none;">
                            <form method="POST" action="/auth/users/{{ user.username }}/reset-password" style="display: flex; align-items: center; gap: 10px; padding: 5px 0;">
                                <label style="white-space: nowrap; font-size: 0.9rem;">New password for <strong>{{ user.username }}</strong>:</label>
                                <input type="password" name="new_password" required minlength="4" placeholder="Min 4 characters" style="flex: 1; max-width: 250px; padding: 6px 10px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 4px; color: var(--text-primary);">
                                <button type="submit" class="btn btn-sm">Set &amp; Force Change</button>
                                <button type="button" class="btn btn-secondary btn-sm" onclick="toggleResetForm('{{ user.username }}')">Cancel</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    <script>
    function toggleResetForm(username) {
        var row = document.getElementById('reset-row-' + username);
        if (row.style.display === 'none') {
            // Hide all other open reset forms first
            document.querySelectorAll('[id^="reset-row-"]').forEach(function(r) { r.style.display = 'none'; });
            row.style.display = 'table-row';
            row.querySelector('input[type="password"]').focus();
        } else {
            row.style.display = 'none';
        }
    }
    </script>
</body>
</html>
'''

    SETTINGS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleet Management | Settings</title>
    <style>''' + BASE_STYLE + '''</style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;"><path d="M52 24c0-8.8-7.2-16-16-16-6.6 0-12.3 4-14.7 9.7C19.9 17.3 18.5 17 17 17c-5.5 0-10 4.5-10 10 0 .3 0 .7.1 1C4.1 29.4 2 32.5 2 36c0 5 4 9 9 9h7v-3H11c-3.3 0-6-2.7-6-6 0-2.6 1.7-4.9 4.1-5.7l1.4-.5-.2-1.5c0-.4-.1-.9-.1-1.3 0-3.9 3.1-7 7-7 1.3 0 2.5.4 3.5 1l1.5 1 .6-1.7C24.5 15.4 29.8 11 36 11c7.2 0 13 5.8 13 13v2h2c4.4 0 8 3.6 8 8s-3.6 8-8 8h-5v3h5c6.1 0 11-4.9 11-11 0-5.5-4.1-10.1-9.4-10.9L52 24z" fill="#4FC3F7"/><rect x="18" y="36" width="28" height="8" rx="2" fill="#4FC3F7"/><rect x="18" y="46" width="28" height="8" rx="2" fill="#29B6F6"/></svg> Dashboard</a>
            <a href="/auth/users">👥 Users</a>
            <a href="/auth/settings" class="active">⚙️ Settings</a>
            <a href="/auth/logout">Logout</a>
        </div>
        
        <h1 style="margin-bottom: 30px;">Security Settings</h1>
        
        {% if success %}
        <div class="success">{{ success }}</div>
        {% endif %}
        
        <div class="card">
            <h2>Access Control</h2>
            <form method="POST">
                <div class="form-group">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong>Allow Anonymous Access</strong>
                            <p style="color: var(--text-secondary); margin-top: 5px; font-size: 0.9rem;">
                                When enabled, unauthenticated users can access the dashboard with read-only permissions.
                                <br><strong style="color: var(--accent-yellow);">⚠️ Not recommended for production.</strong>
                            </p>
                        </div>
                        <label class="toggle">
                            <input type="checkbox" name="allow_anonymous" {{ 'checked' if settings.allow_anonymous }}>
                            <span class="toggle-slider"></span>
                        </label>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Anonymous User Role (if enabled)</label>
                    <select name="anonymous_role">
                        <option value="readonly" {{ 'selected' if settings.anonymous_role == 'readonly' }}>Read Only</option>
                    </select>
                </div>
                
                <hr style="border: none; border-top: 1px solid var(--border-color); margin: 25px 0;">
                
                <div class="form-group">
                    <label>Session Timeout (hours)</label>
                    <input type="number" name="session_timeout_hours" value="{{ settings.session_timeout_hours }}" min="1" max="720">
                </div>
                
                <div class="form-group">
                    <label>Max Login Attempts Before Lockout</label>
                    <input type="number" name="max_login_attempts" value="{{ settings.max_login_attempts }}" min="3" max="20">
                </div>
                
                <div class="form-group">
                    <label>Lockout Duration (minutes)</label>
                    <input type="number" name="lockout_duration_minutes" value="{{ settings.lockout_duration_minutes }}" min="5" max="60">
                </div>
                
                <button type="submit" class="btn">Save Settings</button>
            </form>
        </div>
        
        <div class="card">
            <h2>Role Permissions</h2>
            <table>
                <thead>
                    <tr>
                        <th>Role</th>
                        <th>View Dashboard</th>
                        <th>Modify Data</th>
                        <th>Manage Users</th>
                        <th>System Settings</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="badge badge-admin">admin</span></td>
                        <td>✅</td><td>✅</td><td>✅</td><td>✅</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-readwrite">readwrite</span></td>
                        <td>✅</td><td>✅</td><td>❌</td><td>❌</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-readonly">readonly</span></td>
                        <td>✅</td><td>❌</td><td>❌</td><td>❌</td>
                    </tr>
                    <tr>
                        <td><span class="badge badge-disabled">anonymous</span></td>
                        <td>✅ (if enabled)</td><td>❌</td><td>❌</td><td>❌</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
'''

    CHANGE_PASSWORD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleet Management | Change Password</title>
    <style>''' + BASE_STYLE + '''
        body { display: flex; align-items: center; justify-content: center; }
        .card { max-width: 400px; margin: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Change Password</h2>
        <p style="color: var(--text-secondary); margin-bottom: 20px;">
            You are required to change your password before continuing.
        </p>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label>Current Password</label>
                <input type="password" name="current_password" required autofocus>
            </div>
            <div class="form-group">
                <label>New Password</label>
                <input type="password" name="new_password" required>
            </div>
            <div class="form-group">
                <label>Confirm New Password</label>
                <input type="password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn" style="width: 100%;">Change Password</button>
        </form>
    </div>
</body>
</html>
'''

    # =========================================================================
    # DECORATORS
    # =========================================================================
    
    def login_required_decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect('/auth/login')
            return f(*args, **kwargs)
        return decorated
    
    def admin_required_decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect('/auth/login')
            if session.get('role') != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            return f(*args, **kwargs)
        return decorated

    # =========================================================================
    # ROUTES
    # =========================================================================
    
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
                    session['require_password_change'] = user.get('require_password_change', False)
                    session.permanent = True
                    
                    token, _ = generate_auth_token(user['username'], user['role'])
                    session['auth_token'] = token
                    
                    # Redirect to password change if required
                    if user.get('require_password_change'):
                        return redirect('/auth/change-password')
                    
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
    
    @app.route('/auth/change-password', methods=['GET', 'POST'])
    @login_required_decorator
    def change_password_route():
        error = None
        
        if request.method == 'POST':
            current = request.form.get('current_password', '')
            new_pass = request.form.get('new_password', '')
            confirm = request.form.get('confirm_password', '')
            
            if len(new_pass) < 4:
                error = 'Password must be at least 4 characters'
            elif new_pass != confirm:
                error = 'Passwords do not match'
            elif change_password(session['username'], current, new_pass):
                session['require_password_change'] = False
                return redirect('/')
            else:
                error = 'Current password is incorrect'
        
        return render_template_string(CHANGE_PASSWORD_TEMPLATE, error=error)
    
    @app.route('/auth/users')
    @admin_required_decorator
    def users_list():
        users = list_users()
        return render_template_string(USERS_TEMPLATE, 
                                      users=users,
                                      current_user=session.get('username'),
                                      error=request.args.get('error'),
                                      success=request.args.get('success'))
    
    @app.route('/auth/users/create', methods=['POST'])
    @admin_required_decorator
    def users_create():
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'readonly')
        
        if not username or not password:
            return redirect('/auth/users?error=Username+and+password+required')
        
        if create_user(username, password, role, require_password_change=True):
            return redirect(f'/auth/users?success=User+{username}+created')
        else:
            return redirect('/auth/users?error=User+already+exists')
    
    @app.route('/auth/users/<username>/toggle', methods=['POST'])
    @admin_required_decorator
    def users_toggle(username):
        user = get_user(username)
        if user:
            update_user(username, enabled=not user.get('enabled', True))
            return redirect('/auth/users?success=User+updated')
        return redirect('/auth/users?error=User+not+found')
    
    @app.route('/auth/users/<username>/delete', methods=['POST'])
    @admin_required_decorator
    def users_delete(username):
        if delete_user(username):
            return redirect('/auth/users?success=User+deleted')
        return redirect('/auth/users?error=Cannot+delete+user')
    
    @app.route('/auth/users/<username>/reset-password', methods=['POST'])
    @admin_required_decorator
    def users_reset_password(username):
        new_password = request.form.get('new_password', '').strip()
        if not new_password or len(new_password) < 4:
            return redirect('/auth/users?error=Password+must+be+at+least+4+characters')
        if admin_set_password(username, new_password):
            return redirect(f'/auth/users?success=Password+reset+for+{username}.+They+must+change+it+on+next+login.')
        return redirect('/auth/users?error=User+not+found')
    
    @app.route('/auth/users/<username>/role', methods=['POST'])
    @admin_required_decorator
    def users_change_role(username):
        new_role = request.form.get('role', '')
        if new_role not in VALID_ROLES:
            return redirect('/auth/users?error=Invalid+role')
        if username == session.get('username'):
            return redirect('/auth/users?error=Cannot+change+your+own+role')
        if update_user(username, role=new_role):
            return redirect(f'/auth/users?success=Role+updated+to+{new_role}+for+{username}')
        return redirect('/auth/users?error=User+not+found')
    
    @app.route('/auth/settings', methods=['GET', 'POST'])
    @admin_required_decorator
    def settings_page():
        success = None
        
        if request.method == 'POST':
            settings = load_settings()
            settings['allow_anonymous'] = 'allow_anonymous' in request.form
            settings['anonymous_role'] = request.form.get('anonymous_role', 'readonly')
            settings['session_timeout_hours'] = int(request.form.get('session_timeout_hours', 24))
            settings['max_login_attempts'] = int(request.form.get('max_login_attempts', 5))
            settings['lockout_duration_minutes'] = int(request.form.get('lockout_duration_minutes', 15))
            save_settings(settings)
            success = 'Settings saved successfully'
        
        return render_template_string(SETTINGS_TEMPLATE,
                                      settings=load_settings(),
                                      success=success)
    
    @app.route('/auth/check')
    def check_auth():
        """API endpoint to check authentication status."""
        if session.get('logged_in'):
            return jsonify({
                'authenticated': True,
                'username': session.get('username'),
                'role': session.get('role'),
            })
        
        # Check if anonymous access is allowed
        if get_setting('allow_anonymous', False):
            return jsonify({
                'authenticated': True,
                'username': 'anonymous',
                'role': get_setting('anonymous_role', 'readonly'),
            })
        
        return jsonify({'authenticated': False}), 401
    
    @app.route('/auth/token')
    def get_token():
        """Get current auth token for service integration."""
        if not session.get('logged_in'):
            # Check anonymous access
            if get_setting('allow_anonymous', False):
                token, _ = generate_auth_token('anonymous', get_setting('anonymous_role', 'readonly'))
                return jsonify({
                    'token': token,
                    'username': 'anonymous',
                    'role': get_setting('anonymous_role', 'readonly'),
                })
            return jsonify({'error': 'Not authenticated'}), 401
        
        token = session.get('auth_token')
        if not token or not verify_auth_token(token):
            token, _ = generate_auth_token(
                session.get('username'), 
                session.get('role', 'readonly')
            )
            session['auth_token'] = token
        
        return jsonify({
            'token': token,
            'username': session.get('username'),
            'role': session.get('role'),
        })
    
    def _get_exporter_mgmt_token() -> str:
        """Get the exporter management API token.
        
        The container env var is the source of truth (set by whoever deployed
        the exporter — either fleet_manager.py or exporter_manager.py).
        Docker inspect is checked first; local file is only a fallback.
        
        Result is cached for 60s to avoid repeated docker inspect calls.
        """
        import time as _time
        now = _time.time()
        if not hasattr(_get_exporter_mgmt_token, '_cached'):
            _get_exporter_mgmt_token._cached = ''
            _get_exporter_mgmt_token._ts = 0
        
        # Return cache if fresh (60s TTL)
        if (now - _get_exporter_mgmt_token._ts) < 60:
            return _get_exporter_mgmt_token._cached
        
        token = ''
        
        # Source 1 (truth): read MGMT_TOKEN from a running exporter container
        for container in ('vastai-exporter', 'runpod-exporter'):
            try:
                import subprocess as _sp
                result = _sp.run(
                    ["docker", "inspect", "--format",
                     "{{range .Config.Env}}{{println .}}{{end}}", container],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.startswith('MGMT_TOKEN='):
                            token = line.split('=', 1)[1]
                            # Persist to file so it stays in sync
                            try:
                                token_file = DATA_DIR / 'exporter-mgmt-token'
                                DATA_DIR.mkdir(parents=True, exist_ok=True)
                                token_file.write_text(token)
                            except Exception:
                                pass
                            break
                if token:
                    break
            except Exception:
                pass
        
        # Source 2 (fallback): local file (if no exporter containers are running)
        if not token:
            token_file = DATA_DIR / 'exporter-mgmt-token'
            try:
                if token_file.exists():
                    token = token_file.read_text().strip()
            except Exception:
                pass
        
        _get_exporter_mgmt_token._cached = token
        _get_exporter_mgmt_token._ts = now
        return token
    
    @app.route('/auth/headers')
    def get_headers():
        """Get auth headers for nginx subrequest.
        
        Also includes X-Mgmt-Token for exporter management API proxying.
        Nginx captures this via auth_request_set and forwards it to
        the exporter containers.
        """
        # Check for logged in user first
        if session.get('logged_in'):
            # Check if password change required
            if session.get('require_password_change'):
                return '', 401
            
            username = session.get('username')
            role = session.get('role', 'readonly')
            token = session.get('auth_token')
            
            if not token or not verify_auth_token(token):
                token, _ = generate_auth_token(username, role)
                session['auth_token'] = token
            
            response = app.make_response('')
            response.status_code = 200
            response.headers[AUTH_HEADER_USER] = username
            response.headers[AUTH_HEADER_ROLE] = role
            response.headers[AUTH_HEADER_TOKEN] = token
            # Include exporter management token for nginx to forward
            mgmt_token = _get_exporter_mgmt_token()
            if mgmt_token:
                response.headers['X-Mgmt-Token'] = mgmt_token
            return response
        
        # Check if anonymous access is allowed
        if get_setting('allow_anonymous', False):
            role = get_setting('anonymous_role', 'readonly')
            token, _ = generate_auth_token('anonymous', role)
            
            response = app.make_response('')
            response.status_code = 200
            response.headers[AUTH_HEADER_USER] = 'anonymous'
            response.headers[AUTH_HEADER_ROLE] = role
            response.headers[AUTH_HEADER_TOKEN] = token
            return response
        
        return '', 401
    
    # API endpoints for programmatic access
    @app.route('/auth/api/users', methods=['GET'])
    @admin_required_decorator
    def api_users_list():
        return jsonify(list_users())
    
    @app.route('/auth/api/users', methods=['POST'])
    @admin_required_decorator
    def api_users_create():
        data = request.json
        if create_user(
            data.get('username'),
            data.get('password'),
            data.get('role', 'readonly'),
            require_password_change=data.get('require_password_change', True)
        ):
            return jsonify({'success': True})
        return jsonify({'error': 'User already exists'}), 400
    
    @app.route('/auth/api/settings', methods=['GET'])
    @admin_required_decorator
    def api_settings_get():
        return jsonify(load_settings())
    
    @app.route('/auth/api/settings', methods=['POST'])
    @admin_required_decorator
    def api_settings_set():
        settings = load_settings()
        settings.update(request.json)
        save_settings(settings)
        return jsonify({'success': True})
    
    # =========================================================================
    # EXPORTER MANAGEMENT (Vast.ai / RunPod)
    # =========================================================================
    
    @app.route('/auth/api/exporters', methods=['GET'])
    @login_required_decorator
    def api_exporters_status():
        """Get status of all optional exporters."""
        from cryptolabs_proxy.exporter_manager import get_exporter_status
        return jsonify(get_exporter_status())
    
    @app.route('/auth/api/exporters/<name>/enable', methods=['POST'])
    @admin_required_decorator
    def api_exporter_enable(name):
        """Enable an exporter (vastai or runpod)."""
        from cryptolabs_proxy.exporter_manager import enable_exporter
        data = request.json or {}
        api_key = data.get('api_key', '').strip()
        if not api_key:
            return jsonify({'success': False, 'error': 'API key is required'}), 400
        result = enable_exporter(name, api_key)
        status = 200 if result.get('success') else 500
        return jsonify(result), status
    
    @app.route('/auth/api/exporters/<name>/disable', methods=['POST'])
    @admin_required_decorator
    def api_exporter_disable(name):
        """Disable an exporter (vastai or runpod)."""
        from cryptolabs_proxy.exporter_manager import disable_exporter
        result = disable_exporter(name)
        return jsonify(result)
    
    @app.route('/auth/api/exporters/<name>/restart', methods=['POST'])
    @admin_required_decorator
    def api_exporter_restart(name):
        """Restart an exporter container."""
        from cryptolabs_proxy.exporter_manager import restart_exporter
        result = restart_exporter(name)
        status = 200 if result.get('success') else 500
        return jsonify(result), status
    
    # =========================================================================
    # EXPORTER MANAGEMENT PAGES
    # =========================================================================
    
    EXPORTER_PAGE_CONFIG = {
        'vastai': {
            'display_name': 'Vast.ai Exporter',
            'api_prefix': '/vastai-api',
            'metrics_path': '/vastai-metrics/',
            'grafana_path': '/grafana/d/vast-dashboard/vast-dashboard?orgId=1',
            'key_placeholder': 'Your Vast.ai API Key',
            'key_help': 'Find your API key at console.vast.ai &rarr; Account &rarr; API Keys',
            'logo_html': '<img src="https://vast.ai/favicon.ico" alt="Vast.ai" style="width:28px;height:28px;border-radius:6px;" onerror="this.onerror=null;this.textContent=\'💎\';">',
        },
        'runpod': {
            'display_name': 'RunPod Exporter',
            'api_prefix': '/runpod-api',
            'metrics_path': '/runpod-metrics/',
            'grafana_path': '/grafana/d/runpod-dashboard/runpod-dashboard?orgId=1',
            'key_placeholder': 'rpa_XXXXXXXXXXXXX',
            'key_help': 'Find your API key at runpod.io &rarr; Settings &rarr; API Keys',
            'logo_html': '<img src="https://cdn.prod.website-files.com/67d20fb9f56ff2ec6a7a657d/683cd0ee11462aef4a016ef6_runpod%20lowercase.webp" alt="RunPod" style="width:28px;height:28px;border-radius:6px;object-fit:contain;" onerror="this.onerror=null;this.textContent=\'🚀\';">',
        },
    }
    
    EXPORTER_PAGE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fleet Management | {{ config.display_name }}</title>
    <style>''' + BASE_STYLE + '''
        .top-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 30px; }
        .top-bar a.home-btn { color: var(--accent-blue); text-decoration: none; border: 1px solid var(--accent-blue); padding: 6px 16px; border-radius: 6px; font-size: 0.9rem; transition: background 0.2s; }
        .top-bar a.home-btn:hover { background: rgba(0, 180, 216, 0.15); }
        .top-bar .sep { color: var(--border-color); }
        .top-bar .title { font-size: 1.2rem; font-weight: 600; display: flex; align-items: center; gap: 8px; }
        .status-badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 500; }
        .status-running { background: rgba(76,175,80,0.2); color: var(--accent-green); }
        .status-stopped { background: rgba(244,67,54,0.2); color: #f44336; }
        .actions-row { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
        .key-table { width: 100%; border-collapse: collapse; }
        .key-table th, .key-table td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border-color); }
        .key-table th { color: var(--text-secondary); font-size: 0.85rem; font-weight: 500; }
        .key-masked { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem; color: var(--text-secondary); background: var(--bg-secondary); padding: 2px 8px; border-radius: 4px; }
        .key-meta { font-size: 0.8rem; color: var(--text-secondary); margin-top: 2px; }
        .add-key-form { display: flex; gap: 10px; align-items: end; margin-top: 15px; }
        .add-key-form input { flex: 1; padding: 8px 12px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; }
        .add-key-form input::placeholder { color: var(--text-secondary); }
        #status-msg { margin-top: 12px; padding: 10px 14px; border-radius: 6px; font-size: 0.9rem; display: none; }
        .msg-success { background: rgba(76,175,80,0.15); color: var(--accent-green); }
        .msg-error { background: rgba(244,67,54,0.15); color: #f44336; }
        .msg-info { background: rgba(33,150,243,0.15); color: #2196f3; }
        .btn-restart { background: rgba(255,152,0,0.15); color: #ff9800; border: 1px solid rgba(255,152,0,0.3); }
        .btn-restart:hover { background: rgba(255,152,0,0.25); }
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <a href="/" class="home-btn">Home</a>
            <span class="sep">|</span>
            <span class="title">{{ config.logo_html|safe }} {{ config.display_name }}</span>
            <span id="status-badge" class="status-badge status-stopped">checking...</span>
        </div>
        
        <div class="actions-row">
            <a href="{{ config.grafana_path }}" class="btn">Open Grafana Dashboard</a>
            <a href="{{ config.metrics_path }}" class="btn btn-secondary">Raw Metrics</a>
        </div>
        
        <div class="card">
            <h2>Service Status</h2>
            <div id="service-status">Loading...</div>
            <div style="margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap;">
                <button id="btn-enable" class="btn" style="display:none;" onclick="showEnableForm()">Enable Service</button>
                <button id="btn-restart" class="btn btn-restart" style="display:none;" onclick="restartService()">Restart Container</button>
                <button id="btn-disable" class="btn btn-danger" style="display:none;" onclick="disableService()">Disable &amp; Remove</button>
            </div>
            <div id="enable-form" style="display:none; margin-top:15px;">
                <form onsubmit="event.preventDefault(); enableService();" class="add-key-form">
                    <input type="password" id="enable-key" placeholder="{{ config.key_placeholder }}" autocomplete="new-password">
                    <button type="submit" class="btn">Enable</button>
                    <button type="button" class="btn btn-secondary" onclick="hideEnableForm()">Cancel</button>
                </form>
                <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:6px;">{{ config.key_help|safe }}</div>
            </div>
            <div id="status-msg"></div>
        </div>
        
        <div class="card" id="accounts-card" style="display:none;">
            <h2>API Key Accounts</h2>
            <p style="color:var(--text-secondary); font-size:0.9rem; margin-bottom:15px;">
                Manage API key accounts for this exporter. Multiple accounts can be monitored simultaneously.
            </p>
            <div id="accounts-list">Loading...</div>
            <form onsubmit="event.preventDefault(); addAccount();" class="add-key-form" style="margin-top:20px; padding-top:15px; border-top:1px solid var(--border-color);">
                <input type="text" id="new-account-name" placeholder="Account name" style="max-width:180px;" autocomplete="off">
                <input type="password" id="new-account-key" placeholder="{{ config.key_placeholder }}" autocomplete="new-password">
                <button type="submit" class="btn">Add Account</button>
            </form>
        </div>
    </div>
    
    <script>
    const EXPORTER = '{{ exporter_name }}';
    const API_PREFIX = '{{ config.api_prefix }}';
    
    async function loadStatus() {
        try {
            const resp = await fetch('/auth/api/exporters');
            if (!resp.ok) throw new Error('Failed');
            const data = await resp.json();
            const info = data[EXPORTER];
            if (!info) { document.getElementById('service-status').textContent = 'Unknown exporter'; return; }
            
            const badge = document.getElementById('status-badge');
            const statusDiv = document.getElementById('service-status');
            
            if (info.running) {
                badge.textContent = 'Running';
                badge.className = 'status-badge status-running';
                statusDiv.innerHTML = 'Container is running on port <strong>' + info.port + '</strong>';
                document.getElementById('btn-disable').style.display = '';
                document.getElementById('btn-restart').style.display = '';
                document.getElementById('btn-enable').style.display = 'none';
                loadAccounts();
            } else if (info.enabled) {
                badge.textContent = 'Enabled (not running)';
                badge.className = 'status-badge status-stopped';
                statusDiv.innerHTML = 'Service is enabled but the container is not running.';
                document.getElementById('btn-disable').style.display = '';
                document.getElementById('btn-restart').style.display = 'none';
                document.getElementById('btn-enable').style.display = '';
            } else {
                badge.textContent = 'Disabled';
                badge.className = 'status-badge status-stopped';
                document.getElementById('btn-restart').style.display = 'none';
                if (info.can_deploy === false) {
                    statusDiv.innerHTML = '<span style="color:var(--accent-yellow);">' + (info.deploy_blocked_reason || 'Cannot deploy yet') + '</span>';
                    document.getElementById('btn-disable').style.display = 'none';
                    document.getElementById('btn-enable').style.display = 'none';
                } else {
                    statusDiv.innerHTML = 'Service is not enabled. Click Enable to start.';
                    document.getElementById('btn-disable').style.display = 'none';
                    document.getElementById('btn-enable').style.display = '';
                }
            }
        } catch (e) {
            document.getElementById('service-status').textContent = 'Error loading status';
        }
    }
    
    async function loadAccounts() {
        const card = document.getElementById('accounts-card');
        const listDiv = document.getElementById('accounts-list');
        try {
            const resp = await fetch(API_PREFIX + '/accounts');
            if (!resp.ok) { card.style.display = 'none'; return; }
            const data = await resp.json();
            card.style.display = '';
            
            if (!data.accounts || data.accounts.length === 0) {
                listDiv.innerHTML = '<p style="color:var(--text-secondary);">No accounts configured.</p>';
                return;
            }
            
            let html = '<table class="key-table"><thead><tr><th>Account</th><th>API Key</th><th>Status</th><th>Details</th><th></th></tr></thead><tbody>';
            for (const acc of data.accounts) {
                const name = acc.name || acc;
                const keyMasked = acc.key_masked || '***';
                const status = acc.status || 'unknown';
                const statusColor = status === 'connected' ? 'var(--accent-green)' : '#f44336';
                const statusIcon = status === 'connected' ? '&#9679;' : '&#9679;';
                
                let details = '';
                if (acc.balance !== null && acc.balance !== undefined) {
                    details += '$' + parseFloat(acc.balance).toFixed(2);
                }
                if (acc.machine_count !== null && acc.machine_count !== undefined) {
                    details += (details ? ' &middot; ' : '') + acc.machine_count + ' machine' + (acc.machine_count !== 1 ? 's' : '');
                }
                
                html += '<tr>';
                html += '<td><strong>' + name + '</strong></td>';
                html += '<td><code class="key-masked">' + keyMasked + '</code></td>';
                html += '<td><span style="color:' + statusColor + ';">' + statusIcon + ' ' + status + '</span></td>';
                html += '<td style="color:var(--text-secondary); font-size:0.85rem;">' + (details || '&mdash;') + '</td>';
                html += '<td style="text-align:right;"><button class="btn btn-danger btn-sm" data-acct="' + name.replace(/"/g, '&quot;') + '">Remove</button></td>';
                html += '</tr>';
            }
            html += '</tbody></table>';
            listDiv.innerHTML = html;
            // Attach remove handlers via event delegation
            listDiv.querySelectorAll('[data-acct]').forEach(function(btn) {
                btn.onclick = function() { removeAccount(btn.dataset.acct); };
            });
        } catch (e) {
            card.style.display = 'none';
        }
    }
    
    async function addAccount() {
        const name = document.getElementById('new-account-name').value.trim();
        const key = document.getElementById('new-account-key').value.trim();
        if (!name || !key) { showMsg('Please enter both account name and API key', 'error'); return; }
        
        showMsg('Adding account...', 'info');
        try {
            const resp = await fetch(API_PREFIX + '/accounts', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: name, key: key})
            });
            if (resp.ok) {
                showMsg('Account added successfully', 'success');
                document.getElementById('new-account-name').value = '';
                document.getElementById('new-account-key').value = '';
                loadAccounts();
            } else {
                const data = await resp.json().catch(() => ({}));
                showMsg(data.error || 'Failed to add account', 'error');
            }
        } catch (e) { showMsg('Request failed: ' + e.message, 'error'); }
    }
    
    async function removeAccount(name) {
        if (!confirm('Remove account "' + name + '"? This will stop monitoring for this API key.')) return;
        showMsg('Removing account...', 'info');
        try {
            const resp = await fetch(API_PREFIX + '/accounts/' + encodeURIComponent(name), {
                method: 'DELETE'
            });
            if (resp.ok) {
                showMsg('Account "' + name + '" removed successfully', 'success');
                loadAccounts();
            } else {
                const data = await resp.json().catch(() => ({}));
                showMsg(data.error || 'Failed to remove account', 'error');
            }
        } catch (e) { showMsg('Request failed: ' + e.message, 'error'); }
    }
    
    function showEnableForm() { document.getElementById('enable-form').style.display = ''; }
    function hideEnableForm() { document.getElementById('enable-form').style.display = 'none'; }
    
    async function enableService() {
        const key = document.getElementById('enable-key').value.trim();
        if (!key) { showMsg('Please enter an API key', 'error'); return; }
        showMsg('Enabling service (starting container, configuring Prometheus, importing dashboard)...', 'info');
        try {
            const resp = await fetch('/auth/api/exporters/' + EXPORTER + '/enable', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({api_key: key})
            });
            const data = await resp.json();
            if (data.success) {
                showMsg('Service enabled! ' + (data.steps || []).join(' | '), 'success');
                hideEnableForm();
                setTimeout(loadStatus, 1500);
            } else { showMsg(data.error || 'Failed to enable', 'error'); }
        } catch (e) { showMsg('Request failed: ' + e.message, 'error'); }
    }
    
    async function restartService() {
        if (!confirm('Restart the exporter container? Metrics will be briefly unavailable.')) return;
        showMsg('Restarting container...', 'info');
        try {
            const resp = await fetch('/auth/api/exporters/' + EXPORTER + '/restart', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            });
            const data = await resp.json();
            if (data.success) {
                showMsg(data.message || 'Container restarted successfully', 'success');
                setTimeout(loadStatus, 2000);
            } else { showMsg(data.error || 'Failed to restart', 'error'); }
        } catch (e) { showMsg('Request failed: ' + e.message, 'error'); }
    }
    
    async function disableService() {
        if (!confirm('Disable this service? This will stop the container, remove the Prometheus target, and delete the Grafana dashboard.')) return;
        showMsg('Disabling service...', 'info');
        try {
            const resp = await fetch('/auth/api/exporters/' + EXPORTER + '/disable', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            });
            const data = await resp.json();
            if (data.success) {
                showMsg('Service disabled. ' + (data.steps || []).join(' | '), 'success');
                document.getElementById('accounts-card').style.display = 'none';
                setTimeout(loadStatus, 1500);
            } else { showMsg(data.error || 'Failed to disable', 'error'); }
        } catch (e) { showMsg('Request failed: ' + e.message, 'error'); }
    }
    
    function showMsg(msg, type) {
        const el = document.getElementById('status-msg');
        el.style.display = 'block';
        el.className = 'msg-' + type;
        el.textContent = msg;
    }
    
    loadStatus();
    </script>
</body>
</html>
'''
    
    @app.route('/vastai/')
    @login_required_decorator
    def vastai_management():
        """Vast.ai exporter management page."""
        return render_template_string(EXPORTER_PAGE_TEMPLATE,
                                      config=EXPORTER_PAGE_CONFIG['vastai'],
                                      exporter_name='vastai')
    
    @app.route('/runpod/')
    @login_required_decorator
    def runpod_management():
        """RunPod exporter management page."""
        return render_template_string(EXPORTER_PAGE_TEMPLATE,
                                      config=EXPORTER_PAGE_CONFIG['runpod'],
                                      exporter_name='runpod')
    
    # =========================================================================
    # DC WATCHDOG AUTO-SSO
    # =========================================================================
    
    @app.route('/auth/watchdog/sso')
    def watchdog_sso():
        """Generate SSO URL for DC Watchdog - enables seamless one-click access.
        
        IMPORTANT: WordPress validation ALWAYS happens!
        This is NOT skipping WordPress - it's just avoiding browser redirects.
        
        Flow:
        1. Fleet Management has API key (sk-ipmi-xxx) from client's .secrets.yaml
        2. This endpoint generates a signed token containing the API key
        3. DC Watchdog receives token and validates API key against WordPress
        4. WordPress confirms: user_id, email, tier, subscription status
        5. If valid, DC Watchdog creates session with WordPress-verified info
        6. User lands on dashboard - no manual login needed!
        
        The API key is the trust anchor - it was obtained from WordPress during
        initial signup at cryptolabs.co.za. DC Watchdog validates it every time.
        
        If API key is not configured, falls back to WordPress browser SSO.
        """
        import base64
        
        # Check if user is logged in to Fleet Management
        if not session.get('logged_in'):
            if not get_setting('allow_anonymous', False):
                return redirect('/auth/login?next=/auth/watchdog/sso')
        
        username = session.get('username', 'anonymous')
        role = session.get('role', 'readonly')
        
        # Get API key (from env or persistent storage)
        api_key = get_watchdog_api_key()
        
        # If no API key configured, redirect to WordPress signup with callback
        # After signup, WordPress will redirect back with the API key
        if not api_key:
            # Build callback URL for this Fleet Management instance
            callback_url = request.host_url.rstrip('/') + '/auth/watchdog/callback'
            signup_url = f"{WATCHDOG_SIGNUP_URL}?redirect_uri={callback_url}&source=fleet_management"
            return redirect(signup_url)
        
        # Generate signed SSO payload
        # NOTE: DC Watchdog will validate this API key against WordPress server-to-server
        # The token is just a signed transport - WordPress is the source of truth
        timestamp = int(time.time())
        
        # Include this Fleet Management instance's URL so dc-watchdog
        # can show a "Home" button that navigates back here.
        fleet_home = request.host_url.rstrip('/')  + '/'
        
        sso_data = {
            'username': username,
            'role': role,
            'api_key': api_key,  # Will be validated against WordPress by DC Watchdog
            'timestamp': timestamp,
            'source': 'fleet_management',
            'fleet_home_url': fleet_home,
        }
        
        # Sign the payload using the API key itself as the secret
        # This eliminates the need for a separate shared secret per client!
        # DC Watchdog will verify using the same API key from the payload
        payload = base64.b64encode(json.dumps(sso_data).encode('utf-8')).decode('utf-8')
        signature = hmac.new(
            api_key.encode('utf-8'),  # API key IS the secret
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Mark as verified - user is actively using DC Watchdog via SSO
        # This handles the case where API key came from setup but user
        # never went through the WordPress callback flow
        if not is_watchdog_verified():
            set_watchdog_verified()
            logger.info("DC Watchdog verified via direct SSO (API key from setup)")
        
        # Build SSO redirect URL
        sso_url = f"{WATCHDOG_URL}/auth/sso?payload={payload}&signature={signature}"
        
        return redirect(sso_url)
    
    @app.route('/auth/watchdog/sso-url')
    def watchdog_sso_url():
        """API endpoint to get SSO URL without redirect (for JavaScript fetch).
        
        Returns JSON with the SSO URL that can be used client-side.
        """
        import base64
        
        # Check if user is logged in
        if not session.get('logged_in'):
            if not get_setting('allow_anonymous', False):
                return jsonify({'error': 'Not authenticated'}), 401
        
        username = session.get('username', 'anonymous')
        role = session.get('role', 'readonly')
        
        # Get API key (from env or persistent storage)
        api_key = get_watchdog_api_key()
        
        # If no API key configured, return signup URL with callback
        if not api_key:
            callback_url = request.host_url.rstrip('/') + '/auth/watchdog/callback'
            signup_url = f"{WATCHDOG_SIGNUP_URL}?redirect_uri={callback_url}&source=fleet_management"
            return jsonify({
                'sso_url': signup_url,
                'auto_sso': False,
                'needs_signup': True,
                'message': 'API key not configured - redirect to signup'
            })
        
        # Generate signed SSO payload
        timestamp = int(time.time())
        
        fleet_home = request.host_url.rstrip('/') + '/'
        
        sso_data = {
            'username': username,
            'role': role,
            'api_key': api_key,
            'timestamp': timestamp,
            'source': 'fleet_management',
            'fleet_home_url': fleet_home,
        }
        
        # Sign using API key as the secret (same as /auth/watchdog/sso)
        payload = base64.b64encode(json.dumps(sso_data).encode('utf-8')).decode('utf-8')
        signature = hmac.new(
            api_key.encode('utf-8'),  # API key IS the secret
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        sso_url = f"{WATCHDOG_URL}/auth/sso?payload={payload}&signature={signature}"
        
        return jsonify({
            'sso_url': sso_url,
            'auto_sso': True,
            'message': 'Auto-SSO enabled'
        })
    
    @app.route('/auth/watchdog/callback')
    def watchdog_callback():
        """OAuth-style callback from WordPress after user signs up for DC Watchdog.
        
        WordPress redirects here with:
        - api_key: The user's API key (sk-ipmi-xxx)
        - user_email: User's email
        - subscription: Subscription status (trial, active, etc.)
        
        We store the API key and then redirect to the DC Watchdog dashboard.
        """
        api_key = request.args.get('api_key')
        user_email = request.args.get('user_email', '')
        subscription = request.args.get('subscription', 'trial')
        
        if not api_key or not api_key.startswith('sk-ipmi-'):
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head><title>Error</title></head>
                <body style="font-family: sans-serif; padding: 40px; text-align: center;">
                    <h2>❌ Invalid API Key</h2>
                    <p>No valid API key was provided. Please try again.</p>
                    <a href="/">Return to Dashboard</a>
                </body>
                </html>
            '''), 400
        
        # Save the API key persistently and mark as verified (SSO completed)
        if save_watchdog_api_key(api_key):
            set_watchdog_verified()  # User completed SSO, now DC Watchdog is enabled
            # Now redirect to DC Watchdog with SSO
            return redirect('/auth/watchdog/sso')
        else:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head><title>Error</title></head>
                <body style="font-family: sans-serif; padding: 40px; text-align: center;">
                    <h2>❌ Failed to Save API Key</h2>
                    <p>Could not save the API key. Please try again.</p>
                    <a href="/">Return to Dashboard</a>
                </body>
                </html>
            '''), 500
    
    @app.route('/auth/watchdog/status')
    def watchdog_status():
        """Check DC Watchdog configuration and agent status.
        
        Returns detailed status for UI rendering:
        - state: 'not_configured' | 'pending_agents' | 'agents_installed' | 'active' | 'error'
        - configured: bool - user has completed SSO verification
        - agents: dict with total, online, outdated counts
        - latest_version: string - latest agent version from watchdog server
        """
        api_key = get_watchdog_api_key()
        verified = is_watchdog_verified()
        
        result = {
            'configured': verified,  # Only true after SSO completion
            'has_api_key': bool(api_key),
            'verified': verified,
            'signup_url': WATCHDOG_SIGNUP_URL,
            'state': 'not_configured',
            'agents': {
                'total': 0,
                'online': 0,
                'outdated': 0
            },
            'sites': [],  # Per-site breakdown for multi-site customers
            'latest_version': None,
            'dashboard_url': f'{WATCHDOG_URL}/dashboard'
        }
        
        if not verified:
            # First-time: require user to enable DC Watchdog via "Link Account" + SSO.
            # Even if setup passed API key via env var, user must complete SSO to
            # verify account. After SSO, agents get worker tokens for encrypted comms.
            result['state'] = 'not_configured'
            result['message'] = 'Enable DC Watchdog to monitor server uptime'
            return jsonify(result)
        
        if not api_key:
            # Verified but no key (shouldn't happen, but handle gracefully)
            result['state'] = 'not_configured'
            result['message'] = 'API key missing, please re-enable DC Watchdog'
            return jsonify(result)
        
        # Try to get agent status from watchdog server
        try:
            # First get latest version (public endpoint)
            version_resp = requests.get(
                f'{WATCHDOG_URL}/api/latest-version',
                timeout=5
            )
            if version_resp.ok:
                version_data = version_resp.json()
                result['latest_version'] = version_data.get('version', 'unknown')
            
            # Try to get agent count (requires API key)
            agents_resp = requests.get(
                f'{WATCHDOG_URL}/api/updates',
                params={'api_key': api_key},
                timeout=5
            )
            if agents_resp.ok:
                agents_data = agents_resp.json()
                # API returns: total (all registered), online (currently online), outdated, sites
                total_registered = agents_data.get('total_registered', agents_data.get('total', 0))
                online_count = agents_data.get('online', 0)  # Default 0, not total_registered
                result['agents'] = {
                    'total': total_registered,
                    'online': online_count,
                    'outdated': agents_data.get('outdated', 0)
                }
                result['sites'] = agents_data.get('sites', [])
                result['latest_version'] = agents_data.get('latest_version', result['latest_version'])
                result['min_version'] = agents_data.get('min_version')  # Lowest running agent version
                result['max_version'] = agents_data.get('max_version')  # Highest running agent version
                
                if result['agents']['total'] > 0:
                    if online_count == 0:
                        # Agents registered but none online - likely not deployed or all offline
                        result['state'] = 'agents_offline'
                        result['message'] = f"0/{total_registered} agents online"
                    elif result['agents']['outdated'] > 0:
                        result['state'] = 'active'
                        result['message'] = f"{result['agents']['outdated']} agents need updates"
                    else:
                        result['state'] = 'active'
                        result['message'] = f"{online_count}/{total_registered} agents online"
                else:
                    # No agents reporting to watchdog yet - check if any are installed locally (e.g. via dc-overview setup)
                    result['state'] = 'pending_agents'
                    result['message'] = 'API key configured, deploy agents to start monitoring'
                    
                    try:
                        local_resp = requests.get(
                            'http://dc-overview:5001/api/watchdog-agents/status',
                            timeout=3
                        )
                        if local_resp.ok:
                            local_data = local_resp.json()
                            result['local'] = {
                                'total_servers': local_data.get('total_servers', 0),
                                'installed': local_data.get('installed', 0),
                                'not_installed': local_data.get('not_installed', 0)
                            }
                            installed = local_data.get('installed', 0)
                            if installed > 0:
                                result['state'] = 'agents_installed'  # Go agents deployed, waiting for heartbeats
                                result['message'] = f"{installed} agents installed, waiting for heartbeats..."
                    except Exception:
                        pass  # dc-overview not available
            elif agents_resp.status_code in (401, 403):
                # API key is invalid, expired, or subscription ended
                result['configured'] = False  # Force re-link
                result['state'] = 'key_invalid'
                result['key_error'] = True
                if agents_resp.status_code == 401:
                    result['message'] = 'API key invalid or expired. Please re-link your account.'
                else:
                    result['message'] = 'Subscription expired or access denied. Please check your account.'
            else:
                # Other error - might be temporary
                result['state'] = 'pending_agents'
                result['message'] = 'Verifying API key with watchdog server...'
                
        except requests.RequestException as e:
            result['state'] = 'pending_agents' if api_key else 'not_configured'
            result['message'] = 'Could not reach watchdog server'
        
        return jsonify(result)
    
    @app.route('/auth/watchdog/deploy-agents', methods=['POST'])
    @login_required_decorator
    def watchdog_deploy_agents():
        """Deploy DC Watchdog agents to all servers via dc-overview.
        
        This forwards the request to dc-overview's /api/watchdog-agents/deploy-all
        endpoint which handles the SSH deployment to each server.
        """
        # Check if user has write access
        role = session.get('role', 'readonly')
        if role == 'readonly':
            return jsonify({
                'success': False,
                'error': 'Write access required to deploy agents'
            }), 403
        
        # Forward to dc-overview
        try:
            # dc-overview container is accessible via internal network
            dc_overview_url = 'http://dc-overview:5001'
            
            # Forward the deploy request with Fleet auth headers
            # dc-overview expects X-Fleet-Auth-* headers from trusted proxy
            resp = requests.post(
                f'{dc_overview_url}/api/watchdog-agents/deploy-all',
                timeout=120,  # Allow time for SSH to multiple servers
                headers={
                    'X-Fleet-Auth-User': session.get('username', 'admin'),
                    'X-Fleet-Auth-Role': role,
                    'X-Fleet-Authenticated': 'true',
                    'Content-Type': 'application/json'
                }
            )
            
            if resp.ok:
                return jsonify(resp.json())
            else:
                return jsonify({
                    'success': False,
                    'error': f'Deploy failed: {resp.text}'
                }), resp.status_code
                
        except requests.exceptions.ConnectionError:
            return jsonify({
                'success': False,
                'error': 'Could not connect to dc-overview. Is Server Manager running?'
            }), 503
        except requests.exceptions.Timeout:
            return jsonify({
                'success': False,
                'error': 'Deployment timed out. Check server connectivity.'
            }), 504
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/auth/watchdog/agents-status')
    @login_required_decorator
    def watchdog_agents_local_status():
        """Get local agent deployment status from dc-overview.
        
        Returns how many agents are installed locally (via dc-overview)
        vs what watchdog server sees.
        """
        try:
            dc_overview_url = 'http://dc-overview:5001'
            resp = requests.get(
                f'{dc_overview_url}/api/watchdog-agents/status',
                timeout=5
            )
            
            if resp.ok:
                return jsonify(resp.json())
            else:
                return jsonify({
                    'configured': False,
                    'error': 'Could not get status from dc-overview'
                }), resp.status_code
                
        except requests.exceptions.ConnectionError:
            return jsonify({
                'configured': False,
                'error': 'dc-overview not running'
            }), 503
        except Exception as e:
            return jsonify({
                'configured': False,
                'error': str(e)
            }), 500
    
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
