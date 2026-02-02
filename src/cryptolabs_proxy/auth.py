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
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Tuple, List

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

# DC Watchdog SSO Configuration
# API key (sk-ipmi-xxx) from CryptoLabs subscription - enables Auto-SSO
# This key is also used as the signing secret for SSO tokens (no separate secret needed!)
WATCHDOG_API_KEY = os.environ.get('WATCHDOG_API_KEY', '')
WATCHDOG_URL = os.environ.get('WATCHDOG_URL', 'https://watchdog.cryptolabs.co.za')

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
        .logo { font-size: 3rem; text-align: center; margin-bottom: 10px; }
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
            <a href="/">🚀 Dashboard</a>
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
                        <td><strong>{{ user.username }}</strong></td>
                        <td>
                            <span class="badge badge-{{ user.role }}">{{ user.role }}</span>
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
                            <span style="color: var(--text-secondary);">(current user)</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
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
            <a href="/">🚀 Dashboard</a>
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
    
    @app.route('/auth/headers')
    def get_headers():
        """Get auth headers for nginx subrequest."""
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
        
        # If no API key configured, fall back to WordPress browser SSO
        # This happens when client hasn't linked their account yet
        if not WATCHDOG_API_KEY:
            # Redirect to WordPress signup page - they need to get an API key first
            return redirect('https://www.cryptolabs.co.za/dc-watchdog-signup/')
        
        # Generate signed SSO payload
        # NOTE: DC Watchdog will validate this API key against WordPress server-to-server
        # The token is just a signed transport - WordPress is the source of truth
        timestamp = int(time.time())
        
        sso_data = {
            'username': username,
            'role': role,
            'api_key': WATCHDOG_API_KEY,  # Will be validated against WordPress by DC Watchdog
            'timestamp': timestamp,
            'source': 'fleet_management',
        }
        
        # Sign the payload using the API key itself as the secret
        # This eliminates the need for a separate shared secret per client!
        # DC Watchdog will verify using the same API key from the payload
        payload = base64.b64encode(json.dumps(sso_data).encode('utf-8')).decode('utf-8')
        signature = hmac.new(
            WATCHDOG_API_KEY.encode('utf-8'),  # API key IS the secret
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
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
        
        # If no API key configured, return WordPress fallback URL
        if not WATCHDOG_API_KEY:
            return jsonify({
                'sso_url': 'https://www.cryptolabs.co.za/dc-watchdog-signup/',
                'auto_sso': False,
                'message': 'API key not configured, using WordPress SSO'
            })
        
        # Generate signed SSO payload
        timestamp = int(time.time())
        
        sso_data = {
            'username': username,
            'role': role,
            'api_key': WATCHDOG_API_KEY,
            'timestamp': timestamp,
            'source': 'fleet_management',
        }
        
        # Sign using API key as the secret (same as /auth/watchdog/sso)
        payload = base64.b64encode(json.dumps(sso_data).encode('utf-8')).decode('utf-8')
        signature = hmac.new(
            WATCHDOG_API_KEY.encode('utf-8'),  # API key IS the secret
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        sso_url = f"{WATCHDOG_URL}/auth/sso?payload={payload}&signature={signature}"
        
        return jsonify({
            'sso_url': sso_url,
            'auto_sso': True,
            'message': 'Auto-SSO enabled'
        })
    
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
