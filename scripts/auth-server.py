#!/usr/bin/env python3
"""
CryptoLabs Proxy - Authentication Server

Runs alongside nginx to handle:
- User login/logout
- Session management  
- Auth verification for nginx auth_request

Listens on port 8081 (internal only)
"""

import os
import sys

# Add src to path for imports
sys.path.insert(0, '/app/src')

from cryptolabs_proxy.auth import create_flask_auth_app, ensure_default_user

# Create Flask app
app = create_flask_auth_app()

# Ensure default user exists
ensure_default_user()

if __name__ == '__main__':
    port = int(os.environ.get('AUTH_PORT', '8081'))
    app.run(host='0.0.0.0', port=port, debug=False)
