"""Pure identity-store validation shared by host adoption and server startup."""

# Valid roles (ordered by privilege level)
VALID_ROLES = ['admin', 'readwrite', 'readonly']


def validate_identity_users(users):
    """Validate existing account authority without mutating or filling defaults."""
    if not isinstance(users, dict) or not users:
        raise ValueError('empty identity store')
    for name, user in users.items():
        if (not isinstance(name, str) or not name or not isinstance(user, dict)
                or not isinstance(user.get('password_hash'), str) or not user['password_hash']
                or user.get('role') not in VALID_ROLES
                or any(key in user and type(user[key]) is not bool
                       for key in ('enabled', 'require_password_change'))):
            raise ValueError('invalid identity store')
