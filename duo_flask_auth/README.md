# Duo Flask Auth

A reusable Flask authentication library with Duo MFA support and enhanced security features. This library provides a clean, simple way to add secure authentication and Multi-Factor Authentication (MFA) to your Flask applications.

## Features

- User authentication with username and password
- Duo MFA integration using Duo Universal Prompt
- MongoDB integration for user storage
- User management (add users, enable/disable MFA)
- Comprehensive security features:
  - Rate limiting
  - Account lockout
  - CSRF protection
  - Enhanced password policies
  - Security event logging
- Customizable templates
- Blueprint-based architecture for easy integration

## Installation

```bash
pip install duo-flask-auth
```

Or install directly from the repository:

```bash
pip install git+https://github.com/yourusername/duo-flask-auth.git
```

## Requirements

- Python 3.7+
- Flask 2.0+
- Flask-Login 0.5+
- Flask-WTF 1.0+ (for CSRF protection)
- Duo Universal SDK 1.0+
- PyMongo 4.0+
- Werkzeug 2.0+
- MongoDB (for user storage)

## Quick Start

Here's a minimal example to get you started:

```python
from flask import Flask, redirect, url_for
from duo_flask_auth import DuoFlaskAuth

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure secret key

# Configure database connection
db_config = {
    'username': 'mongodb_username',
    'password': 'mongodb_password',
    'host': 'mongodb_host',
    'database': 'your_database'
}

# Configure Duo MFA (optional)
duo_config = {
    'client_id': 'YOUR_DUO_CLIENT_ID',
    'client_secret': 'YOUR_DUO_CLIENT_SECRET',
    'api_host': 'api-XXXXXXXX.duosecurity.com',
    'redirect_uri': 'https://your-app.com/duo-callback'
}

# Initialize the authentication library
auth = DuoFlaskAuth(app, db_config=db_config, duo_config=duo_config)

# Override the login_success route
@app.route('/login-success')
def login_success():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@auth.login_required
def dashboard():
    return "Welcome to your dashboard!"

@app.route('/')
def home():
    return "Welcome to the home page!"

if __name__ == '__main__':
    app.run(debug=True)
```

## Security Features

The library includes comprehensive security features to protect against common authentication vulnerabilities and follow industry best practices.

### Rate Limiting

Rate limiting helps prevent brute force attacks by restricting the number of authentication attempts within a given time period.

```python
# Configure rate limiting
rate_limit_config = {
    "enabled": True,
    "max_attempts": {
        "login": 5,           # 5 login attempts
        "password_reset": 3    # 3 password reset attempts
    },
    "window_seconds": {
        "login": 300,          # in a 5-minute window
        "password_reset": 600  # in a 10-minute window
    }
}

# Pass the configuration when initializing
auth = DuoFlaskAuth(app, db_config=db_config, rate_limit_config=rate_limit_config)
```

### Account Lockout Policy

Account lockout provides protection against targeted account attacks by temporarily locking an account after too many failed login attempts.

```python
# Configure account lockout
account_lockout_config = {
    "enabled": True,
    "max_attempts": 5,         # Lock after 5 failed attempts
    "lockout_duration": 1800,  # 30 minutes lockout
    "lockout_reset_on_success": True  # Reset counter after successful login
}

# Pass the configuration when initializing
auth = DuoFlaskAuth(app, db_config=db_config, account_lockout_config=account_lockout_config)
```

### CSRF Protection

Cross-Site Request Forgery (CSRF) protection is automatically enabled through Flask-WTF's CSRFProtect.

### Enhanced Password Policies

Configure strong password policies to protect against password guessing and dictionary attacks.

```python
# Configure password policy
password_policy = {
    "min_length": 8,         # Minimum password length
    "require_upper": True,   # Require uppercase letters
    "require_lower": True,   # Require lowercase letters
    "require_digit": True,   # Require digits
    "require_special": False, # Optional special characters
    "max_age_days": 90,      # Password expires after 90 days
    "prevent_common": True,  # Prevent common passwords
    "common_passwords": ["Password123", "Admin123", "Welcome123"]
}

# Pass the configuration when initializing
auth = DuoFlaskAuth(app, db_config=db_config, password_policy=password_policy)
```

### Security Event Logging

The library logs all security-related events to a dedicated MongoDB collection for audit purposes. Events include login attempts, password changes, account lockouts, etc.

### Complete Security Configuration

Here's an example of configuring all security features:

```python
from flask import Flask
from duo_flask_auth import DuoFlaskAuth

app = Flask(__name__)
app.secret_key = 'your-secure-secret-key'

# Database and Duo configurations (as shown above)
# ...

# Configure enhanced security
rate_limit_config = {
    "enabled": True,
    "max_attempts": {"login": 5, "password_reset": 3},
    "window_seconds": {"login": 300, "password_reset": 600}
}

account_lockout_config = {
    "enabled": True,
    "max_attempts": 5,
    "lockout_duration": 1800,
    "lockout_reset_on_success": True
}

password_policy = {
    "min_length": 10,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_special": True,
    "max_age_days": 90
}

# Initialize the authentication library with security enhancements
auth = DuoFlaskAuth(
    app,
    db_config=db_config,
    duo_config=duo_config,
    rate_limit_config=rate_limit_config,
    account_lockout_config=account_lockout_config,
    password_policy=password_policy
)
```

## Using Deferred Initialization

If you're using an application factory pattern, you can initialize the extension later:

```python
from flask import Flask
from duo_flask_auth import DuoFlaskAuth

auth = DuoFlaskAuth()

def create_app():
    app = Flask(__name__)
    app.secret_key = 'your-secret-key'

    # Configure the extension
    auth.init_app(app)

    # Register routes
    # ...

    return app
```

## Configuration Options

### Database Configuration

- `username`: MongoDB username
- `password`: MongoDB password
- `host`: MongoDB host address
- `database`: MongoDB database name

### Duo MFA Configuration

- `client_id`: Duo application client ID
- `client_secret`: Duo application client secret
- `api_host`: Duo API hostname
- `redirect_uri`: Your application's redirect URI for Duo callbacks

## Customizing Templates

The library comes with basic templates for login, enabling MFA, and disabling MFA. You can override these templates by placing your own templates in your app's template folder with the same names:

- `login_page.html`: The login form
- `enable_mfa.html`: Form to enable MFA
- `disable_mfa.html`: Form to disable MFA
- `password_expired.html`: Form for changing expired passwords
- `account_locked.html`: Page shown when an account is locked
- `forgot_password.html`: Form for initiating password reset
- `reset_password.html`: Form for completing password reset

## API Documentation

### DuoFlaskAuth

The main class that provides authentication functionality.

#### Methods

- `__init__(app=None, db_config=None, duo_config=None, template_folder='templates', rate_limit_config=None, account_lockout_config=None, password_policy=None)`: Initialize the extension
- `init_app(app)`: Initialize the extension with a Flask application
- `login()`: Handle user login with optional Duo MFA
- `logout()`: Log out the current user
- `duo_callback()`: Handle callbacks from Duo MFA
- `enable_mfa()`: Enable MFA for the current user
- `disable_mfa()`: Disable MFA for the current user
- `add_user(username, password)`: Add a new user to the database
- `verify_email(username)`: Mark a user's email as verified
- `update_user_role(username, role)`: Update a user's role
- `set_user_active_status(username, is_active)`: Activate or deactivate a user account
- `generate_password_reset_token(username, expiry_hours=24)`: Generate a password reset token
- `reset_password_with_token(username, token, new_password)`: Reset a password using a token
- `unlock_account(username)`: Unlock a locked user account
- `log_security_event(event_type, username, ip_address=None, details=None)`: Log a security event

### User

Represents a user in the Flask-Login system.

#### Attributes

- `id`: The unique identifier for the user
- `username`: The username (email) of the user
- `password_hash`: The hashed password
- `mfa_enabled`: Whether MFA is enabled for this user
- `is_active`: Whether the user account is active
- `role`: The user's role (e.g., "admin", "user")
- `created_by`: Username of the user who created this account
- `created_at`: Timestamp when the account was created
- `last_password_change`: Timestamp of the last password change
- `account_id`: Unique identifier for the account (UUID)
- `login_attempts`: Number of consecutive failed login attempts
- `creation_ip`: IP address used during account creation
- `last_login`: Timestamp of the last successful login
- `email_verified`: Whether the user's email has been verified
- `reset_token`: Token for password reset (if any)
- `reset_token_expires`: Expiration timestamp for the reset token
- `password_expired`: Whether the password has expired
- `locked_until`: When the account lockout expires

#### Methods

- `__init__(user_id, username, password_hash, mfa_enabled=False, **kwargs)`: Initialize a user
- `check_password(password)`: Verify if the provided password matches the stored hash
- `get_id()`: Return the user ID for Flask-Login
- `is_account_locked`: Property that checks if the account is locked

## MongoDB Schema

The library uses the following schema for the users collection:

```javascript
{
  "_id": ObjectId("..."),
  "username": "user@example.com",
  "password_hash": "pbkdf2:sha256:...",
  "created_by": "admin@example.com",
  "created_at": ISODate("2025-05-09T12:00:00Z"),
  "is_active": true,
  "role": "admin", // or "user", etc.
  "last_password_change": ISODate("2025-05-09T12:00:00Z"),
  "account_id": "550e8400-e29b-41d4-a716-446655440000",
  "login_attempts": 0,
  "creation_ip": "192.168.1.1",
  "mfa_enabled": true,
  "last_login": ISODate("2025-05-09T12:00:00Z"),
  "email_verified": true,
  "reset_token": null,
  "reset_token_expires": null,
  "locked_until": null
}
```

The library also creates a `security_events` collection for audit logging:

```javascript
{
  "_id": ObjectId("..."),
  "timestamp": ISODate("2025-05-09T12:05:33Z"),
  "event_type": "login_failed", // login_success, password_reset, account_locked, etc.
  "username": "user@example.com",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
  "details": {
    "reason": "Invalid password",
    // Additional context information
  }
}
```

## Advanced Usage

For more advanced use cases and customization, see the examples folder.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
