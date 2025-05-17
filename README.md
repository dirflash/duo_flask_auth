# Duo Flask Auth

A reusable Flask authentication library with Duo MFA support, enhanced security features, flexibility improvements, and performance optimizations. This library provides a clean, simple way to add secure authentication and Multi-Factor Authentication (MFA) to your Flask applications.

## Features

- User authentication with username and password
- Duo MFA integration using Duo Universal Prompt
- MongoDB database backend support (SQLAlchemy support planned for future releases)
- Customizable user model with extensibility
- Configurable routes to match your application's URL structure
- Comprehensive security features:
  - Rate limiting
  - Account lockout
  - CSRF protection
  - Enhanced password policies
  - Security event logging
- Performance optimizations:
  - Connection pooling
  - User data caching
  - Optimized database indexing
- Customizable templates
- Blueprint-based architecture for easy integration

## Installation

### Standard Installation

```bash
pip install duo_flask_auth
```

### Development Installation

For development or when installing from the repository, use:

```bash
# Install directly from the repository with a specific package name
pip install git+https://github.com/dirflash/duo_flask_auth.git#egg=duo_flask_auth

# Install required dependencies
pip install duo-universal flask-login
```

## Dependencies

This package depends on the following:

- Flask
- duo-universal
- flask-login

## Requirements

- Python 3.7+
- Flask 2.0+
- Flask-Login 0.5+
- Flask-WTF 1.0+ (for CSRF protection)
- Duo Universal SDK 1.0+ (for MFA functionality)
- Database dependencies:
  - MongoDB: PyMongo 4.0+

## Quick Start

Here's a minimal example to get you started:

```python
from flask import Flask, redirect, url_for
from duo_flask_auth import DuoFlaskAuth
from flask_login import LoginManager, current_user

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

The library logs all security-related events to a dedicated collection for audit purposes. Events include login attempts, password changes, account lockouts, etc.

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

## Flexibility Features

The library has been designed with flexibility in mind, allowing you to adapt it to different applications and environments.

### 1. Database Backend Support

Currently, MongoDB is the only supported database backend:

```python
# Using MongoDB (default)
auth = DuoFlaskAuth(
    app,
    db_config={
        'username': 'mongo_user',
        'password': 'mongo_pass',
        'host': 'mongodb.example.com',
        'database': 'auth_db'
    }
)

# Using a custom adapter (advanced usage)
class MyCustomAdapter(DatabaseAdapter):
    # Implement the required methods...

auth = DuoFlaskAuth(
    app,
    db_adapter=MyCustomAdapter()
)
```

Note: SQLAlchemy support is planned for future releases.

### 2. Customizable User Model

Extend the user model with application-specific fields and methods:

```python
from duo_flask_auth import BaseUser, register_user_model

# Define your custom user class
class EnterpriseUser(BaseUser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.employee_id = kwargs.get('employee_id')
        self.department = kwargs.get('department')
        self.permissions = kwargs.get('permissions', [])

    def has_permission(self, permission):
        return permission in self.permissions

# Create a factory function
def enterprise_user_factory(user_data):
    return EnterpriseUser(
        user_id=str(user_data.get("_id", user_data.get("id", ""))),
        username=user_data.get("username"),
        password_hash=user_data.get("password_hash"),
        mfa_enabled=user_data.get("mfa_enabled", False),
        # Standard fields...
        employee_id=user_data.get("employee_id"),
        department=user_data.get("department"),
        permissions=user_data.get("permissions", [])
    )

# Register your model
register_user_model('enterprise', enterprise_user_factory)

# Use your model
auth = DuoFlaskAuth(app, user_model='enterprise')

# Now you can use your custom methods
@app.route('/admin-only')
@auth.login_required
def admin_only():
    if current_user.has_permission('admin_panel'):
        return "Welcome to the admin panel"
    return "Access denied"
```

### 3. Configurable Routes

Configure authentication routes to match your application's URL structure:

```python
# Default routes at /auth/login, /auth/logout, etc.
auth = DuoFlaskAuth(app)

# Custom routes at /identity/login, /identity/logout, etc.
auth = DuoFlaskAuth(app, routes_prefix='/identity')

# API routes at /api/v1/auth/login, etc.
auth = DuoFlaskAuth(app, routes_prefix='/api/v1/auth')

# Root routes at /login, /logout, etc.
auth = DuoFlaskAuth(app, routes_prefix='')
```

## Performance Configuration

The library includes several performance enhancements that can be configured to optimize your application's performance.

### Connection Pooling

Connection pooling reduces the overhead of establishing new database connections for each request by reusing existing connections.

```python
# Configure connection pooling for MongoDB
db_config = {
    'username': 'mongodb_username',
    'password': 'mongodb_password',
    'host': 'mongodb_host',
    'database': 'your_database',
    'pool_size': 50,            # Maximum number of connections in the pool
    'min_pool_size': 10,        # Minimum number of connections to maintain
    'max_idle_time_ms': 60000,  # How long connections can remain idle (1 minute)
    'wait_queue_timeout_ms': 2000  # How long to wait for an available connection
}

auth = DuoFlaskAuth(app, db_config=db_config)
```

### Caching

The library implements in-memory caching to reduce database load for frequently accessed user data.

```python
# Configure caching
cache_config = {
    'enabled': True,           # Enable or disable caching
    'type': 'memory',          # Currently only memory cache is supported
    'default_ttl': 300,        # Default TTL for cached items (5 minutes)
    'user_ttl': 60,            # TTL for user data (1 minute)
    'security_events_ttl': 300 # TTL for security events (5 minutes)
}

auth = DuoFlaskAuth(app, db_config=db_config, cache_config=cache_config)
```

### Database Indexing

The library automatically creates optimized indexes for MongoDB collections to improve query performance. You can check index health using:

```python
# Check database index health
index_health = auth.check_database_indexes()
print(f"Database index health: {index_health['status']} ({index_health['health_percentage']}%)")
```

### Complete Performance Configuration

Here's an example of configuring all performance features:

```python
from flask import Flask
from duo_flask_auth import DuoFlaskAuth

app = Flask(__name__)
app.secret_key = 'your-secure-secret-key'

# Database and Duo configurations (as shown earlier)
# ...

# Performance configuration
performance_config = {
    # Database connection pooling
    'db_config': {
        'username': 'mongodb_username',
        'password': 'mongodb_password',
        'host': 'mongodb_host',
        'database': 'your_database',
        'pool_size': 50,
        'min_pool_size': 10,
        'max_idle_time_ms': 60000,
        'wait_queue_timeout_ms': 2000
    },

    # Caching configuration
    'cache_config': {
        'enabled': True,
        'type': 'memory',
        'default_ttl': 300,
        'user_ttl': 60,
        'security_events_ttl': 300
    }
}

# Initialize the authentication library with performance enhancements
auth = DuoFlaskAuth(
    app,
    db_config=performance_config['db_config'],
    duo_config=duo_config,
    cache_config=performance_config['cache_config']
)

# Check database indexes health on startup
@app.before_first_request
def check_db_health():
    index_health = auth.check_database_indexes()
    app.logger.info(f"Database index health: {index_health['status']} ({index_health['health_percentage']}%)")
    if index_health.get('missing_indexes'):
        app.logger.warning(f"Missing indexes: {', '.join(index_health['missing_indexes'])}")
```

## Performance Monitoring

The library includes tools to monitor performance metrics, which can help identify potential bottlenecks in your application.

### Cache Statistics

You can monitor cache performance using the `get_cache_stats()` method:

```python
# Get cache statistics
cache_stats = auth.get_cache_stats()
print(f"Cache hit rate: {cache_stats['hit_rate']*100:.1f}%")
print(f"Total hits: {cache_stats['hits']}, Misses: {cache_stats['misses']}")
print(f"Active cache keys: {cache_stats['active_keys']}")
```

### Database Index Health

The `check_database_indexes()` method returns information about the health of database indexes:

```python
# Check database index health
index_health = auth.check_database_indexes()
print(f"Database index status: {index_health['status']}")
print(f"Index health: {index_health['health_percentage']:.1f}%")
print(f"Existing indexes: {index_health['existing_indexes']} of {index_health['total_indexes']}")

# List any missing indexes
if index_health['missing_indexes']:
    print("Missing indexes:")
    for idx in index_health['missing_indexes']:
        print(f"  - {idx}")
```

For a more detailed view of index health, you can expose this information in your admin dashboard.

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

#### MongoDB

- `username`: MongoDB username
- `password`: MongoDB password
- `host`: MongoDB host address
- `database`: MongoDB database name
- `pool_size`: Maximum connection pool size (default: 50)
- `min_pool_size`: Minimum connections to maintain (default: 10)
- `max_idle_time_ms`: Maximum time a connection can remain idle (default: 60000)
- `wait_queue_timeout_ms`: How long to wait for an available connection (default: 2000)
- `connect_timeout_ms`: Timeout for initial connection (default: 30000)
- `socket_timeout_ms`: Timeout for operations (default: 45000)

### Duo MFA Configuration

- `client_id`: Duo application client ID
- `client_secret`: Duo application client secret
- `api_host`: Duo API hostname
- `redirect_uri`: Your application's redirect URI for Duo callbacks

### Caching Configuration

- `enabled`: Enable or disable caching (default: True)
- `type`: Cache implementation to use (default: 'memory')
- `default_ttl`: Default time-to-live in seconds (default: 300)
- `user_ttl`: TTL for user data in seconds (default: 60)
- `security_events_ttl`: TTL for security events in seconds (default: 300)

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

#### Constructor Parameters

- `app`: Flask application instance (optional)
- `db_config`: Database configuration dictionary (optional)
- `db_adapter`: Database adapter instance (optional)
- `duo_config`: Duo MFA configuration dictionary (optional)
- `template_folder`: Folder for auth templates (default: 'templates')
- `routes_prefix`: Prefix for authentication routes (default: '/auth')
- `user_model`: User model type (default: 'default')
- `rate_limit_config`: Rate limiting configuration (optional)
- `account_lockout_config`: Account lockout configuration (optional)
- `password_policy`: Password policy configuration (optional)
- `cache_config`: Caching configuration (optional)

#### Methods

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
- `get_cache_stats()`: Get statistics about cache performance
- `check_database_indexes()`: Check the health of database indexes

### BaseUser

Base class for user models in the system.

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
