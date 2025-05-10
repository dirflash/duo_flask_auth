# Duo Flask Auth

A reusable Flask authentication library with Duo MFA support. This library provides a clean, simple way to add authentication and Multi-Factor Authentication (MFA) to your Flask applications.

## Features

- User authentication with username and password
- Duo MFA integration using Duo Universal Prompt
- MongoDB integration for user storage
- User management (add users, enable/disable MFA)
- Customizable templates
- Blueprint-based architecture for easy integration

## Installation

```bash
pip install duo-flask-auth
```

Or install directly from the repository:

```bash
pip install git+https://github.com/dirflash/duo-flask-auth.git
```

## Requirements

- Python 3.7+
- Flask 2.0+
- Flask-Login 0.5+
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

## API Documentation

### DuoFlaskAuth

The main class that provides authentication functionality.

#### Methods

- `__init__(app=None, db_config=None, duo_config=None, template_folder='templates')`: Initialize the extension
- `init_app(app)`: Initialize the extension with a Flask application
- `login()`: Handle user login with optional Duo MFA
- `logout()`: Log out the current user
- `duo_callback()`: Handle callbacks from Duo MFA
- `enable_mfa()`: Enable MFA for the current user
- `disable_mfa()`: Disable MFA for the current user
- `add_user(username, password)`: Add a new user to the database

### User

Represents a user in the Flask-Login system.

#### Methods

- `__init__(user_id, username, password_hash, mfa_enabled=False)`: Initialize a user
- `check_password(password)`: Verify if the provided password matches the stored hash
- `get_id()`: Return the user ID for Flask-Login

## Advanced Usage

For more advanced use cases and customization, see the examples folder.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
