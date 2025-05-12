"""
Example of a Flask application with enhanced security features from Duo Flask Auth

This example demonstrates how to configure and use all the security features
provided by the Duo Flask Auth library.
"""

import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash
from duo_flask_auth import DuoFlaskAuth

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'replace-with-strong-secret-key-in-production')

# Configure database connection
db_config = {
    'username': os.environ.get('MONGO_USERNAME', 'mongodb_username'),
    'password': os.environ.get('MONGO_PASSWORD', 'mongodb_password'),
    'host': os.environ.get('MONGO_HOST', 'cluster0.example.mongodb.net'),
    'database': os.environ.get('MONGO_DATABASE', 'auth-db')
}

# Configure Duo MFA (optional)
duo_config = {
    'client_id': os.environ.get('DUO_CLIENT_ID'),
    'client_secret': os.environ.get('DUO_CLIENT_SECRET'),
    'api_host': os.environ.get('DUO_API_HOST'),
    'redirect_uri': os.environ.get('DUO_REDIRECT_URI')
}

# Configure rate limiting
rate_limit_config = {
    "enabled": True,
    "max_attempts": {
        "login": 5,            # 5 login attempts
        "password_reset": 3     # 3 password reset attempts
    },
    "window_seconds": {
        "login": 300,           # in a 5-minute window
        "password_reset": 600   # in a 10-minute window
    }
}

# Configure account lockout
account_lockout_config = {
    "enabled": True,
    "max_attempts": 5,         # Lock after 5 failed attempts
    "lockout_duration": 1800,  # 30 minutes lockout
    "lockout_reset_on_success": True  # Reset counter after successful login
}

# Configure password policy
password_policy = {
    "min_length": 10,         # Minimum password length
    "require_upper": True,    # Require uppercase letters
    "require_lower": True,    # Require lowercase letters
    "require_digit": True,    # Require digits
    "require_special": True,  # Require special characters
    "max_age_days": 90,       # Password expires after 90 days
    "prevent_common": True,   # Prevent common passwords
    "common_passwords": [
        "Password123!", "Admin123!", "Welcome123!",
        "Summer2025!", "Winter2025!"
    ]
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

# Override the login_success route
@app.route('/login-success')
def login_success():
    """Handle successful login redirection"""
    # Log the successful login event with additional context
    auth.log_security_event(
        event_type="login_success",
        username=current_user.username,
        details={
            "method": "password" if not current_user.mfa_enabled else "password_and_mfa"
        }
    )

    # Check if this is first login (never logged in before)
    if current_user.last_login is None:
        flash("Welcome! This appears to be your first login.", "info")

    return redirect(url_for('dashboard'))

@app.route('/')
def home():
    """Home page route"""
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard route (protected)"""
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@login_required
def admin_panel():
    """Admin panel route (protected and role-restricted)"""
    # Connect to MongoDB
    mongo_url = auth.mongo_connect()
    local_db = mongo_url[db_config['database']]
    users_collection = local_db["users"]

    # Retrieve the current user's full information from the database
    current_user_data = users_collection.find_one({"username": current_user.username})

    # Check if the user has admin role
    if not current_user_data or current_user_data.get("role") != "admin":
        # Log the unauthorized access attempt
        auth.log_security_event(
            event_type="unauthorized_access",
            username=current_user.username,
            details={
                "resource": "admin_panel",
                "required_role": "admin"
            }
        )

        flash("You don't have permission to access the admin panel.", "error")
        return redirect(url_for('dashboard'))

    # List all users for the admin
    users = list(users_collection.find())

    # Get recent security events (last 100)
    security_events = list(local_db["security_events"].find().sort("timestamp", -1).limit(100))

    return render_template('admin.html', users=users, security_events=security_events)

@app.route('/admin/database-health')
@login_required
def database_health():
    """Database health status for administrators."""
    # Check if the user has admin role
    if not current_user.role == 'admin':
        flash("You don't have permission to access this page.", "error")
        return redirect(url_for('dashboard'))

    # Get database index health information
    index_health = auth.check_database_indexes()

    # Display the health information
    return render_template(
        'admin/database_health.html',
        index_health=index_health
    )

@app.route('/create-user-form')
@login_required
def create_user_form():
    """Form to create a new user (admin only)"""
    # Check if the user has admin role (similar to admin_panel)
    mongo_url = auth.mongo_connect()
    local_db = mongo_url[db_config['database']]
    users_collection = local_db["users"]
    current_user_data = users_collection.find_one({"username": current_user.username})

    if not current_user_data or current_user_data.get("role") != "admin":
        auth.log_security_event(
            event_type="unauthorized_access",
            username=current_user.username,
            details={"action": "create_user_form"}
        )
        flash("You don't have permission to create users.", "error")
        return redirect(url_for('dashboard'))

    return render_template('create_user.html')

@app.route('/create-user', methods=['POST'])
@login_required
def create_user():
    """Create a new user (admin only)"""
    username = request.form.get('username')
    password = request.form.get('password')

    result = auth.add_user(username, password)
    if result.startswith("Success"):
        # Optionally verify the email automatically
        auth.verify_email(username)
        auth.log_security_event(
            event_type="user_created",
            username=current_user.username,
            details={"new_user": username}
        )
        flash("User created successfully.", "success")
    else:
        flash(result, "error")
    return redirect(url_for('admin_panel'))

@app.route('/security-events')
@login_required
def security_events():
    """View security events (admin only)"""
    # Check admin permission
    mongo_url = auth.mongo_connect()
    local_db = mongo_url[db_config['database']]
    users_collection = local_db["users"]
    current_user_data = users_collection.find_one({"username": current_user.username})

    if not current_user_data or current_user_data.get("role") != "admin":
        flash("You don't have permission to view security events.", "error")
        return redirect(url_for('dashboard'))

    # Get filter parameters
    event_type = request.args.get('event_type')
    username = request.args.get('username')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Build the query
    query = {}
    if event_type:
        query["event_type"] = event_type
    if username:
        query["username"] = username

    # Date filtering
    if start_date or end_date:
        query["timestamp"] = {}
        if start_date:
            try:
                start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
                query["timestamp"]["$gte"] = start_datetime
            except ValueError:
                flash("Invalid start date format. Use YYYY-MM-DD.", "error")

        if end_date:
            try:
                end_datetime = datetime.strptime(end_date, "%Y-%m-%d")
                # Set to the end of the day
                end_datetime = end_datetime.replace(hour=23, minute=59, second=59)
                query["timestamp"]["$lte"] = end_datetime
            except ValueError:
                flash("Invalid end date format. Use YYYY-MM-DD.", "error")

    # Get security events
    security_events = list(
        local_db["security_events"].find(query).sort("timestamp", -1).limit(500)
    )

    # Get distinct event types for the filter dropdown
    event_types = local_db["security_events"].distinct("event_type")

    return render_template('security_events.html',
                          events=security_events,
                          event_types=event_types,
                          filter_event_type=event_type,
                          filter_username=username,
                          filter_start_date=start_date,
                          filter_end_date=end_date)

@app.route('/account-settings')
@login_required
def account_settings():
    """Account settings page for the current user"""
    return render_template('account_settings.html', user=current_user)

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)