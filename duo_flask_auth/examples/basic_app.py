"""
Example Flask application using Duo Flask Auth

This example demonstrates how to integrate the Duo Flask Auth library
into a Flask application.
"""

import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash
from duo_flask_auth import DuoFlaskAuth

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'replace-with-strong-secret-key')

# Configure database connection
db_config = {
    'username': os.environ.get('MONGO_USERNAME'),
    'password': os.environ.get('MONGO_PASSWORD'),
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

# Initialize the authentication library
auth = DuoFlaskAuth(app, db_config=db_config, duo_config=duo_config)

# Override the login_success route
@app.route('/login-success')
def login_success():
    """Handle successful login redirection"""
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

@app.route('/profile')
@login_required
def profile():
    """User profile route (protected)"""
    return render_template('profile.html', user=current_user)

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
        flash("You don't have permission to access the admin panel.", "error")
        return redirect(url_for('dashboard'))

    # List all users for the admin
    users = list(users_collection.find())
    return render_template('admin.html', users=users)

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
        flash("You don't have permission to create users.", "error")
        return redirect(url_for('dashboard'))

    return render_template('create_user.html')

@app.route('/create-user/<username>/<password>')
@login_required
def create_user(username, password):
    """Create a new user (admin only)"""
    result = auth.add_user(username, password)
    if result.startswith("Success"):
        # Optionally verify the email automatically
        auth.verify_email(username)
        flash("User created successfully.", "success")
    else:
        flash(result, "error")
    return redirect(url_for('admin_panel'))

@app.route('/update-role/<username>/<role>')
@login_required
def update_role(username, role):
    """Update a user's role (admin only)"""
    # Check if the user has admin role (similar to admin_panel)
    mongo_url = auth.mongo_connect()
    local_db = mongo_url[db_config['database']]
    users_collection = local_db["users"]
    current_user_data = users_collection.find_one({"username": current_user.username})

    if not current_user_data or current_user_data.get("role") != "admin":
        flash("You don't have permission to update user roles.", "error")
        return redirect(url_for('dashboard'))

    # Update the user's role
    if auth.update_user_role(username, role):
        flash(f"User role updated to {role}.", "success")
    else:
        flash("Failed to update user role.", "error")

    return redirect(url_for('admin_panel'))

@app.route('/toggle-active/<username>/<int:active>')
@login_required
def toggle_active(username, active):
    """Activate or deactivate a user account (admin only)"""
    # Check if the user has admin role (similar to admin_panel)
    mongo_url = auth.mongo_connect()
    local_db = mongo_url[db_config['database']]
    users_collection = local_db["users"]
    current_user_data = users_collection.find_one({"username": current_user.username})

    if not current_user_data or current_user_data.get("role") != "admin":
        flash("You don't have permission to activate/deactivate users.", "error")
        return redirect(url_for('dashboard'))

    # Convert active param to boolean
    is_active = bool(active)

    # Update the user's active status
    if auth.set_user_active_status(username, is_active):
        status = "activated" if is_active else "deactivated"
        flash(f"User account {status}.", "success")
    else:
        flash("Failed to update user account status.", "error")

    return redirect(url_for('admin_panel'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgot password requests"""
    if request.method == 'GET':
        return render_template('forgot_password.html')

    # Process the form submission
    username = request.form.get('username')
    if not username:
        flash("Please enter your email address.", "error")
        return render_template('forgot_password.html')

    # Generate a password reset token
    token = auth.generate_password_reset_token(username)

    if token:
        # In a real application, you would send this token to the user's email
        # For this example, we'll just display it
        reset_url = url_for('reset_password', username=username, token=token, _external=True)
        flash(f"Password reset link generated. In a real application, this would be emailed to the user.", "success")
        flash(f"Reset link: {reset_url}", "info")


if __name__ == '__main__':
    app.run(debug=True)