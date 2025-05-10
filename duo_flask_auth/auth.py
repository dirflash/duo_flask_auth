"""
duo_flask_auth - Flask Authentication Library with Duo MFA Support

This library provides authentication functionality with Duo MFA integration
for Flask applications, extracted from the original application.
"""

import logging
import re
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, Any, Callable

import certifi

# Import Duo Universal SDK
from duo_universal.client import Client, DuoException
from flask import Blueprint, Flask, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash


class DuoFlaskAuth:
    """
    Flask authentication library with Duo MFA support.

    This class provides authentication functionality with optional Duo MFA integration
    for Flask applications.
    """

    def __init__(
        self,
        app: Optional[Flask] = None,
        db_config: Optional[Dict[str, str]] = None,
        duo_config: Optional[Dict[str, str]] = None,
        template_folder: str = 'templates'
    ):
        """
        Initialize the DuoFlaskAuth extension.

        Args:
            app (Optional[Flask]): The Flask application to initialize with.
            db_config (Optional[Dict[str, str]]): MongoDB connection configuration.
            duo_config (Optional[Dict[str, str]]): Duo MFA configuration.
            template_folder (str): Folder for auth templates.
        """
        self.login_manager = LoginManager()
        self.db_config = db_config or {}
        self.duo_config = duo_config or {}
        self.template_folder = template_folder
        self.duo_client = None
        self.blueprint = Blueprint('duo_flask_auth', __name__,
                                  template_folder=template_folder)

        self._setup_routes()

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize the extension with the given Flask application.

        Args:
            app (Flask): The Flask application to initialize with.
        """
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['duo_flask_auth'] = self

        # Set up the login manager
        self.login_manager.init_app(app)
        self.login_manager.login_view = "duo_flask_auth.login"
        self.login_manager.login_message = "Please log in to access this page."
        self.login_manager.login_message_category = "info"

        # Set up the MongoDB connection if provided
        if self.db_config:
            self._setup_mongodb(app)

        # Set up the Duo client if provided
        if self.duo_config:
            self._setup_duo_client(app)

        # Register the user loader
        @self.login_manager.user_loader
        def load_user(user_id):
            return self.load_user(user_id)

        # Register the blueprint with the app
        app.register_blueprint(self.blueprint)

    def _setup_mongodb(self, app: Flask) -> None:
        """Set up MongoDB connection."""
        app.logger.info("Setting up MongoDB connection")
        # MongoDB configuration is stored but connection is made on demand

    def _setup_duo_client(self, app: Flask) -> None:
        """Set up Duo MFA client."""
        # Extract Duo configuration
        client_id = self.duo_config.get('client_id')
        client_secret = self.duo_config.get('client_secret')
        api_host = self.duo_config.get('api_host')
        redirect_uri = self.duo_config.get('redirect_uri')

        # Initialize Duo client if all required parameters are provided
        if all([client_id, client_secret, api_host, redirect_uri]):
            self.duo_client = Client(
                client_id=client_id,
                client_secret=client_secret,
                host=api_host,
                redirect_uri=redirect_uri,
            )
            app.logger.info("Duo MFA client initialized")
        else:
            app.logger.warning(
                "Duo MFA not fully configured. Some parameters are missing."
            )

    def _setup_routes(self) -> None:
        """Set up authentication routes on the blueprint."""
        self.blueprint.route('/login/', methods=['GET', 'POST'])(self.login)
        self.blueprint.route('/duo-callback')(self.duo_callback)
        self.blueprint.route('/logout')(self.logout)
        self.blueprint.route('/enable-mfa', methods=['GET', 'POST'])(self.enable_mfa)
        self.blueprint.route('/disable-mfa', methods=['GET', 'POST'])(self.disable_mfa)
        self.blueprint.route('/add-user/<username>/<password>', methods=['GET', 'POST'])(self.add_user)

    def mongo_connect(self) -> MongoClient:
        """
        Connect to MongoDB.

        Returns:
            MongoClient: The MongoDB connection object.
        """
        db_un = self.db_config.get('username')
        db_pw = self.db_config.get('password')
        mongo_host = self.db_config.get('host')
        db_name = self.db_config.get('database')

        mongo_url = f"mongodb+srv://{db_un}:{db_pw}@{mongo_host}/{db_name}"
        mongo_connection_str = MongoClient(
            mongo_url + "?retryWrites=true&w=majority",
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=500,
        )
        current_app.logger.info("Built MongoDB connection string")
        return mongo_connection_str

    def mongo_test(self, mongo_url: MongoClient) -> Tuple[bool, Optional[str]]:
        """
        Test the connection to MongoDB.

        Args:
            mongo_url (MongoClient): The MongoDB connection URL.

        Returns:
            Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the connection status
            and the connected database name (or None if the connection failed).
        """
        try:
            mongo_url.server_info()
            current_app.logger.info("Connected to MongoDB successfully")
            # Log the MongoDB database names
            db_names = mongo_url.list_database_names()
            current_app.logger.info(f"MongoDB databases: {db_names}")
            # Convert connected_db to a string
            connected_db_str = ", ".join(db_names)
            return True, connected_db_str
        except Exception as e:
            current_app.logger.error(f"Failed to connect to MongoDB: {e}")
            return False, None

    def load_user(self, user_id: str) -> Optional['User']:
        """
        Load a user from the database by their user ID.

        Args:
            user_id (str): The ID of the user to load (typically the username).

        Returns:
            User: A User object if the user is found in the database, otherwise None.
        """
        current_app.logger.debug(f"Loading user: {user_id}")

        # Connect to MongoDB
        mongo_url = self.mongo_connect()
        db_name = self.db_config.get('database')

        # Access the database and collection
        local_db = mongo_url[db_name]
        users_collection = local_db["users"]

        # Look up the user by username (which is what we're using as the ID)
        user_data = users_collection.find_one({"username": user_id})

        if user_data:
            # Create a User object with the data from MongoDB, including all schema fields
            return User(
                user_id=str(user_data.get("_id")),
                username=user_data.get("username"),
                password_hash=user_data.get("password_hash"),
                mfa_enabled=user_data.get("mfa_enabled", False),
                is_active=user_data.get("is_active", True),
                role=user_data.get("role", "user"),
                created_by=user_data.get("created_by"),
                created_at=user_data.get("created_at"),
                last_password_change=user_data.get("last_password_change"),
                account_id=user_data.get("account_id"),
                login_attempts=user_data.get("login_attempts", 0),
                creation_ip=user_data.get("creation_ip"),
                last_login=user_data.get("last_login"),
                email_verified=user_data.get("email_verified", False),
                reset_token=user_data.get("reset_token"),
                reset_token_expires=user_data.get("reset_token_expires")
            )

        return None

    def is_valid_email(self, email: str) -> bool:
        """
        Validate email format using regex.

        Args:
            email (str): The email to validate

        Returns:
            bool: True if valid email format, False otherwise
        """
        # Basic email validation pattern
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def login(self):
        """
        Handle user login with Duo MFA.

        This function manages the login process, including initial authentication with
        username/password and then redirecting to Duo for MFA if enabled.
        """
        if request.method == "GET":
            return render_template("login_page.html", error=False)

        username = request.form["username"]
        password = request.form["password"]
        current_app.logger.debug(f"Login attempt: {username}")

        # Connect to MongoDB
        mongo_url = self.mongo_connect()
        db_name = self.db_config.get('database')

        # Access the database and collection
        local_db = mongo_url[db_name]
        users_collection = local_db["users"]

        # Find the user by username
        user_data = users_collection.find_one({"username": username})
        current_app.logger.debug(f"User found: {user_data is not None}")

        if user_data is None:
            current_app.logger.debug(f"User not found: {username}")
            return render_template("login_page.html", error=True)

        # Create a User object with the complete data from MongoDB
        user = User(
            user_id=str(user_data.get("_id")),
            username=user_data.get("username"),
            password_hash=user_data.get("password_hash"),
            mfa_enabled=user_data.get("mfa_enabled", False),
            is_active=user_data.get("is_active", True),
            role=user_data.get("role", "user"),
            created_by=user_data.get("created_by"),
            created_at=user_data.get("created_at"),
            last_password_change=user_data.get("last_password_change"),
            account_id=user_data.get("account_id"),
            login_attempts=user_data.get("login_attempts", 0),
            creation_ip=user_data.get("creation_ip"),
            last_login=user_data.get("last_login"),
            email_verified=user_data.get("email_verified", False),
            reset_token=user_data.get("reset_token"),
            reset_token_expires=user_data.get("reset_token_expires")
        )

        # Debug user details
        current_app.logger.debug(f"User ID: {user.id}")
        current_app.logger.debug(f"Username: {user.username}")
        current_app.logger.debug(f"Password hash: {user.password_hash}")
        current_app.logger.debug(f"MFA enabled: {user.mfa_enabled}")

        password_check = user.check_password(password)

        if not password_check:
            current_app.logger.debug(f"Password check failed for user: {username}")

            # Increment login attempts counter
            users_collection.update_one(
                {"username": username},
                {"$inc": {"login_attempts": 1}}
            )

            return render_template("login_page.html", error=True)

        # Check if the user is active
        if not user.is_active:
            current_app.logger.warning(f"Login attempt for inactive account: {username}")
            return render_template("login_page.html", error=True,
                                  message="This account has been deactivated. Please contact an administrator.")

        # Password check passed
        # Reset login attempts counter and update last login time
        users_collection.update_one(
            {"username": username},
            {
                "$set": {
                    "login_attempts": 0,
                    "last_login": datetime.utcnow()
                }
            }
        )

        # If Duo MFA is enabled for this user and Duo is configured, redirect to Duo
        if user.mfa_enabled and self.duo_client is not None:
            try:
                # Check if Duo services are available
                self.duo_client.health_check()

                # Generate a state parameter to verify the authentication response
                state = self.duo_client.generate_state()
                session["duo_state"] = state
                # Store username in session for completing authentication after Duo callback
                session["pending_username"] = username

                # Generate the Duo authentication URL
                duo_auth_url = self.duo_client.create_auth_url(username, state)

                # Redirect to Duo for 2FA
                current_app.logger.info(f"Redirecting user {username} to Duo MFA")
                return redirect(duo_auth_url)

            except DuoException as e:
                # If there's an issue with Duo, log it and decide how to proceed
                current_app.logger.error(f"Duo authentication error: {e}")
                # Options:
                # 1. Fail closed: Deny access and return to login
                # return render_template("login_page.html", error=True, message="MFA service unavailable")

                # 2. Fail open: Allow login without MFA (less secure but maintains service availability)
                current_app.logger.warning(
                    f"Bypassing MFA for {username} due to Duo service unavailable"
                )
                login_user(user)
                return redirect(url_for("duo_flask_auth.login_success"))

        # If MFA is not enabled for this user or Duo is not configured, log in directly
        login_user(user)
        return redirect(url_for("duo_flask_auth.login_success"))

    @login_required
    def login_success(self):
        """Handler for successful login - can be overridden by the application."""
        return "Login successful. Override login_success method to customize."

    def duo_callback(self):
        """
        Handle the callback from Duo MFA authentication.

        This endpoint receives the response from Duo after a user completes 2FA.
        It validates the state parameter and authentication result before completing login.
        """
        # Check that we have a pending authentication
        if "duo_state" not in session or "pending_username" not in session:
            current_app.logger.error("Duo callback received without pending authentication")
            return redirect(url_for("duo_flask_auth.login"))

        # Get query parameters
        state = request.args.get("state")
        duo_code = request.args.get("duo_code")

        # Verify state parameter to prevent CSRF
        if state != session["duo_state"]:
            current_app.logger.error("Duo callback state mismatch")
            return redirect(url_for("duo_flask_auth.login"))

        # Get the pending username
        username = session["pending_username"]

        try:
            # Exchange the code for an authentication result
            decoded_token = self.duo_client.exchange_authorization_code_for_2fa_result(
                duo_code, username
            )

            # Verify successful authentication
            if decoded_token:
                # Load the user and complete login
                user = self.load_user(username)
                if user:
                    login_user(user)

                    # Clean up session
                    session.pop("duo_state", None)
                    session.pop("pending_username", None)

                    current_app.logger.info(
                        f"User {username} successfully authenticated with Duo MFA"
                    )
                    return redirect(url_for("duo_flask_auth.login_success"))
                else:
                    current_app.logger.error(f"User {username} not found after Duo authentication")

        except DuoException as e:
            current_app.logger.error(f"Duo authentication error during callback: {e}")

        # If we get here, something went wrong
        flash("Two-factor authentication failed", "error")
        return redirect(url_for("duo_flask_auth.login"))

    @login_required
    def logout(self):
        """
        Log out the current user.

        Returns:
            str: A message indicating that the user has been logged out.
        """
        logout_user()
        current_app.logger.info("User logged out successfully")
        return "You have been logged out."

    @login_required
    def enable_mfa(self):
        """
        Enable MFA for the current user.
        """
        if request.method == "GET":
            return render_template("enable_mfa.html")

        # POST request - enable MFA for the current user
        mongo_url = self.mongo_connect()
        db_name = self.db_config.get('database')

        local_db = mongo_url[db_name]
        users_collection = local_db["users"]

        # Update the user's MFA status
        result = users_collection.update_one(
            {"username": current_user.username}, {"$set": {"mfa_enabled": True}}
        )

        if result.modified_count == 1:
            current_app.logger.info(f"MFA enabled for user: {current_user.username}")
            flash("MFA has been enabled for your account.", "success")
        else:
            current_app.logger.error(f"Failed to enable MFA for user: {current_user.username}")
            flash("Failed to enable MFA. Please try again.", "error")

        return redirect(url_for("duo_flask_auth.login_success"))

    @login_required
    def disable_mfa(self):
        """
        Disable MFA for the current user.
        """
        if request.method == "GET":
            return render_template("disable_mfa.html")

        # POST request - disable MFA for the current user
        mongo_url = self.mongo_connect()
        db_name = self.db_config.get('database')

        local_db = mongo_url[db_name]
        users_collection = local_db["users"]

        # Update the user's MFA status
        result = users_collection.update_one(
            {"username": current_user.username}, {"$set": {"mfa_enabled": False}}
        )

        if result.modified_count == 1:
            current_app.logger.info(f"MFA disabled for user: {current_user.username}")
            flash("MFA has been disabled for your account.", "success")
        else:
            current_app.logger.error(f"Failed to disable MFA for user: {current_user.username}")
            flash("Failed to disable MFA. Please try again.", "error")

        return redirect(url_for("duo_flask_auth.login_success"))

    def verify_email(self, username: str):
        """
        Mark a user's email as verified.

        Args:
            username (str): The username (email) to verify

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            mongo_url = self.mongo_connect()
            db_name = self.db_config.get('database')

            local_db = mongo_url[db_name]
            users_collection = local_db["users"]

            result = users_collection.update_one(
                {"username": username},
                {"$set": {"email_verified": True}}
            )

            current_app.logger.info(f"Email verified for user: {username}")
            return result.modified_count == 1

        except Exception as e:
            current_app.logger.error(f"Error verifying email for user '{username}': {e}")
            return False

    def update_user_role(self, username: str, role: str):
        """
        Update a user's role.

        Args:
            username (str): The username to update
            role (str): The new role to assign

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            mongo_url = self.mongo_connect()
            db_name = self.db_config.get('database')

            local_db = mongo_url[db_name]
            users_collection = local_db["users"]

            result = users_collection.update_one(
                {"username": username},
                {"$set": {"role": role}}
            )

            current_app.logger.info(f"Role updated for user '{username}' to '{role}'")
            return result.modified_count == 1

        except Exception as e:
            current_app.logger.error(f"Error updating role for user '{username}': {e}")
            return False

    def set_user_active_status(self, username: str, is_active: bool):
        """
        Set a user's active status.

        Args:
            username (str): The username to update
            is_active (bool): Whether the user should be active

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            mongo_url = self.mongo_connect()
            db_name = self.db_config.get('database')

            local_db = mongo_url[db_name]
            users_collection = local_db["users"]

            result = users_collection.update_one(
                {"username": username},
                {"$set": {"is_active": is_active}}
            )

            status_str = "activated" if is_active else "deactivated"
            current_app.logger.info(f"User '{username}' {status_str}")
            return result.modified_count == 1

        except Exception as e:
            current_app.logger.error(f"Error updating active status for user '{username}': {e}")
            return False

    def generate_password_reset_token(self, username: str, expiry_hours: int = 24):
        """
        Generate a password reset token for a user.

        Args:
            username (str): The username to generate a token for
            expiry_hours (int): Number of hours until the token expires

        Returns:
            str: The reset token, or None if generation failed
        """
        try:
            mongo_url = self.mongo_connect()
            db_name = self.db_config.get('database')

            local_db = mongo_url[db_name]
            users_collection = local_db["users"]

            # Generate a random token
            reset_token = str(uuid.uuid4())

            # Calculate expiry time
            expiry_time = datetime.utcnow() + timedelta(hours=expiry_hours)

            # Update the user record
            result = users_collection.update_one(
                {"username": username},
                {
                    "$set": {
                        "reset_token": reset_token,
                        "reset_token_expires": expiry_time
                    }
                }
            )

            if result.modified_count == 1:
                current_app.logger.info(f"Password reset token generated for user: {username}")
                return reset_token
            else:
                current_app.logger.error(f"Failed to generate password reset token for user: {username}")
                return None

        except Exception as e:
            current_app.logger.error(f"Error generating password reset token for user '{username}': {e}")
            return None

    def reset_password_with_token(self, username: str, token: str, new_password: str):
        """
        Reset a user's password using a reset token.

        Args:
            username (str): The username to reset password for
            token (str): The reset token
            new_password (str): The new password

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            mongo_url = self.mongo_connect()
            db_name = self.db_config.get('database')

            local_db = mongo_url[db_name]
            users_collection = local_db["users"]

            # Find the user and check token
            user = users_collection.find_one({
                "username": username,
                "reset_token": token,
                "reset_token_expires": {"$gt": datetime.utcnow()}
            })

            if not user:
                current_app.logger.warning(f"Invalid or expired token for user: {username}")
                return False

            # Validate the new password
            # Check for password complexity
            if len(new_password) < 8:
                current_app.logger.warning("Password too short")
                return False

            has_upper = any(c.isupper() for c in new_password)
            has_lower = any(c.islower() for c in new_password)
            has_digit = any(c.isdigit() for c in new_password)

            if not (has_upper and has_lower and has_digit):
                current_app.logger.warning("Password not complex enough")
                return False

            # Generate new password hash
            password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")

            # Update user record
            result = users_collection.update_one(
                {"username": username},
                {
                    "$set": {
                        "password_hash": password_hash,
                        "last_password_change": datetime.utcnow(),
                        "reset_token": None,
                        "reset_token_expires": None
                    }
                }
            )

            if result.modified_count == 1:
                current_app.logger.info(f"Password reset successful for user: {username}")
                return True
            else:
                current_app.logger.error(f"Failed to reset password for user: {username}")
                return False

        except Exception as e:
            current_app.logger.error(f"Error resetting password for user '{username}': {e}")
            return False

    @login_required
    def add_user(self, username: str, password: str):
        """
        Add a user to the MongoDB database with enhanced security validation.

        Args:
            username (str): The username (email) of the user to be added
            password (str): The password of the user to be added

        Returns:
            str: A message indicating whether the user was added successfully or not
        """
        try:
            # SECURITY CHECK 1: Double-check authentication (defense in depth)
            if not current_user.is_authenticated:
                current_app.logger.error(
                    f"Unauthenticated access attempt to add_user from IP: {request.remote_addr}"
                )
                return "Error: Authentication required."

            # Connect to MongoDB
            mongo_url = self.mongo_connect()
            db_name = self.db_config.get('database')

            local_db = mongo_url[db_name]
            users_collection = local_db["users"]

            # Retrieve the current user's full information from the database
            current_user_data = users_collection.find_one(
                {"username": current_user.username}
            )

            # SECURITY CHECK 2: Admin role validation - now using data from the database
            if (
                not current_user_data
                or not current_user_data.get("role")
                or current_user_data.get("role") != "admin"
            ):
                current_app.logger.warning(
                    f"Non-admin user {current_user.username} attempted to add user"
                )
                return "Error: Admin privileges required to add users."

            current_app.logger.info(f"Adding user attempt: {username}")
            current_app.logger.info(f"Request made by admin: {current_user.username}")

            # Regular validation continues...
            # VALIDATION 1: Input validation with length restrictions
            if not username or not password:
                current_app.logger.warning("Missing username or password")
                return "Error: Username and password are required."

            # Prevent excessively long inputs
            if len(username) > 100 or len(password) > 72:  # bcrypt max is 72 bytes
                current_app.logger.warning("Username or password exceeds maximum length")
                return "Error: Username or password too long."

            # VALIDATION 2: Email format validation
            if not self.is_valid_email(username):
                current_app.logger.warning(f"Invalid email format: {username}")
                return f"Error: '{username}' is not a valid email address."

            # VALIDATION 3: Password strength validation
            if len(password) < 8:
                current_app.logger.warning("Password too short")
                return "Error: Password must be at least 8 characters long."

            # Check for password complexity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)

            if not (has_upper and has_lower and has_digit):
                current_app.logger.warning("Password not complex enough")
                return "Error: Password must contain uppercase letters, lowercase letters, and numbers."

            # VALIDATION 4: Check if user already exists
            existing_user = users_collection.find_one({"username": username})
            if existing_user:
                current_app.logger.warning(f"User '{username}' already exists in the database")
                return f"Error: User '{username}' already exists in the database."

            # All validations passed, proceed with user creation
            password_hash = generate_password_hash(password, method="pbkdf2:sha256")

            # Current time
            current_time = datetime.utcnow()

            # Add user with full schema implementation
            user_data = {
                "username": username,
                "password_hash": password_hash,
                "created_by": current_user.username,
                "created_at": current_time,
                "is_active": True,
                "role": "user",  # Default role
                "last_password_change": current_time,
                "account_id": str(uuid.uuid4()),
                "login_attempts": 0,
                "creation_ip": request.remote_addr,
                "mfa_enabled": False,  # Default to MFA disabled
                "last_login": None,
                "email_verified": False,
                "reset_token": None,
                "reset_token_expires": None
            }

            # Insert the new user into the collection
            result = users_collection.insert_one(user_data)

            current_app.logger.info(
                f"User '{username}' added successfully with ID: {result.inserted_id}"
            )
            return f"Success: User '{username}' added successfully."

        except Exception as e:
            current_app.logger.error(f"Error adding user '{username}': {e}")
            return f"Error: Failed to add user '{username}'. {str(e)}"


class User(UserMixin):
    """
    Represents a user in the Flask-Login system.

    This class extends Flask-Login's UserMixin to provide the necessary methods
    for user authentication and session management.

    Attributes:
        id (str): The unique identifier for the user.
        username (str): The username of the user.
        password_hash (str): The hashed password of the user.
        mfa_enabled (bool): Whether MFA is enabled for this user.
    """

    def __init__(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        mfa_enabled: bool = False,
        **kwargs
    ):
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.mfa_enabled = mfa_enabled

        # Additional fields from the recommended schema
        self.is_active = kwargs.get('is_active', True)
        self.role = kwargs.get('role', 'user')
        self.created_by = kwargs.get('created_by')
        self.created_at = kwargs.get('created_at')
        self.last_password_change = kwargs.get('last_password_change')
        self.account_id = kwargs.get('account_id')
        self.login_attempts = kwargs.get('login_attempts', 0)
        self.creation_ip = kwargs.get('creation_ip')
        self.last_login = kwargs.get('last_login')
        self.email_verified = kwargs.get('email_verified', False)
        self.reset_token = kwargs.get('reset_token')
        self.reset_token_expires = kwargs.get('reset_token_expires')

    def check_password(self, password: str) -> bool:
        """
        Verify if the provided password matches the stored password hash.

        Args:
            password (str): The plaintext password to verify.

        Returns:
            bool: True if the password matches the stored hash, False otherwise.
        """
        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:
        """
        Return the user ID for Flask-Login.

        Returns:
            str: The username (used as ID in this system).
        """
        return self.username
