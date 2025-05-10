"""
Tests for the core authentication functionality of the Duo Flask Auth library.
"""

import unittest
from unittest.mock import patch, MagicMock, ANY
from datetime import datetime, timedelta

from flask import Flask, session
from werkzeug.security import generate_password_hash

from duo_flask_auth import DuoFlaskAuth
from duo_flask_auth.exceptions import AuthError, InvalidCredentialsError


class MockCollection:
    """Mock MongoDB collection for testing."""

    def __init__(self, data=None):
        self.data = data or []
        self.inserted = []
        self.updated = []

    def find_one(self, query):
        """Mock find_one method."""
        if not self.data:
            return None

        # Simple query matching
        if isinstance(query, dict) and "username" in query:
            for item in self.data:
                if item.get("username") == query["username"]:
                    return item
        return None

    def insert_one(self, document):
        """Mock insert_one method."""
        self.inserted.append(document)
        mock_result = MagicMock()
        mock_result.inserted_id = "mock_id_12345"
        return mock_result

    def update_one(self, query, update):
        """Mock update_one method."""
        self.updated.append((query, update))
        mock_result = MagicMock()
        mock_result.modified_count = 1
        return mock_result

    def find(self, query=None):
        """Mock find method."""
        return self.data


class MockDB:
    """Mock MongoDB database for testing."""

    def __init__(self, collections=None):
        self.collections = collections or {
            "users": MockCollection(),
            "security_events": MockCollection()
        }

    def __getitem__(self, name):
        return self.collections.get(name, MockCollection())

    def list_collection_names(self):
        """Mock list_collection_names method."""
        return list(self.collections.keys())

    def create_collection(self, name):
        """Mock create_collection method."""
        if name not in self.collections:
            self.collections[name] = MockCollection()
        return self.collections[name]


class MockMongoClient:
    """Mock MongoDB client for testing."""

    def __init__(self, dbs=None):
        self.dbs = dbs or {
            "fuse-db": MockDB()
        }

    def __getitem__(self, name):
        return self.dbs.get(name, MockDB())

    def server_info(self):
        """Mock server_info method."""
        return {"version": "4.4.0"}

    def list_database_names(self):
        """Mock list_database_names method."""
        return list(self.dbs.keys())


class TestDuoFlaskAuth(unittest.TestCase):
    """Tests for the DuoFlaskAuth class."""

    def setUp(self):
        """Set up the test environment."""
        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = "test-secret-key"
        self.app.config["TESTING"] = True

        # Test database config
        self.db_config = {
            "username": "test_user",
            "password": "test_password",
            "host": "test.mongodb.net",
            "database": "fuse-db"
        }

        # Create a test user
        self.test_user = {
            "_id": "user_id_12345",
            "username": "test@example.com",
            "password_hash": generate_password_hash("Password123"),
            "created_by": "admin@example.com",
            "created_at": datetime.utcnow(),
            "is_active": True,
            "role": "user",
            "last_password_change": datetime.utcnow(),
            "account_id": "account_id_12345",
            "login_attempts": 0,
            "creation_ip": "127.0.0.1",
            "mfa_enabled": False,
            "last_login": None,
            "email_verified": False,
            "reset_token": None,
            "reset_token_expires": None,
            "locked_until": None
        }

        # Create a test admin user
        self.test_admin = {
            "_id": "admin_id_12345",
            "username": "admin@example.com",
            "password_hash": generate_password_hash("AdminPass123"),
            "created_by": "system",
            "created_at": datetime.utcnow(),
            "is_active": True,
            "role": "admin",
            "last_password_change": datetime.utcnow(),
            "account_id": "account_id_67890",
            "login_attempts": 0,
            "creation_ip": "127.0.0.1",
            "mfa_enabled": False,
            "last_login": datetime.utcnow(),
            "email_verified": True,
            "reset_token": None,
            "reset_token_expires": None,
            "locked_until": None
        }

        # Mock MongoDB collections
        self.mock_users_collection = MockCollection([self.test_user, self.test_admin])
        self.mock_security_events_collection = MockCollection([])

        # Mock MongoDB db
        self.mock_db = MockDB({
            "users": self.mock_users_collection,
            "security_events": self.mock_security_events_collection
        })

        # Mock MongoDB client
        self.mock_mongo_client = MockMongoClient({
            "fuse-db": self.mock_db
        })

        # Create patcher for mongo_connect
        self.mongo_connect_patcher = patch("duo_flask_auth.auth.MongoClient")
        self.mock_mongo_connect = self.mongo_connect_patcher.start()
        self.mock_mongo_connect.return_value = self.mock_mongo_client

        # Initialize DuoFlaskAuth with mocked MongoDB
        self.auth = DuoFlaskAuth(
            app=self.app,
            db_config=self.db_config
        )

        # Create test client
        self.client = self.app.test_client()

    def tearDown(self):
        """Tear down the test environment."""
        self.mongo_connect_patcher.stop()

    def test_init_app(self):
        """Test initializing the app."""
        # Create a new app
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "another-test-key"

        # Initialize with the new app
        auth = DuoFlaskAuth()
        auth.init_app(app)

        # Check that the extension was initialized
        self.assertIn("duo_flask_auth", app.extensions)
        self.assertEqual(app.extensions["duo_flask_auth"], auth)

    def test_load_user_found(self):
        """Test loading a user that exists."""
        with self.app.app_context():
            user = self.auth.load_user("test@example.com")

            # Check that the user was loaded correctly
            self.assertIsNotNone(user)
            self.assertEqual(user.username, "test@example.com")
            self.assertEqual(user.id, "user_id_12345")
            self.assertEqual(user.role, "user")
            self.assertFalse(user.mfa_enabled)

    def test_load_user_not_found(self):
        """Test loading a user that doesn't exist."""
        with self.app.app_context():
            user = self.auth.load_user("nonexistent@example.com")

            # Check that no user was returned
            self.assertIsNone(user)

    def test_is_valid_email(self):
        """Test email validation."""
        # Valid emails
        self.assertTrue(self.auth.is_valid_email("user@example.com"))
        self.assertTrue(self.auth.is_valid_email("user.name@example.co.uk"))
        self.assertTrue(self.auth.is_valid_email("user+tag@example.org"))

        # Invalid emails
        self.assertFalse(self.auth.is_valid_email("user@"))
        self.assertFalse(self.auth.is_valid_email("user@.com"))
        self.assertFalse(self.auth.is_valid_email("@example.com"))
        self.assertFalse(self.auth.is_valid_email("user@example"))
        self.assertFalse(self.auth.is_valid_email("user.example.com"))

    @patch("duo_flask_auth.auth.login_user")
    def test_login_success(self, mock_login_user):
        """Test successful login."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "test@example.com",
            "password": "Password123"
        }):
            response = self.auth.login()

            # Check that the user was logged in
            mock_login_user.assert_called_once()

            # Check that the login attempts were reset
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertEqual(update["$set"]["login_attempts"], 0)

    @patch("duo_flask_auth.auth.render_template")
    def test_login_invalid_credentials(self, mock_render_template):
        """Test login with invalid credentials."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "test@example.com",
            "password": "WrongPassword"
        }):
            response = self.auth.login()

            # Check that the template was rendered with an error
            mock_render_template.assert_called_with("login_page.html", error=True, message=ANY, error_code=ANY)

            # Check that login attempts were incremented
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertEqual(update["$inc"]["login_attempts"], 1)

    @patch("duo_flask_auth.auth.render_template")
    def test_login_user_not_found(self, mock_render_template):
        """Test login with a nonexistent user."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "nonexistent@example.com",
            "password": "Password123"
        }):
            response = self.auth.login()

            # Check that the template was rendered with an error
            mock_render_template.assert_called_with("login_page.html", error=True, message=ANY, error_code=ANY)

    def test_verify_email(self):
        """Test verifying an email address."""
        with self.app.app_context():
            result = self.auth.verify_email("test@example.com")

            # Check that the method returned success
            self.assertTrue(result)

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertEqual(update["$set"]["email_verified"], True)

    def test_update_user_role(self):
        """Test updating a user's role."""
        with self.app.app_context():
            result = self.auth.update_user_role("test@example.com", "admin")

            # Check that the method returned success
            self.assertTrue(result)

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertEqual(update["$set"]["role"], "admin")

    def test_update_user_role_invalid_role(self):
        """Test updating a user's role with an invalid role."""
        with self.app.app_context():
            result = self.auth.update_user_role("test@example.com", "superuser")

            # Check that the method returned failure
            self.assertFalse(result)

            # Check that no update was performed
            self.assertEqual(len(self.mock_users_collection.updated), 0)

    def test_set_user_active_status_activate(self):
        """Test activating a user account."""
        with self.app.app_context():
            result = self.auth.set_user_active_status("test@example.com", True)

            # Check that the method returned success
            self.assertTrue(result)

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertEqual(update["$set"]["is_active"], True)
            self.assertEqual(update["$set"]["login_attempts"], 0)
            self.assertIsNone(update["$set"]["locked_until"])

    def test_set_user_active_status_deactivate(self):
        """Test deactivating a user account."""
        with self.app.app_context():
            result = self.auth.set_user_active_status("test@example.com", False)

            # Check that the method returned success
            self.assertTrue(result)

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertEqual(update["$set"]["is_active"], False)

    def test_add_user_success(self):
        """Test adding a new user successfully."""
        # Mock current_user
        mock_current_user = MagicMock()
        mock_current_user.is_authenticated = True
        mock_current_user.username = "admin@example.com"

        with patch("duo_flask_auth.auth.current_user", mock_current_user):
            with self.app.test_request_context():
                result = self.auth.add_user("newuser@example.com", "NewPassword123")

                # Check that the method returned success
                self.assertTrue(result.startswith("Success"))

                # Check that the user was added
                self.assertEqual(len(self.mock_users_collection.inserted), 1)
                new_user = self.mock_users_collection.inserted[0]
                self.assertEqual(new_user["username"], "newuser@example.com")
                self.assertTrue("password_hash" in new_user)
                self.assertEqual(new_user["created_by"], "admin@example.com")
                self.assertEqual(new_user["role"], "user")
                self.assertTrue(new_user["is_active"])

    def test_add_user_not_admin(self):
        """Test adding a user without admin privileges."""
        # Mock current_user
        mock_current_user = MagicMock()
        mock_current_user.is_authenticated = True
        mock_current_user.username = "test@example.com"  # Not an admin

        with patch("duo_flask_auth.auth.current_user", mock_current_user):
            with self.app.test_request_context():
                result = self.auth.add_user("newuser@example.com", "NewPassword123")

                # Check that the method returned an error
                self.assertTrue(result.startswith("Error"))
                self.assertIn("Admin privileges required", result)

                # Check that no user was added
                self.assertEqual(len(self.mock_users_collection.inserted), 0)

    def test_add_user_invalid_email(self):
        """Test adding a user with an invalid email address."""
        # Mock current_user
        mock_current_user = MagicMock()
        mock_current_user.is_authenticated = True
        mock_current_user.username = "admin@example.com"

        with patch("duo_flask_auth.auth.current_user", mock_current_user):
            with self.app.test_request_context():
                result = self.auth.add_user("not-an-email", "NewPassword123")

                # Check that the method returned an error
                self.assertTrue(result.startswith("Error"))
                self.assertIn("not a valid email address", result)

                # Check that no user was added
                self.assertEqual(len(self.mock_users_collection.inserted), 0)

    def test_add_user_weak_password(self):
        """Test adding a user with a weak password."""
        # Mock current_user
        mock_current_user = MagicMock()
        mock_current_user.is_authenticated = True
        mock_current_user.username = "admin@example.com"

        with patch("duo_flask_auth.auth.current_user", mock_current_user):
            with self.app.test_request_context():
                # Test with a password that's too short
                result = self.auth.add_user("newuser@example.com", "Short1")

                # Check that the method returned an error
                self.assertTrue(result.startswith("Error"))
                self.assertIn("Password must be at least", result)

                # Check that no user was added
                self.assertEqual(len(self.mock_users_collection.inserted), 0)

                # Test with a password missing uppercase
                result = self.auth.add_user("newuser@example.com", "password123")
                self.assertTrue(result.startswith("Error"))
                self.assertIn("must contain uppercase", result)

                # Test with a password missing lowercase
                result = self.auth.add_user("newuser@example.com", "PASSWORD123")
                self.assertTrue(result.startswith("Error"))
                self.assertIn("must contain lowercase", result)

                # Test with a password missing digits
                result = self.auth.add_user("newuser@example.com", "PasswordOnly")
                self.assertTrue(result.startswith("Error"))
                self.assertIn("must contain", result)


if __name__ == "__main__":
    unittest.main()