"""
Tests for the security features of the Duo Flask Auth library.
"""

import unittest
import time
from unittest.mock import patch, MagicMock, ANY
from datetime import datetime, timedelta

from flask import Flask, session, request
from werkzeug.security import generate_password_hash

from duo_flask_auth import DuoFlaskAuth
from duo_flask_auth.exceptions import (
    AuthError,
    InvalidCredentialsError,
    AccountLockedError,
    RateLimitedError,
    PasswordPolicyError,
    TokenInvalidError
)


class MockCollection:
    """Mock MongoDB collection for testing."""

    def __init__(self, data=None):
        self.data = data or []
        self.inserted = []
        self.updated = []
        self.deleted = []

    def find_one(self, query):
        """Mock find_one method."""
        if not self.data:
            return None

        # Simple query matching
        if isinstance(query, dict):
            # Match by username
            if "username" in query:
                for item in self.data:
                    if item.get("username") == query["username"]:
                        return item

            # Match by reset token
            if "reset_token" in query:
                for item in self.data:
                    if item.get("reset_token") == query["reset_token"]:
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

    def delete_one(self, query):
        """Mock delete_one method."""
        self.deleted.append(query)
        mock_result = MagicMock()
        mock_result.deleted_count = 1
        return mock_result

    def find(self, query=None):
        """Mock find method."""
        return self.data

    def create_index(self, keys, **kwargs):
        """Mock create_index method."""
        return "index_name"


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


class TestSecurity(unittest.TestCase):
    """Tests for the security features of DuoFlaskAuth."""

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

        # Create a locked user
        self.locked_user = {
            "_id": "user_id_67890",
            "username": "locked@example.com",
            "password_hash": generate_password_hash("Password123"),
            "created_by": "admin@example.com",
            "created_at": datetime.utcnow(),
            "is_active": True,
            "role": "user",
            "last_password_change": datetime.utcnow(),
            "account_id": "account_id_67890",
            "login_attempts": 5,
            "creation_ip": "127.0.0.1",
            "mfa_enabled": False,
            "last_login": None,
            "email_verified": False,
            "reset_token": None,
            "reset_token_expires": None,
            "locked_until": datetime.utcnow() + timedelta(minutes=30)
        }

        # Create a user with an expired password
        self.expired_password_user = {
            "_id": "user_id_24680",
            "username": "expired@example.com",
            "password_hash": generate_password_hash("Password123"),
            "created_by": "admin@example.com",
            "created_at": datetime.utcnow() - timedelta(days=100),
            "is_active": True,
            "role": "user",
            "last_password_change": datetime.utcnow() - timedelta(days=100),
            "account_id": "account_id_24680",
            "login_attempts": 0,
            "creation_ip": "127.0.0.1",
            "mfa_enabled": False,
            "last_login": None,
            "email_verified": False,
            "reset_token": None,
            "reset_token_expires": None,
            "locked_until": None
        }

        # Create a user with a reset token
        self.reset_token_user = {
            "_id": "user_id_13579",
            "username": "reset@example.com",
            "password_hash": generate_password_hash("Password123"),
            "created_by": "admin@example.com",
            "created_at": datetime.utcnow(),
            "is_active": True,
            "role": "user",
            "last_password_change": datetime.utcnow() - timedelta(days=10),
            "account_id": "account_id_13579",
            "login_attempts": 0,
            "creation_ip": "127.0.0.1",
            "mfa_enabled": False,
            "last_login": None,
            "email_verified": False,
            "reset_token": "test_reset_token",
            "reset_token_expires": datetime.utcnow() + timedelta(hours=24)
        }

        # Mock MongoDB collections
        self.mock_users_collection = MockCollection([
            self.test_user,
            self.locked_user,
            self.expired_password_user,
            self.reset_token_user
        ])
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

        # Configure security options
        self.rate_limit_config = {
            "enabled": True,
            "max_attempts": {
                "login": 3,
                "password_reset": 2
            },
            "window_seconds": {
                "login": 300,
                "password_reset": 600
            }
        }

        self.account_lockout_config = {
            "enabled": True,
            "max_attempts": 3,
            "lockout_duration": 1800,  # 30 minutes
            "lockout_reset_on_success": True
        }

        self.password_policy = {
            "min_length": 8,
            "require_upper": True,
            "require_lower": True,
            "require_digit": True,
            "require_special": False,
            "max_age_days": 90,
            "prevent_common": True,
            "common_passwords": ["Password123", "Admin123", "Welcome123"]
        }

        # Initialize DuoFlaskAuth with security features
        self.auth = DuoFlaskAuth(
            app=self.app,
            db_config=self.db_config,
            rate_limit_config=self.rate_limit_config,
            account_lockout_config=self.account_lockout_config,
            password_policy=self.password_policy
        )

        # Create test client
        self.client = self.app.test_client()

    def tearDown(self):
        """Tear down the test environment."""
        self.mongo_connect_patcher.stop()

    def test_rate_limiting(self):
        """Test rate limiting for login attempts."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "nonexistent@example.com",
            "password": "WrongPassword"
        }):
            # First attempt
            response = self.auth.login()

            # Second attempt
            response = self.auth.login()

            # Third attempt
            response = self.auth.login()

            # Fourth attempt - should be rate limited
            with patch("duo_flask_auth.auth.render_template") as mock_render_template:
                response = self.auth.login()

                # Check that the template was rendered with a rate limit error
                mock_render_template.assert_called_with(
                    "login_page.html",
                    error=True,
                    message=ANY,
                    error_code="rate_limited"
                )

    def test_account_lockout(self):
        """Test account lockout after too many failed login attempts."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "test@example.com",
            "password": "WrongPassword"
        }):
            # First attempt
            response = self.auth.login()

            # Check that login attempts were incremented
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertEqual(update["$inc"]["login_attempts"], 1)

            # Reset the updated list
            self.mock_users_collection.updated = []

            # Second attempt
            response = self.auth.login()

            # Third attempt
            response = self.auth.login()

            # Check if account was locked
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertIn("$set", update)
            self.assertIn("locked_until", update["$set"])

    def test_login_with_locked_account(self):
        """Test attempting to login with a locked account."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "locked@example.com",
            "password": "Password123"
        }):
            with patch("duo_flask_auth.auth.render_template") as mock_render_template:
                response = self.auth.login()

                # Check that the template was rendered with a locked account error
                mock_render_template.assert_called_with(
                    "login_page.html",
                    error=True,
                    message=ANY,
                    error_code="account_locked"
                )

    def test_unlock_account(self):
        """Test unlocking an account."""
        # Mock current_user to be admin
        mock_current_user = MagicMock()
        mock_current_user.is_authenticated = True
        mock_current_user.username = "admin@example.com"

        # Add admin to mock db
        self.mock_users_collection.data.append({
            "_id": "admin_id",
            "username": "admin@example.com",
            "role": "admin"
        })

        with patch("duo_flask_auth.auth.current_user", mock_current_user):
            with self.app.test_request_context():
                result = self.auth._unlock_account("locked@example.com")

                # Check that the account was unlocked
                self.assertTrue(result)

                # Check that the update was correct
                self.assertEqual(len(self.mock_users_collection.updated), 1)
                query, update = self.mock_users_collection.updated[0]
                self.assertEqual(query, {"username": "locked@example.com"})
                self.assertEqual(update["$set"]["login_attempts"], 0)
                self.assertIsNone(update["$set"]["locked_until"])

    def test_password_expiration(self):
        """Test password expiration detection."""
        with self.app.app_context():
            # Check if a normal user's password is expired
            self.assertFalse(self.auth._is_password_expired(self.test_user))

            # Check if an expired password is detected
            self.assertTrue(self.auth._is_password_expired(self.expired_password_user))

    @patch("duo_flask_auth.auth.login_user")
    @patch("duo_flask_auth.auth.redirect")
    def test_login_with_expired_password(self, mock_redirect, mock_login_user):
        """Test login with an expired password."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "expired@example.com",
            "password": "Password123"
        }):
            # Initialize session
            with self.client.session_transaction() as sess:
                pass

            response = self.auth.login()

            # Check that the user was logged in
            mock_login_user.assert_called_once()

            # Check that the password_expired flag was set in the session
            self.assertTrue(session.get("password_expired"))

            # Check that we were redirected to the password_expired page
            mock_redirect.assert_called_with("/password-expired")

    def test_password_validation(self):
        """Test password policy validation."""
        with self.app.app_context():
            # Test valid password
            is_valid, reason = self.auth._validate_password("StrongP@ss123")
            self.assertTrue(is_valid)
            self.assertIsNone(reason)

            # Test password that's too short
            is_valid, reason = self.auth._validate_password("Short1")
            self.assertFalse(is_valid)
            self.assertIn("length", reason)

            # Test password without uppercase
            is_valid, reason = self.auth._validate_password("password123")
            self.assertFalse(is_valid)
            self.assertIn("uppercase", reason)

            # Test password without lowercase
            is_valid, reason = self.auth._validate_password("PASSWORD123")
            self.assertFalse(is_valid)
            self.assertIn("lowercase", reason)

            # Test password without digits
            is_valid, reason = self.auth._validate_password("PasswordOnly")
            self.assertFalse(is_valid)
            self.assertIn("digit", reason)

            # Test common password
            is_valid, reason = self.auth._validate_password("Password123")
            self.assertFalse(is_valid)
            self.assertIn("common", reason)

    def test_password_reset_token_generation(self):
        """Test generating a password reset token."""
        with self.app.test_request_context():
            token = self.auth.generate_password_reset_token("test@example.com")

            # Check that a token was generated
            self.assertIsNotNone(token)

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "test@example.com"})
            self.assertIn("$set", update)
            self.assertIn("reset_token", update["$set"])
            self.assertIn("reset_token_expires", update["$set"])

    def test_password_reset_with_token(self):
        """Test resetting a password with a token."""
        with self.app.test_request_context():
            result = self.auth.reset_password_with_token(
                "reset@example.com",
                "test_reset_token",
                "NewStrongP@ss456"
            )

            # Check that the reset was successful
            self.assertTrue(result)

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "reset@example.com"})
            self.assertIn("$set", update)
            self.assertIn("password_hash", update["$set"])
            self.assertIn("last_password_change", update["$set"])
            self.assertIsNone(update["$set"]["reset_token"])
            self.assertIsNone(update["$set"]["reset_token_expires"])

    def test_password_reset_with_invalid_token(self):
        """Test resetting a password with an invalid token."""
        with self.app.test_request_context():
            result = self.auth.reset_password_with_token(
                "reset@example.com",
                "invalid_token",
                "NewStrongP@ss456"
            )

            # Check that the reset failed
            self.assertFalse(result)

            # Check that no user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 0)

    def test_password_reset_with_weak_password(self):
        """Test resetting a password with a weak password."""
        with self.app.test_request_context():
            result = self.auth.reset_password_with_token(
                "reset@example.com",
                "test_reset_token",
                "weak"
            )

            # Check that the reset failed
            self.assertFalse(result)

            # Check that no user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 0)

    def test_rate_limit_password_reset(self):
        """Test rate limiting for password reset requests."""
        with self.app.test_request_context():
            # First attempt
            token1 = self.auth.generate_password_reset_token("test@example.com")
            self.assertIsNotNone(token1)

            # Second attempt
            token2 = self.auth.generate_password_reset_token("test@example.com")
            self.assertIsNotNone(token2)

            # Third attempt - should be rate limited
            token3 = self.auth.generate_password_reset_token("test@example.com")
            self.assertIsNone(token3)

    def test_log_security_event(self):
        """Test logging security events."""
        with self.app.test_request_context():
            # Create a security events collection if it doesn't exist
            if "security_events" not in self.mock_db.collections:
                self.mock_db.create_collection("security_events")

            # Log an event
            self.auth.log_security_event(
                event_type="login_failed",
                username="test@example.com",
                details={"reason": "Invalid password"}
            )

            # Check that the event was logged
            self.assertEqual(len(self.mock_security_events_collection.inserted), 1)
            event = self.mock_security_events_collection.inserted[0]
            self.assertEqual(event["event_type"], "login_failed")
            self.assertEqual(event["username"], "test@example.com")
            self.assertEqual(event["details"]["reason"], "Invalid password")


if __name__ == "__main__":
    unittest.main()