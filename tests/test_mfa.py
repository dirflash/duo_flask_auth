"""
Tests for the Duo MFA functionality of the Duo Flask Auth library.
"""

import unittest
from unittest.mock import patch, MagicMock, ANY
from datetime import datetime

from flask import Flask, session
from werkzeug.security import generate_password_hash

from duo_flask_auth import DuoFlaskAuth
from duo_universal.client import DuoException


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

    def update_one(self, query, update):
        """Mock update_one method."""
        self.updated.append((query, update))
        mock_result = MagicMock()
        mock_result.modified_count = 1
        return mock_result


class MockDB:
    """Mock MongoDB database for testing."""

    def __init__(self, collections=None):
        self.collections = collections or {
            "users": MockCollection(),
            "security_events": MockCollection()
        }

    def __getitem__(self, name):
        return self.collections.get(name, MockCollection())


class MockMongoClient:
    """Mock MongoDB client for testing."""

    def __init__(self, dbs=None):
        self.dbs = dbs or {
            "fuse-db": MockDB()
        }

    def __getitem__(self, name):
        return self.dbs.get(name, MockDB())


class TestDuoMFA(unittest.TestCase):
    """Tests for the Duo MFA functionality."""

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

        # Test Duo config
        self.duo_config = {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "api_host": "api-test.duosecurity.com",
            "redirect_uri": "https://example.com/duo-callback"
        }

        # Create a test user with MFA enabled
        self.test_user_mfa = {
            "_id": "user_id_12345",
            "username": "mfa_user@example.com",
            "password_hash": generate_password_hash("Password123"),
            "created_by": "admin@example.com",
            "created_at": datetime.utcnow(),
            "is_active": True,
            "role": "user",
            "last_password_change": datetime.utcnow(),
            "account_id": "account_id_12345",
            "login_attempts": 0,
            "creation_ip": "127.0.0.1",
            "mfa_enabled": True,
            "last_login": None,
            "email_verified": True,
            "reset_token": None,
            "reset_token_expires": None,
            "locked_until": None
        }

        # Create a test user without MFA
        self.test_user_no_mfa = {
            "_id": "user_id_67890",
            "username": "regular_user@example.com",
            "password_hash": generate_password_hash("Password123"),
            "created_by": "admin@example.com",
            "created_at": datetime.utcnow(),
            "is_active": True,
            "role": "user",
            "last_password_change": datetime.utcnow(),
            "account_id": "account_id_67890",
            "login_attempts": 0,
            "creation_ip": "127.0.0.1",
            "mfa_enabled": False,
            "last_login": None,
            "email_verified": True,
            "reset_token": None,
            "reset_token_expires": None,
            "locked_until": None
        }

        # Mock MongoDB collections
        self.mock_users_collection = MockCollection([self.test_user_mfa, self.test_user_no_mfa])

        # Mock MongoDB db
        self.mock_db = MockDB({
            "users": self.mock_users_collection
        })

        # Mock MongoDB client
        self.mock_mongo_client = MockMongoClient({
            "fuse-db": self.mock_db
        })

        # Create patcher for mongo_connect
        self.mongo_connect_patcher = patch("duo_flask_auth.auth.MongoClient")
        self.mock_mongo_connect = self.mongo_connect_patcher.start()
        self.mock_mongo_connect.return_value = self.mock_mongo_client

        # Create mock Duo client
        self.mock_duo_client = MagicMock()

        # Create patcher for Duo Client
        self.duo_client_patcher = patch("duo_flask_auth.auth.Client")
        self.mock_duo_client_class = self.duo_client_patcher.start()
        self.mock_duo_client_class.return_value = self.mock_duo_client

        # Set up mock methods for Duo client
        self.mock_duo_client.health_check.return_value = True
        self.mock_duo_client.generate_state.return_value = "test_state"
        self.mock_duo_client.create_auth_url.return_value = "https://api-test.duosecurity.com/auth?request=test"
        self.mock_duo_client.exchange_authorization_code_for_2fa_result.return_value = {
            "preferred_username": "mfa_user@example.com"
        }

        # Initialize DuoFlaskAuth with mocked MongoDB and Duo
        self.auth = DuoFlaskAuth(
            app=self.app,
            db_config=self.db_config,
            duo_config=self.duo_config
        )

        # Create test client
        self.client = self.app.test_client()

    def tearDown(self):
        """Tear down the test environment."""
        self.mongo_connect_patcher.stop()
        self.duo_client_patcher.stop()

    def test_duo_client_initialization(self):
        """Test that the Duo client is initialized correctly."""
        # Check that the Duo client was initialized with the correct parameters
        self.mock_duo_client_class.assert_called_once_with(
            client_id=self.duo_config["client_id"],
            client_secret=self.duo_config["client_secret"],
            host=self.duo_config["api_host"],
            redirect_uri=self.duo_config["redirect_uri"],
        )

    @patch("duo_flask_auth.auth.redirect")
    def test_login_with_mfa(self, mock_redirect):
        """Test login flow with MFA enabled."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "mfa_user@example.com",
            "password": "Password123"
        }):
            # Initialize session
            with self.client.session_transaction() as sess:
                pass

            response = self.auth.login()

            # Check that the Duo health check was called
            self.mock_duo_client.health_check.assert_called_once()

            # Check that a state was generated
            self.mock_duo_client.generate_state.assert_called_once()

            # Check that the Duo auth URL was created
            self.mock_duo_client.create_auth_url.assert_called_once_with("mfa_user@example.com", "test_state")

            # Check that we stored the state and username in the session
            self.assertEqual(session.get("duo_state"), "test_state")
            self.assertEqual(session.get("pending_username"), "mfa_user@example.com")

            # Check that we redirected to Duo
            mock_redirect.assert_called_once_with("https://api-test.duosecurity.com/auth?request=test")

    @patch("duo_flask_auth.auth.login_user")
    def test_login_without_mfa(self, mock_login_user):
        """Test login flow without MFA."""
        with self.app.test_request_context("/login/", method="POST", data={
            "username": "regular_user@example.com",
            "password": "Password123"
        }):
            response = self.auth.login()

            # Check that Duo was not used
            self.mock_duo_client.health_check.assert_not_called()
            self.mock_duo_client.generate_state.assert_not_called()
            self.mock_duo_client.create_auth_url.assert_not_called()

            # Check that the user was logged in directly
            mock_login_user.assert_called_once()

    @patch("duo_flask_auth.auth.redirect")
    @patch("duo_flask_auth.auth.login_user")
    def test_duo_callback_success(self, mock_login_user, mock_redirect):
        """Test successful Duo callback."""
        with self.app.test_request_context("/duo-callback?state=test_state&duo_code=test_code"):
            # Set up session state
            with self.client.session_transaction() as sess:
                sess["duo_state"] = "test_state"
                sess["pending_username"] = "mfa_user@example.com"

            response = self.auth.duo_callback()

            # Check that the code was exchanged
            self.mock_duo_client.exchange_authorization_code_for_2fa_result.assert_called_once_with(
                "test_code", "mfa_user@example.com"
            )

            # Check that the user was logged in
            mock_login_user.assert_called_once()

            # Check that the session was cleaned up
            self.assertNotIn("duo_state", session)
            self.assertNotIn("pending_username", session)

            # Check that we redirected to the success page
            mock_redirect.assert_called_once()

    @patch("duo_flask_auth.auth.flash")
    @patch("duo_flask_auth.auth.redirect")
    def test_duo_callback_state_mismatch(self, mock_redirect, mock_flash):
        """Test Duo callback with mismatched state."""
        with self.app.test_request_context("/duo-callback?state=wrong_state&duo_code=test_code"):
            # Set up session state
            with self.client.session_transaction() as sess:
                sess["duo_state"] = "test_state"
                sess["pending_username"] = "mfa_user@example.com"

            response = self.auth.duo_callback()

            # Check that we did not exchange the code
            self.mock_duo_client.exchange_authorization_code_for_2fa_result.assert_not_called()

            # Check that an error was shown
            mock_flash.assert_called_once_with("Two-factor authentication failed", "error")

            # Check that we redirected to the login page
            mock_redirect.assert_called_once_with("/login/")

    @patch("duo_flask_auth.auth.flash")
    @patch("duo_flask_auth.auth.redirect")
    def test_duo_callback_missing_state(self, mock_redirect, mock_flash):
        """Test Duo callback without state in session."""
        with self.app.test_request_context("/duo-callback?state=test_state&duo_code=test_code"):
            # No session setup

            response = self.auth.duo_callback()

            # Check that we did not exchange the code
            self.mock_duo_client.exchange_authorization_code_for_2fa_result.assert_not_called()

            # Check that we redirected to the login page
            mock_redirect.assert_called_once_with("/login/")

    @patch("duo_flask_auth.auth.render_template")
    def test_enable_mfa_get(self, mock_render_template):
        """Test the GET request to enable MFA."""
        with self.app.test_request_context("/enable-mfa", method="GET"):
            response = self.auth.enable_mfa()

            # Check that the template was rendered
            mock_render_template.assert_called_once_with("enable_mfa.html")

    @patch("duo_flask_auth.auth.flash")
    @patch("duo_flask_auth.auth.redirect")
    @patch("duo_flask_auth.auth.current_user")
    def test_enable_mfa_post(self, mock_current_user, mock_redirect, mock_flash):
        """Test the POST request to enable MFA."""
        mock_current_user.username = "regular_user@example.com"

        with self.app.test_request_context("/enable-mfa", method="POST"):
            response = self.auth.enable_mfa()

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "regular_user@example.com"})
            self.assertEqual(update["$set"]["mfa_enabled"], True)

            # Check that a success message was flashed
            mock_flash.assert_called_once_with("MFA has been enabled for your account.", "success")

            # Check that we redirected to the success page
            mock_redirect.assert_called_once()

    @patch("duo_flask_auth.auth.render_template")
    def test_disable_mfa_get(self, mock_render_template):
        """Test the GET request to disable MFA."""
        with self.app.test_request_context("/disable-mfa", method="GET"):
            response = self.auth.disable_mfa()

            # Check that the template was rendered
            mock_render_template.assert_called_once_with("disable_mfa.html")

    @patch("duo_flask_auth.auth.flash")
    @patch("duo_flask_auth.auth.redirect")
    @patch("duo_flask_auth.auth.current_user")
    def test_disable_mfa_post(self, mock_current_user, mock_redirect, mock_flash):
        """Test the POST request to disable MFA."""
        mock_current_user.username = "mfa_user@example.com"

        with self.app.test_request_context("/disable-mfa", method="POST"):
            response = self.auth.disable_mfa()

            # Check that the user was updated
            self.assertEqual(len(self.mock_users_collection.updated), 1)
            query, update = self.mock_users_collection.updated[0]
            self.assertEqual(query, {"username": "mfa_user@example.com"})
            self.assertEqual(update["$set"]["mfa_enabled"], False)

            # Check that a success message was flashed
            mock_flash.assert_called_once_with("MFA has been disabled for your account.", "success")

            # Check that we redirected to the success page
            mock_redirect.assert_called_once()

    @patch("duo_flask_auth.auth.login_user")
    @patch("duo_flask_auth.auth.redirect")
    def test_duo_health_check_failure(self, mock_redirect, mock_login_user):
        """Test login with MFA when Duo health check fails."""
        # Make health_check raise an exception
        self.mock_duo_client.health_check.side_effect = DuoException("Duo service unavailable")

        with self.app.test_request_context("/login/", method="POST", data={
            "username": "mfa_user@example.com",
            "password": "Password123"
        }):
            response = self.auth.login()

            # Check that the health check was called
            self.mock_duo_client.health_check.assert_called_once()

            # Check that the user was logged in directly (fail open)
            mock_login_user.assert_called_once()

            # Check that we redirected to the success page
            mock_redirect.assert_called_once()


if __name__ == "__main__":
    unittest.main()