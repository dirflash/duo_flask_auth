"""
Tests for the performance enhancements of the Duo Flask Auth library.
"""

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask
from werkzeug.security import generate_password_hash

# Add parent directory to path to allow direct imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Direct imports from modules (avoiding __init__.py)
from duo_flask_auth import DuoFlaskAuth
from duo_flask_auth.cache import MemoryCache, NoCache


class TestCaching(unittest.TestCase):
    """Tests for the caching system."""

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
            "database": "test-db",
        }

        # Test cache config
        self.cache_config = {
            "enabled": True,
            "type": "memory",
            "default_ttl": 300,
            "user_ttl": 60,
            "security_events_ttl": 300,
        }

        # Set up database mocks
        self.mock_db_adapter = MagicMock()

        # Test user data
        self.test_user = {
            "_id": "user_id_12345",
            "username": "test@example.com",
            "password_hash": generate_password_hash("Password123"),
            "is_active": True,
            "role": "user",
            "mfa_enabled": False,
        }

        # Mock get_user method
        self.mock_db_adapter.get_user.return_value = self.test_user

        # Initialize DuoFlaskAuth with mock database adapter and memory cache
        self.auth = DuoFlaskAuth(
            app=self.app, db_adapter=self.mock_db_adapter, cache_config=self.cache_config
        )

    def test_memory_cache_creation(self):
        """Test that the memory cache is created correctly."""
        self.assertIsInstance(self.auth.cache, MemoryCache)
        self.assertEqual(self.auth.cache_config["default_ttl"], 300)
        self.assertEqual(self.auth.cache_config["user_ttl"], 60)

    def test_disable_cache(self):
        """Test that caching can be disabled."""
        # Create a new auth instance with caching disabled
        cache_config = {"enabled": False}
        auth = DuoFlaskAuth(
            app=self.app, db_adapter=self.mock_db_adapter, cache_config=cache_config
        )

        self.assertIsInstance(auth.cache, NoCache)

    def test_cache_get_set(self):
        """Test basic cache get and set operations."""
        cache = self.auth.cache

        # Set a value
        cache.set("test_key", "test_value")

        # Get the value
        value = cache.get("test_key")

        self.assertEqual(value, "test_value")

        # Get a non-existent value
        value = cache.get("non_existent_key")

        self.assertIsNone(value)

    def test_cache_delete(self):
        """Test cache delete operation."""
        cache = self.auth.cache

        # Set a value
        cache.set("test_key", "test_value")

        # Delete the value
        cache.delete("test_key")

        # Try to get the deleted value
        value = cache.get("test_key")

        self.assertIsNone(value)

    def test_cache_clear(self):
        """Test cache clear operation."""
        cache = self.auth.cache

        # Set multiple values
        cache.set("key1", "value1")
        cache.set("key2", "value2")

        # Clear the cache
        cache.clear()

        # Try to get the values
        value1 = cache.get("key1")
        value2 = cache.get("key2")

        self.assertIsNone(value1)
        self.assertIsNone(value2)

    def test_cache_ttl(self):
        """Test that cache items expire after TTL."""
        cache = self.auth.cache

        # Set a value with a short TTL
        cache.set("short_ttl", "test_value", ttl=1)

        # Verify it exists
        self.assertEqual(cache.get("short_ttl"), "test_value")

        # Wait for it to expire
        time.sleep(1.1)

        # Verify it's gone
        self.assertIsNone(cache.get("short_ttl"))

    def test_user_caching(self):
        """Test that users are cached and fetched from cache."""
        with self.app.app_context():
            # First call should hit the database
            user1 = self.auth.load_user("test@example.com")

            # Verify the user was fetched from the database
            self.mock_db_adapter.get_user.assert_called_once_with("test@example.com")

            # Reset the mock to verify the second call
            self.mock_db_adapter.get_user.reset_mock()

            # Second call should hit the cache
            user2 = self.auth.load_user("test@example.com")

            # Verify the database was not queried
            self.mock_db_adapter.get_user.assert_not_called()

            # Verify both calls returned the same user
            self.assertEqual(user1.username, user2.username)

    def test_cache_invalidation(self):
        """Test that cache is invalidated when user data is updated."""
        with self.app.app_context():
            # First load the user to cache it
            user1 = self.auth.load_user("test@example.com")

            # Mock update_user to simulate user data update
            self.mock_db_adapter.update_user.return_value = True

            # Update the user to invalidate the cache
            self.auth.verify_email("test@example.com")

            # Reset the get_user mock to verify the next call
            self.mock_db_adapter.get_user.reset_mock()

            # Load the user again, should hit the database because cache was invalidated
            user2 = self.auth.load_user("test@example.com")

            # Verify the database was queried
            self.mock_db_adapter.get_user.assert_called_once_with("test@example.com")

    def test_cache_statistics(self):
        """Test that cache statistics are tracked."""
        cache = self.auth.cache

        # Initial stats
        stats = cache.get_stats()
        initial_hits = stats.hits
        initial_misses = stats.misses

        # Generate a cache hit
        cache.set("stats_test", "test_value")
        cache.get("stats_test")

        # Generate a cache miss
        cache.get("non_existent_key")

        # Get updated stats
        stats = cache.get_stats()

        # Verify stats were updated
        self.assertEqual(stats.hits, initial_hits + 1)
        self.assertEqual(stats.misses, initial_misses + 1)

    def test_get_cache_stats_method(self):
        """Test the get_cache_stats method."""
        # Set up some cache hits and misses
        cache = self.auth.cache
        cache.set("stats_test", "test_value")
        cache.get("stats_test")  # Hit
        cache.get("non_existent_key")  # Miss

        # Get stats from the auth instance
        stats = self.auth.get_cache_stats()

        # Verify stats contain expected values
        self.assertIn("hits", stats)
        self.assertIn("misses", stats)
        self.assertIn("hit_rate", stats)
        self.assertTrue(0 <= stats["hit_rate"] <= 1)  # Hit rate should be between 0 and 1


class TestDatabaseIndexing(unittest.TestCase):
    """Tests for the database indexing features."""

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
            "database": "test-db",
        }

        # Set up database mocks
        self.mock_db_adapter = MagicMock()

        # Set up mock for verify_indexes
        self.mock_db_adapter.verify_indexes.return_value = {
            "username_idx": True,
            "email_verified_idx": True,
            "reset_token_idx": False,
            "account_id_idx": True,
            "role_idx": True,
        }

        # Initialize DuoFlaskAuth with mock database adapter
        self.auth = DuoFlaskAuth(app=self.app, db_adapter=self.mock_db_adapter)

    def test_check_database_indexes(self):
        """Test the check_database_indexes method."""
        # Run index health check
        index_health = self.auth.check_database_indexes()

        # Verify the method calls the adapter's verify_indexes method
        self.mock_db_adapter.verify_indexes.assert_called_once()

        # Verify the response contains expected fields
        self.assertIn("status", index_health)
        self.assertIn("health_percentage", index_health)
        self.assertIn("existing_indexes", index_health)
        self.assertIn("total_indexes", index_health)
        self.assertIn("missing_indexes", index_health)

        # Verify health percentage calculation (4 out of 5 indexes exist)
        self.assertEqual(index_health["health_percentage"], 80.0)
        self.assertEqual(index_health["existing_indexes"], 4)
        self.assertEqual(index_health["total_indexes"], 5)

        # Verify missing indexes list
        self.assertEqual(index_health["missing_indexes"], ["reset_token_idx"])

        # Verify status determination
        self.assertEqual(index_health["status"], "warning")  # 80% healthy = warning

    def test_index_health_status_calculation(self):
        """Test health status calculations for different health percentages."""
        # Test healthy status (100%)
        self.mock_db_adapter.verify_indexes.return_value = {
            "username_idx": True,
            "email_verified_idx": True,
            "reset_token_idx": True,
            "account_id_idx": True,
            "role_idx": True,
        }
        index_health = self.auth.check_database_indexes()
        self.assertEqual(index_health["status"], "healthy")
        self.assertEqual(index_health["health_percentage"], 100.0)

        # Test warning status (80%)
        self.mock_db_adapter.verify_indexes.return_value = {
            "username_idx": True,
            "email_verified_idx": True,
            "reset_token_idx": True,
            "account_id_idx": True,
            "role_idx": False,
        }
        index_health = self.auth.check_database_indexes()
        self.assertEqual(index_health["status"], "warning")
        self.assertEqual(index_health["health_percentage"], 80.0)

        # Test critical status (50%)
        self.mock_db_adapter.verify_indexes.return_value = {
            "username_idx": True,
            "email_verified_idx": False,
            "reset_token_idx": False,
            "account_id_idx": True,
            "role_idx": False,
        }
        index_health = self.auth.check_database_indexes()
        self.assertEqual(index_health["status"], "critical")
        self.assertEqual(index_health["health_percentage"], 40.0)


class TestConnectionPooling(unittest.TestCase):
    """Tests for connection pooling features."""

    def setUp(self):
        """Set up the test environment."""
        self.app = Flask(__name__)
        self.app.config["SECRET_KEY"] = "test-secret-key"
        self.app.config["TESTING"] = True

        # Test database config with connection pooling options
        self.db_config = {
            "username": "test_user",
            "password": "test_password",
            "host": "test.mongodb.net",
            "database": "test-db",
            "pool_size": 50,
            "min_pool_size": 10,
            "max_idle_time_ms": 60000,
            "wait_queue_timeout_ms": 2000,
        }

        # Set up MongoDB client mock
        self.mock_mongo_client = MagicMock()

        # Patch MongoClient to return our mock
        self.mongo_client_patcher = patch("duo_flask_auth.db_adapters.MongoClient")
        self.mock_mongo_client_class = self.mongo_client_patcher.start()
        self.mock_mongo_client_class.return_value = self.mock_mongo_client

        # Set up mock database
        self.mock_db = MagicMock()
        self.mock_mongo_client.__getitem__.return_value = self.mock_db

        # Mock collections
        self.mock_users_collection = MagicMock()
        self.mock_db.__getitem__.return_value = self.mock_users_collection

    def tearDown(self):
        """Tear down the test environment."""
        self.mongo_client_patcher.stop()

    def test_connection_pooling_config(self):
        """Test that connection pooling is configured correctly."""
        # Initialize DuoFlaskAuth with MongoDB
        auth = DuoFlaskAuth(app=self.app, db_config=self.db_config)

        # Verify MongoClient was called with connection pooling parameters
        self.mock_mongo_client_class.assert_called_once()

        # Extract the call arguments
        call_args = self.mock_mongo_client_class.call_args

        # Verify URL argument (first positional argument)
        url_arg = call_args[0][0]
        self.assertIn("mongodb+srv://test_user:test_password@test.mongodb.net/test-db", url_arg)

        # Verify connection pooling keyword arguments
        kwargs = call_args[1]
        self.assertEqual(kwargs.get("maxPoolSize"), 50)
        self.assertEqual(kwargs.get("minPoolSize"), 10)
        self.assertEqual(kwargs.get("maxIdleTimeMS"), 60000)
        self.assertEqual(kwargs.get("waitQueueTimeoutMS"), 2000)

    def test_default_connection_pooling_values(self):
        """Test default connection pooling values when not specified."""
        # Initialize with minimal config
        minimal_db_config = {
            "username": "test_user",
            "password": "test_password",
            "host": "test.mongodb.net",
            "database": "test-db",
        }

        # Reset the mock to clear previous calls
        self.mock_mongo_client_class.reset_mock()

        # Initialize DuoFlaskAuth with minimal config
        auth = DuoFlaskAuth(app=self.app, db_config=minimal_db_config)

        # Verify MongoClient was called
        self.mock_mongo_client_class.assert_called_once()

        # Extract the call arguments
        kwargs = self.mock_mongo_client_class.call_args[1]

        # Verify default values
        # Note: These checks will depend on what default values you set in your adapter
        self.assertIsNotNone(kwargs.get("maxPoolSize"))
        self.assertIsNotNone(kwargs.get("serverSelectionTimeoutMS"))


if __name__ == "__main__":
    unittest.main()
