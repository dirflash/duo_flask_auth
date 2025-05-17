"""
Database adapters for the Duo Flask Auth library.

This module provides database adapter interfaces and implementations for different database backends.
"""

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pymongo import ASCENDING, DESCENDING


class DatabaseAdapter(ABC):
    """
    Abstract base class for database adapters.

    This class defines the interface that all database adapters must implement.
    It provides methods for user management and security event logging.
    """

    @abstractmethod
    def initialize(self, app=None) -> None:
        """
        Initialize the database adapter.

        Args:
            app: The Flask application, if available.
        """
        pass

    @abstractmethod
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a user by username.

        Args:
            username: The username to look up.

        Returns:
            The user data as a dictionary, or None if not found.
        """
        pass

    @abstractmethod
    def create_user(self, user_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Create a new user.

        Args:
            user_data: The user data to insert.

        Returns:
            A tuple containing:
            - Boolean indicating success/failure
            - User ID or error message
        """
        pass

    @abstractmethod
    def list_users(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_by: str = "username",
        sort_direction: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        List users with optional filtering, pagination, and sorting.

        Args:
            filter_criteria: Optional dictionary of filter criteria
            limit: Maximum number of users to return (default: 100)
            skip: Number of users to skip (for pagination)
            sort_by: Field to sort by (default: username)
            sort_direction: Sort direction (1 for ascending, -1 for descending)

        Returns:
            List of user data dictionaries
        """
        pass

    @abstractmethod
    def update_user(self, username: str, update_data: Dict[str, Any]) -> bool:
        """
        Update a user's data.

        Args:
            username: The username of the user to update.
            update_data: The data to update.

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    def delete_user(self, username: str) -> bool:
        """
        Delete a user.

        Args:
            username: The username of the user to delete.

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    def increment_login_attempts(self, username: str) -> int:
        """
        Increment the login attempts counter for a user.

        Args:
            username: The username of the user.

        Returns:
            The new number of login attempts.
        """
        pass

    @abstractmethod
    def reset_login_attempts(self, username: str) -> bool:
        """
        Reset the login attempts counter for a user.

        Args:
            username: The username of the user.

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    def get_user_by_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get a user by reset token.

        Args:
            token: The reset token.

        Returns:
            The user data if found, None otherwise.
        """
        pass

    @abstractmethod
    def log_security_event(self, event_data: Dict[str, Any]) -> bool:
        """
        Log a security event.

        Args:
            event_data: The event data to log.

        Returns:
            True if successful, False otherwise.
        """
        pass

    @abstractmethod
    def get_security_events(self,
                          filters: Optional[Dict[str, Any]] = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get security events.

        Args:
            filters: Optional filters to apply.
            limit: Maximum number of events to return.

        Returns:
            A list of security events.
        """
        pass


class MongoDBAdapter(DatabaseAdapter):
    """
    MongoDB adapter for the Duo Flask Auth library.

    This adapter uses PyMongo to interact with a MongoDB database.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the MongoDB adapter with enhanced connection pooling.

        Args:
            config: MongoDB configuration dictionary.
                Required keys: username, password, host, database
                Optional connection pooling keys:
                    - pool_size: Maximum number of connections in the pool (default: 50)
                    - min_pool_size: Minimum connections to maintain (default: 10)
                    - max_idle_time_ms: Maximum time a connection can remain idle (default: 60000)
                    - wait_queue_timeout_ms: How long to wait for an available connection (default: 2000)
                    - connect_timeout_ms: Timeout for initial connection (default: 30000)
                    - socket_timeout_ms: Timeout for operations (default: 45000)
        """
        self.config = config
        self.client = None
        self.db = None
        self.logger = logging.getLogger("duo_flask_auth.db_adapters.MongoDBAdapter")

    def initialize(self, app=None) -> None:
        """
        Initialize the MongoDB connection and create indexes.

        Args:
            app: The Flask application, if available.
        """
        if app:
            app.logger.info("Initializing MongoDB adapter")

        # Connect to MongoDB
        self._connect()

        # Create indexes if db is available
        if self.db is not None:
            self._create_indexes()

    def _connect(self) -> None:
        """
        Connect to MongoDB with optimized connection pooling.
        """
        try:
            # Extract basic configuration
            db_un = self.config.get("username")
            db_pw = self.config.get("password")
            mongo_host = self.config.get("host")
            db_name = self.config.get("database")  # Check both 'database' and 'db_name'

            # If db_name is not provided, check if there's a 'db_name' field (for backward compatibility)
            if not db_name:
                db_name = self.config.get("db_name")

            # Check if all required parameters are provided
            if not all([db_un, db_pw, mongo_host, db_name]):
                self.logger.error("MongoDB configuration is incomplete")
                # log the missing parameters
                missing_params = [
                    param
                    for param in ["username", "password", "host", "database"]
                    if not self.config.get(param)
                    and not (param == "database" and self.config.get("db_name"))
                ]
                self.logger.error(f"Missing MongoDB configuration parameters: {missing_params}")
                return

            # Rest of the method remains the same
            # ...
        except Exception as e:
            self.logger.error(f"Error connecting to MongoDB: {e}")
            self.client = None
            self.db = None

    def _create_indexes(self) -> None:
        """
        Create optimized indexes for MongoDB collections.
        """
        try:
            # Get the users collection
            if self.db is None:
                self.logger.error("MongoDB not connected")
                return

            # Define sorting directions in case imports fail
            ascending = ASCENDING if "ASCENDING" in globals() else 1
            descending = DESCENDING if "DESCENDING" in globals() else -1

            users_collection = self.db["users"]

            # Create indexes for users collection
            self.logger.info("Creating optimized MongoDB indexes...")

            # Track created indexes
            index_names = []

            # 1. Username index - most frequently queried field
            index_name = users_collection.create_index(
                [("username", ascending)], unique=True, background=True, name="username_idx"
            )
            index_names.append(index_name)

            # 2. Email verification status index
            index_name = users_collection.create_index(
                [("email_verified", ascending)], background=True, name="email_verified_idx"
            )
            index_names.append(index_name)

            # 3. Reset token index with TTL expiration
            index_name = users_collection.create_index(
                [("reset_token", ascending)],
                sparse=True,  # Only index documents with this field
                unique=True,  # Each token must be unique
                background=True,
                name="reset_token_idx",
            )
            index_names.append(index_name)

            # 4. Separate index for reset token expiration for TTL
            # This automatically removes expired tokens
            index_name = users_collection.create_index(
                [("reset_token_expires", ascending)],
                sparse=True,  # Only index documents with this field
                expireAfterSeconds=0,  # Expire at the exact time
                background=True,
                name="reset_token_ttl_idx",
            )
            index_names.append(index_name)

            # 5. Account ID index
            index_name = users_collection.create_index(
                [("account_id", ascending)], unique=True, background=True, name="account_id_idx"
            )
            index_names.append(index_name)

            # 6. Role index for role-based access checks
            index_name = users_collection.create_index(
                [("role", ascending)], background=True, name="role_idx"
            )
            index_names.append(index_name)

            # 7. Account status compound index - optimizes lockout checks
            index_name = users_collection.create_index(
                [("is_active", ascending), ("locked_until", ascending)],
                background=True,
                sparse=True,  # Only index documents where locked_until exists
                name="account_status_idx",
            )
            index_names.append(index_name)

            # 8. Password age index - optimizes password expiration checks
            index_name = users_collection.create_index(
                [("last_password_change", ascending)], background=True, name="password_age_idx"
            )
            index_names.append(index_name)

            # 9. Login attempts index - optimizes account lockout
            index_name = users_collection.create_index(
                [("login_attempts", ascending)], background=True, name="login_attempts_idx"
            )
            index_names.append(index_name)

            # Now set up security_events collection and its indexes
            if "security_events" not in self.db.list_collection_names():
                self.logger.info("Creating security_events collection...")
                try:
                    # Try to create as a time series collection (MongoDB 5.0+)
                    self.db.create_collection(
                        "security_events",
                        timeseries={
                            "timeField": "timestamp",
                            "metaField": "username",
                            "granularity": "minutes"
                        }
                    )
                    self.logger.info("Created security_events as a time series collection")
                except Exception as e:
                    # Fall back to regular collection if time series not supported
                    self.logger.warning(f"Could not create time series collection: {e}")
                    self.logger.info("Creating security_events as a regular collection")
                    self.db.create_collection("security_events")

            # Get security_events collection
            security_events_collection = self.db["security_events"]

            # 10. Timestamp index for security events
            index_name = security_events_collection.create_index(
                [("timestamp", descending)],  # Descending for most recent first
                background=True,
                name="timestamp_idx",
            )
            index_names.append(index_name)

            # 11. Username index for security events
            index_name = security_events_collection.create_index(
                [("username", ascending)], background=True, name="username_events_idx"
            )
            index_names.append(index_name)

            # 12. Event type index
            index_name = security_events_collection.create_index(
                [("event_type", ascending)], background=True, name="event_type_idx"
            )
            index_names.append(index_name)

            # 13. Compound index for common security event queries
            index_name = security_events_collection.create_index(
                [("username", ascending), ("event_type", ascending), ("timestamp", descending)],
                background=True,
                name="user_event_time_idx",
            )
            index_names.append(index_name)

            # 14. IP address index for rate limiting and security tracking
            index_name = security_events_collection.create_index(
                [("ip_address", ascending)],
                background=True,
                sparse=True,  # Not all events have IP addresses
                name="ip_address_idx",
            )
            index_names.append(index_name)

            self.logger.info(f"Created {len(index_names)} MongoDB indexes: {', '.join(index_names)}")

        except Exception as e:
            self.logger.error(f"Error creating MongoDB indexes: {e}")

    def verify_indexes(self) -> Dict[str, bool]:
        """
        Verify that all required indexes exist and are correctly configured.

        Returns:
            Dictionary with index names as keys and boolean values indicating
            whether each index exists and is correctly configured.
        """
        if (
            self.db is None
        ):  # Changed from "if self.db is not None:" (looks like a bug in original code)
            self.logger.error("MongoDB not connected")
            return {}

        try:
            # Define expected indexes for each collection
            expected_indexes = {
                "users": [
                    "username_idx",
                    "email_verified_idx",
                    "reset_token_idx",
                    "reset_token_ttl_idx",
                    "account_id_idx",
                    "role_idx",
                    "account_status_idx",
                    "password_age_idx",
                    "login_attempts_idx"
                ],
                "security_events": [
                    "timestamp_idx",
                    "username_events_idx",
                    "event_type_idx",
                    "user_event_time_idx",
                    "ip_address_idx"
                ]
            }

            # Initialize result dictionary
            index_status = {}
            for indexes in expected_indexes.values():
                for idx in indexes:
                    index_status[idx] = False

            # Check indexes in each collection
            for collection_name, indexes in expected_indexes.items():
                if collection_name not in self.db.list_collection_names():
                    self.logger.warning(f"Collection '{collection_name}' does not exist")
                    continue

                # Get existing indexes in the collection
                collection = self.db[collection_name]
                existing_indexes = [idx.get('name') for idx in collection.list_indexes()]

                # Mark existing indexes as present
                for idx in indexes:
                    if idx in existing_indexes:
                        index_status[idx] = True

            # Log missing indexes
            missing_indexes = [name for name, exists in index_status.items() if not exists]
            if missing_indexes:
                self.logger.warning(f"Missing MongoDB indexes: {', '.join(missing_indexes)}")

                # Attempt to recreate missing indexes
                self.logger.info("Attempting to recreate missing indexes...")
                self._create_indexes()
            else:
                self.logger.info("All MongoDB indexes are correctly configured")

            return index_status

        except Exception as e:
            self.logger.error(f"Error verifying MongoDB indexes: {e}")
            return {}

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a user by username.

        Args:
            username: The username to look up.

        Returns:
            The user data as a dictionary, or None if not found.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return None

        try:
            users_collection = self.db["users"]
            return users_collection.find_one({"username": username})
        except Exception as e:
            self.logger.error(f"Error retrieving user '{username}': {e}")
            return None

    def create_user(self, user_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Create a new user.

        Args:
            user_data: The user data to insert.

        Returns:
            A tuple containing:
            - Boolean indicating success/failure
            - User ID or error message
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return False, "Database not connected"

        try:
            users_collection = self.db["users"]

            # Check if user already exists
            existing_user = users_collection.find_one({"username": user_data["username"]})
            if existing_user:
                return False, f"User '{user_data['username']}' already exists"

            # Insert the user
            result = users_collection.insert_one(user_data)

            if result.inserted_id:
                return True, str(result.inserted_id)
            else:
                return False, "Failed to insert user"

        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            return False, str(e)

    def update_user(self, username: str, update_data: Dict[str, Any]) -> bool:
        """
        Update a user's data.

        Args:
            username: The username of the user to update.
            update_data: The data to update.

        Returns:
            True if successful, False otherwise.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return False

        try:
            users_collection = self.db["users"]
            result = users_collection.update_one(
                {"username": username},
                {"$set": update_data}
            )

            return result.modified_count > 0

        except Exception as e:
            self.logger.error(f"Error updating user '{username}': {e}")
            return False

    def list_users(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_by: str = "username",
        sort_direction: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        List users with optional filtering, pagination, and sorting.

        Args:
            filter_criteria: Optional dictionary of filter criteria
            limit: Maximum number of users to return (default: 100)
            skip: Number of users to skip (for pagination)
            sort_by: Field to sort by (default: username)
            sort_direction: Sort direction (1 for ascending, -1 for descending)

        Returns:
            List of user data dictionaries
        """
        if self.db is None:
            self.logger.error("MongoDB not connected")
            return []

        try:
            users_collection = self.db["users"]

            # Use the filter criteria if provided, otherwise use an empty filter
            query = filter_criteria or {}

            # Create cursor with sorting and pagination
            cursor = users_collection.find(query)

            # Apply sorting if a valid sort field is provided
            if sort_by:
                cursor = cursor.sort(sort_by, sort_direction)

            # Apply pagination
            cursor = cursor.skip(skip).limit(limit)

            # Get timing information for performance monitoring
            start_time = time.time()
            results = list(cursor)
            query_time = time.time() - start_time

            # Log query performance for large result sets
            if len(results) > 50 or query_time > 0.5:
                self.logger.info(f"Listed {len(results)} users in {query_time:.4f}s")

            return results

        except Exception as e:
            self.logger.error(f"Error listing users: {e}")
            return []

    def delete_user(self, username: str) -> bool:
        """
        Delete a user.

        Args:
            username: The username of the user to delete.

        Returns:
            True if successful, False otherwise.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return False

        try:
            users_collection = self.db["users"]
            result = users_collection.delete_one({"username": username})

            return result.deleted_count > 0

        except Exception as e:
            self.logger.error(f"Error deleting user '{username}': {e}")
            return False

    def increment_login_attempts(self, username: str) -> int:
        """
        Increment the login attempts counter for a user.

        Args:
            username: The username of the user.

        Returns:
            The new number of login attempts.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return 0

        try:
            users_collection = self.db["users"]
            result = users_collection.update_one(
                {"username": username},
                {"$inc": {"login_attempts": 1}}
            )

            if result.modified_count > 0:
                # Get the updated user to return the new count
                user = users_collection.find_one({"username": username})
                return user.get("login_attempts", 0) if user else 0
            else:
                return 0

        except Exception as e:
            self.logger.error(f"Error incrementing login attempts for user '{username}': {e}")
            return 0

    def reset_login_attempts(self, username: str) -> bool:
        """
        Reset the login attempts counter for a user.

        Args:
            username: The username of the user.

        Returns:
            True if successful, False otherwise.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return False

        try:
            users_collection = self.db["users"]
            result = users_collection.update_one(
                {"username": username},
                {"$set": {"login_attempts": 0}}
            )

            return result.modified_count > 0

        except Exception as e:
            self.logger.error(f"Error resetting login attempts for user '{username}': {e}")
            return False

    def get_user_by_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get a user by reset token using optimized query with indexes.

        Args:
            token: The reset token.

        Returns:
            The user data if found, None otherwise.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return None

        try:
            users_collection = self.db["users"]

            # This query uses the reset_token_idx index for efficient lookup
            # The {$exists: true, $ne: null} conditions ensure we only match documents with valid tokens
            # The $gt comparison on reset_token_expires uses the TTL index
            query = {
                "reset_token": token,
                "reset_token_expires": {
                    "$exists": True,
                    "$ne": None,
                    "$gt": datetime.utcnow()
                }
            }

            # Execute query with explain plan to verify index usage
            explain_plan = users_collection.find(query).explain()
            winning_plan = explain_plan.get("queryPlanner", {}).get("winningPlan", {})
            index_name = winning_plan.get("inputStage", {}).get("indexName", "none")

            # Log index usage
            self.logger.debug(f"Query for reset token used index: {index_name}")

            # Execute the actual query
            user = users_collection.find_one(query)

            return user

        except Exception as e:
            self.logger.error(f"Error retrieving user by reset token: {e}")
            return None

    def log_security_event(self, event_data: Dict[str, Any]) -> bool:
        """
        Log a security event.

        Args:
            event_data: The event data to log.

        Returns:
            True if successful, False otherwise.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return False

        try:
            # Ensure timestamp is set
            if "timestamp" not in event_data:
                event_data["timestamp"] = datetime.utcnow()

            security_events_collection = self.db["security_events"]
            result = security_events_collection.insert_one(event_data)

            return result.inserted_id is not None

        except Exception as e:
            self.logger.error(f"Error logging security event: {e}")
            return False

    def get_security_events(self,
                        filters: Optional[Dict[str, Any]] = None,
                        limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get security events using optimized query with indexes.

        Args:
            filters: Optional filters to apply.
            limit: Maximum number of events to return.

        Returns:
            A list of security events.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return []

        try:
            security_events_collection = self.db["security_events"]
            query = filters or {}

            # Determine which index to use based on the query filters
            # This ensures we use the most efficient index for each query
            index_hint = None

            # If username and event_type are provided, use the compound index
            if "username" in query and "event_type" in query:
                index_hint = "user_event_time_idx"
                self.logger.debug("Using compound index for security events query")

            # If only username is provided, use the username index
            elif "username" in query:
                index_hint = "username_events_idx"
                self.logger.debug("Using username index for security events query")

            # If only event_type is provided, use the event_type index
            elif "event_type" in query:
                index_hint = "event_type_idx"
                self.logger.debug("Using event_type index for security events query")

            # If IP address is in the query, use the IP address index
            elif "ip_address" in query:
                index_hint = "ip_address_idx"
                self.logger.debug("Using IP address index for security events query")

            # For date range queries, use the timestamp index
            elif any(key.startswith("timestamp") for key in query):
                index_hint = "timestamp_idx"
                self.logger.debug("Using timestamp index for security events query")

            # Create a cursor with proper sort and limit
            cursor = security_events_collection.find(query).sort("timestamp", -1).limit(limit)

            # Add index hint if determined
            if index_hint:
                cursor = cursor.hint(index_hint)

            # Performance monitoring for the query
            start_time = time.time()
            results = list(cursor)
            query_time = time.time() - start_time

            # Log query performance
            self.logger.debug(f"Security events query returned {len(results)} results in {query_time:.4f}s")

            # If query is slow, log a warning
            if query_time > 0.5:  # More than 500ms is considered slow
                self.logger.warning(f"Slow security events query: {query_time:.4f}s for filters: {filters}")

                # Log explain plan for slow queries
                explain_plan = security_events_collection.find(query).explain()
                self.logger.debug(f"Explain plan for slow query: {explain_plan}")

            return results

        except Exception as e:
            self.logger.error(f"Error retrieving security events: {e}")
            return []

    def check_connection_health(self) -> bool:
        """
        Check the health of the MongoDB connection pool.

        Returns:
            True if the connection is healthy, False otherwise.
        """
        if not self.client:
            return False

        try:
            # Check if the connection is still valid
            self.client.admin.command('ping')

            # Get connection pool stats
            stats = self.client.get_default_database_connection_pool_stats()

            # Log pool stats
            self.logger.debug(f"MongoDB connection pool stats: {stats}")

            return True

        except Exception as e:
            self.logger.error(f"MongoDB connection health check failed: {e}")
            return False


class SQLAlchemyAdapter(DatabaseAdapter):
    """
    SQLAlchemy adapter for the Duo Flask Auth library.

    This adapter uses SQLAlchemy to interact with SQL databases.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the SQLAlchemy adapter.

        Args:
            config: SQLAlchemy configuration dictionary.
                Required keys: url
                Optional keys: echo, pool_size
        """
        self.config = config
        self.engine = None
        self.session_factory = None
        self.Base = None
        self.User = None
        self.SecurityEvent = None
        self.logger = logging.getLogger("duo_flask_auth.db_adapters.SQLAlchemyAdapter")

        # Import SQLAlchemy here to avoid requiring it for users who don't use this adapter
        try:
            import sqlalchemy
            from sqlalchemy import (
                Boolean,
                Column,
                DateTime,
                ForeignKey,
                Integer,
                String,
                Text,
                create_engine,
            )
            from sqlalchemy.ext.declarative import declarative_base
            from sqlalchemy.orm import relationship, sessionmaker

            self.sqlalchemy = sqlalchemy
            self.create_engine = create_engine
            self.Column = Column
            self.Integer = Integer
            self.String = String
            self.Boolean = Boolean
            self.DateTime = DateTime
            self.Text = Text
            self.ForeignKey = ForeignKey
            self.declarative_base = declarative_base
            self.sessionmaker = sessionmaker
            self.relationship = relationship

        except ImportError:
            self.logger.error("SQLAlchemy is not installed. Please install it with: pip install sqlalchemy")

    def initialize(self, app=None) -> None:
        """
        Initialize the SQLAlchemy engine and create tables.

        Args:
            app: The Flask application, if available.
        """
        if app:
            app.logger.info("Initializing SQLAlchemy adapter")

        if not hasattr(self, 'sqlalchemy'):
            self.logger.error("SQLAlchemy is not installed.")
            return

        # Extract configuration
        url = self.config.get('url')
        if not url:
            self.logger.error("SQLAlchemy URL is required")
            return

        # Create engine
        self.engine = self.create_engine(
            url,
            echo=self.config.get('echo', False),
            pool_size=self.config.get('pool_size', 10)
        )

        # Create base class
        self.Base = self.declarative_base()

        # Define models
        self._define_models()

        # Create session factory
        self.session_factory = self.sessionmaker(bind=self.engine)

        # Create tables
        self.Base.metadata.create_all(self.engine)

        self.logger.info("SQLAlchemy adapter initialized")

    def _define_models(self) -> None:
        """
        Define SQLAlchemy models.
        """
        # Define User model
        class User(self.Base):
            __tablename__ = 'users'

            id = self.Column(self.Integer, primary_key=True)
            username = self.Column(self.String(100), unique=True, nullable=False)
            password_hash = self.Column(self.String(255), nullable=False)
            created_by = self.Column(self.String(100))
            created_at = self.Column(self.DateTime, default=datetime.utcnow)
            is_active = self.Column(self.Boolean, default=True)
            role = self.Column(self.String(50), default='user')
            last_password_change = self.Column(self.DateTime, default=datetime.utcnow)
            account_id = self.Column(self.String(100), unique=True)
            login_attempts = self.Column(self.Integer, default=0)
            creation_ip = self.Column(self.String(50))
            mfa_enabled = self.Column(self.Boolean, default=False)
            last_login = self.Column(self.DateTime)
            email_verified = self.Column(self.Boolean, default=False)
            reset_token = self.Column(self.String(100), unique=True)
            reset_token_expires = self.Column(self.DateTime)
            locked_until = self.Column(self.DateTime)

            def to_dict(self):
                """Convert model to dictionary."""
                return {
                    'id': self.id,
                    'username': self.username,
                    'password_hash': self.password_hash,
                    'created_by': self.created_by,
                    'created_at': self.created_at,
                    'is_active': self.is_active,
                    'role': self.role,
                    'last_password_change': self.last_password_change,
                    'account_id': self.account_id,
                    'login_attempts': self.login_attempts,
                    'creation_ip': self.creation_ip,
                    'mfa_enabled': self.mfa_enabled,
                    'last_login': self.last_login,
                    'email_verified': self.email_verified,
                    'reset_token': self.reset_token,
                    'reset_token_expires': self.reset_token_expires,
                    'locked_until': self.locked_until
                }

        # Define SecurityEvent model
        class SecurityEvent(self.Base):
            __tablename__ = 'security_events'

            id = self.Column(self.Integer, primary_key=True)
            timestamp = self.Column(self.DateTime, default=datetime.utcnow)
            event_type = self.Column(self.String(50), nullable=False)
            username = self.Column(self.String(100))
            ip_address = self.Column(self.String(50))
            user_agent = self.Column(self.String(255))
            details = self.Column(self.Text)

            def to_dict(self):
                """Convert model to dictionary."""
                import json
                return {
                    'id': self.id,
                    'timestamp': self.timestamp,
                    'event_type': self.event_type,
                    'username': self.username,
                    'ip_address': self.ip_address,
                    'user_agent': self.user_agent,
                    'details': json.loads(self.details) if self.details else {}
                }

        # Store models
        self.User = User
        self.SecurityEvent = SecurityEvent

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a user by username.

        Args:
            username: The username to look up.

        Returns:
            The user data as a dictionary, or None if not found.
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return None

        try:
            session = self.session_factory()
            user = session.query(self.User).filter_by(username=username).first()
            session.close()

            return user.to_dict() if user else None

        except Exception as e:
            self.logger.error(f"Error retrieving user '{username}': {e}")
            return None

    def create_user(self, user_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Create a new user.

        Args:
            user_data: The user data to insert.

        Returns:
            A tuple containing:
            - Boolean indicating success/failure
            - User ID or error message
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return False, "Database not initialized"

        try:
            session = self.session_factory()

            # Check if user already exists
            existing_user = session.query(self.User).filter_by(username=user_data["username"]).first()
            if existing_user:
                session.close()
                return False, f"User '{user_data['username']}' already exists"

            # Create new user object
            user = self.User(**user_data)

            # Add to session and commit
            session.add(user)
            session.commit()

            # Get ID
            user_id = user.id

            session.close()

            return True, str(user_id)

        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            if session:
                session.rollback()
                session.close()
            return False, str(e)

    def update_user(self, username: str, update_data: Dict[str, Any]) -> bool:
        """
        Update a user's data.

        Args:
            username: The username of the user to update.
            update_data: The data to update.

        Returns:
            True if successful, False otherwise.
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return False

        try:
            session = self.session_factory()

            # Find the user
            user = session.query(self.User).filter_by(username=username).first()
            if not user:
                session.close()
                return False

            # Update the fields
            for key, value in update_data.items():
                if hasattr(user, key):
                    setattr(user, key, value)

            # Commit changes
            session.commit()
            session.close()

            return True

        except Exception as e:
            self.logger.error(f"Error updating user '{username}': {e}")
            if session:
                session.rollback()
                session.close()
            return False

    def list_users(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        skip: int = 0,
        sort_by: str = "username",
        sort_direction: int = 1,
    ) -> List[Dict[str, Any]]:
        """
        List users with optional filtering, pagination, and sorting.

        Args:
            filter_criteria: Optional dictionary of filter criteria
            limit: Maximum number of users to return (default: 100)
            skip: Number of users to skip (for pagination)
            sort_by: Field to sort by (default: username)
            sort_direction: Sort direction (1 for ascending, -1 for descending)

        Returns:
            List of user data dictionaries
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return []

        try:
            session = self.session_factory()

            # Start query
            query = session.query(self.User)

            # Apply filters if provided
            if filter_criteria:
                for key, value in filter_criteria.items():
                    if hasattr(self.User, key):
                        query = query.filter(getattr(self.User, key) == value)

            # Apply sorting
            if hasattr(self.User, sort_by):
                order_attr = getattr(self.User, sort_by)
                if sort_direction < 0:
                    order_attr = order_attr.desc()
                query = query.order_by(order_attr)

            # Apply pagination
            query = query.offset(skip).limit(limit)

            # Execute query and convert to dictionaries
            users = [user.to_dict() for user in query.all()]

            session.close()
            return users

        except Exception as e:
            self.logger.error(f"Error listing users: {e}")
            if session:
                session.close()
            return []

    def delete_user(self, username: str) -> bool:
        """
        Delete a user.

        Args:
            username: The username of the user to delete.

        Returns:
            True if successful, False otherwise.
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return False

        try:
            session = self.session_factory()

            # Find the user
            user = session.query(self.User).filter_by(username=username).first()
            if not user:
                session.close()
                return False

            # Delete the user
            session.delete(user)
            session.commit()
            session.close()

            return True

        except Exception as e:
            self.logger.error(f"Error deleting user '{username}': {e}")
            if session:
                session.rollback()
                session.close()
            return False

    def increment_login_attempts(self, username: str) -> int:
        """
        Increment the login attempts counter for a user with index optimization.

        Args:
            username: The username of the user.

        Returns:
            The new number of login attempts.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return 0

        try:
            users_collection = self.db["users"]

            # Use findAndModify (findOneAndUpdate) to atomically update and return the value
            # This is more efficient than doing separate update and find operations
            result = users_collection.find_one_and_update(
                {"username": username},  # Uses the username_idx index
                {"$inc": {"login_attempts": 1}},  # Increment login_attempts by 1
                projection={"login_attempts": 1},  # Only return the login_attempts field
                return_document=pymongo.ReturnDocument.AFTER  # Return the document after update
            )

            # Return the new login attempts count, or 0 if the update failed
            return result.get("login_attempts", 0) if result else 0

        except Exception as e:
            self.logger.error(f"Error incrementing login attempts for user '{username}': {e}")
            return 0

    def reset_login_attempts(self, username: str) -> bool:
        """
        Reset the login attempts counter for a user with index optimization.

        Args:
            username: The username of the user.

        Returns:
            True if successful, False otherwise.
        """
        if not self.db:
            self.logger.error("MongoDB not connected")
            return False

        try:
            users_collection = self.db["users"]

            # Update the login_attempts field to 0 and clear locked_until
            # This uses the username_idx index for efficient lookup
            result = users_collection.update_one(
                {"username": username},
                {
                    "$set": {
                        "login_attempts": 0,
                        "locked_until": None
                    }
                }
            )

            # Check if the update was successful
            success = result.modified_count > 0
            if success:
                self.logger.debug(f"Reset login attempts for user '{username}'")
            else:
                self.logger.warning(f"Failed to reset login attempts for user '{username}' - user not found")

            return success

        except Exception as e:
            self.logger.error(f"Error resetting login attempts for user '{username}': {e}")
            return False

    def get_user_by_reset_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get a user by reset token.

        Args:
            token: The reset token.

        Returns:
            The user data if found, None otherwise.
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return None

        try:
            session = self.session_factory()

            # Find the user by token
            user = session.query(self.User).filter(
                self.User.reset_token == token,
                self.User.reset_token_expires > datetime.utcnow()
            ).first()

            session.close()

            return user.to_dict() if user else None

        except Exception as e:
            self.logger.error(f"Error retrieving user by reset token: {e}")
            if session:
                session.close()
            return None

    def log_security_event(self, event_data: Dict[str, Any]) -> bool:
        """
        Log a security event.

        Args:
            event_data: The event data to log.

        Returns:
            True if successful, False otherwise.
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return False

        try:
            session = self.session_factory()

            # Ensure timestamp is set
            if "timestamp" not in event_data:
                event_data["timestamp"] = datetime.utcnow()

            # Convert details to JSON string if present
            if "details" in event_data and isinstance(event_data["details"], dict):
                import json
                event_data["details"] = json.dumps(event_data["details"])

            # Create new event object
            event = self.SecurityEvent(**event_data)

            # Add to session and commit
            session.add(event)
            session.commit()
            session.close()

            return True

        except Exception as e:
            self.logger.error(f"Error logging security event: {e}")
            if session:
                session.rollback()
                session.close()
            return False

    def get_security_events(self,
                          filters: Optional[Dict[str, Any]] = None,
                          limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get security events.

        Args:
            filters: Optional filters to apply.
            limit: Maximum number of events to return.

        Returns:
            A list of security events.
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return []

        try:
            session = self.session_factory()

            # Start query
            query = session.query(self.SecurityEvent)

            # Apply filters
            if filters:
                for key, value in filters.items():
                    if hasattr(self.SecurityEvent, key):
                        query = query.filter(getattr(self.SecurityEvent, key) == value)

            # Order by timestamp and limit
            query = query.order_by(self.SecurityEvent.timestamp.desc()).limit(limit)

            # Execute query and convert to list of dictionaries
            events = [event.to_dict() for event in query.all()]

            session.close()

            return events

        except Exception as e:
            self.logger.error(f"Error retrieving security events: {e}")
            if session:
                session.close()
            return []


# Factory function to create the appropriate database adapter
def get_db_adapter(adapter_type: str, config: Dict[str, Any]) -> DatabaseAdapter:
    """
    Factory function to create a database adapter.

    Args:
        adapter_type: Type of adapter ('mongodb', 'sqlalchemy', etc.)
        config: Adapter configuration

    Returns:
        A database adapter instance

    Raises:
        ValueError: If the adapter type is not supported
    """
    if adapter_type.lower() == 'mongodb':
        return MongoDBAdapter(config)
    elif adapter_type.lower() == 'sqlalchemy':
        return SQLAlchemyAdapter(config)
    else:
        raise ValueError(f"Unsupported database adapter type: {adapter_type}")
