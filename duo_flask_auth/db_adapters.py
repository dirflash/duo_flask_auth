"""
Database adapters for the Duo Flask Auth library.

This module provides database adapter interfaces and implementations for different database backends.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

import certifi
from pymongo import MongoClient, ASCENDING


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
        Initialize the MongoDB adapter.

        Args:
            config: MongoDB configuration dictionary.
                Required keys: username, password, host, database
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
        if self.db:
            self._create_indexes()

    def _connect(self) -> None:
        """
        Connect to MongoDB.
        """
        try:
            # Extract configuration
            db_un = self.config.get('username')
            db_pw = self.config.get('password')
            mongo_host = self.config.get('host')
            db_name = self.config.get('database')

            # Check if all required parameters are provided
            if not all([db_un, db_pw, mongo_host, db_name]):
                self.logger.error("MongoDB configuration is incomplete")
                return

            # Build connection URL
            mongo_url = f"mongodb+srv://{db_un}:{db_pw}@{mongo_host}/{db_name}"

            # Connect to MongoDB
            self.client = MongoClient(
                mongo_url + "?retryWrites=true&w=majority",
                tlsCAFile=certifi.where(),
                maxPoolSize=50,  # Connection pooling
                serverSelectionTimeoutMS=5000,
            )

            # Get the database
            self.db = self.client[db_name]

            self.logger.info(f"Connected to MongoDB: {db_name}")

        except Exception as e:
            self.logger.error(f"Error connecting to MongoDB: {e}")
            self.client = None
            self.db = None

    def _create_indexes(self) -> None:
        """
        Create indexes for MongoDB collections.
        """
        try:
            # Get the users collection
            users_collection = self.db["users"]

            # Create indexes for users collection
            users_collection.create_index([("username", ASCENDING)], unique=True)
            users_collection.create_index([("email_verified", ASCENDING)])
            users_collection.create_index([("reset_token", ASCENDING)])
            users_collection.create_index([("account_id", ASCENDING)])
            users_collection.create_index([("role", ASCENDING)])

            # Get or create the security_events collection
            if "security_events" not in self.db.list_collection_names():
                self.db.create_collection("security_events")

            # Create indexes for security_events collection
            security_events_collection = self.db["security_events"]
            security_events_collection.create_index([("timestamp", ASCENDING)])
            security_events_collection.create_index([("username", ASCENDING)])
            security_events_collection.create_index([("event_type", ASCENDING)])

            self.logger.info("MongoDB indexes created successfully")

        except Exception as e:
            self.logger.error(f"Error creating MongoDB indexes: {e}")

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
        Get a user by reset token.

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
            return users_collection.find_one({
                "reset_token": token,
                "reset_token_expires": {"$gt": datetime.utcnow()}
            })

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
        Get security events.

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

            # Execute the query
            cursor = security_events_collection.find(query).sort(
                "timestamp", -1  # Sort by timestamp descending
            ).limit(limit)

            # Convert cursor to list
            return list(cursor)

        except Exception as e:
            self.logger.error(f"Error retrieving security events: {e}")
            return []


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
            from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
            from sqlalchemy.ext.declarative import declarative_base
            from sqlalchemy.orm import sessionmaker, relationship

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
        Increment the login attempts counter for a user.

        Args:
            username: The username of the user.

        Returns:
            The new number of login attempts.
        """
        if not self.session_factory:
            self.logger.error("SQLAlchemy not initialized")
            return 0

        try:
            session = self.session_factory()

            # Find the user
            user = session.query(self.User).filter_by(username=username).first()
            if not user:
                session.close()
                return 0

            # Increment login attempts
            user.login_attempts += 1
            new_attempts = user.login_attempts

            # Commit changes
            session.commit()
            session.close()

            return new_attempts

        except Exception as e:
            self.logger.error(f"Error incrementing login attempts for user '{username}': {e}")
            if session:
                session.rollback()
                session.close()
            return 0

    def reset_login_attempts(self, username: str) -> bool:
        """
        Reset the login attempts counter for a user.

        Args:
            username: The username of the user.

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

            # Reset login attempts
            user.login_attempts = 0

            # Commit changes
            session.commit()
            session.close()

            return True

        except Exception as e:
            self.logger.error(f"Error resetting login attempts for user '{username}': {e}")
            if session:
                session.rollback()
                session.close()
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