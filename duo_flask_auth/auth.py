"""
Main class for the Duo Flask Auth library with flexibility enhancements.

This module provides the DuoFlaskAuth class, which handles authentication,
Duo MFA integration, and security features with support for different
database backends and customizable routes.
"""
# pylint: disable=logging-fstring-interpolation

import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, Union

# Import Duo Universal SDK
from duo_universal.client import Client, DuoException
from flask import (
    Blueprint,
    Flask,
    current_app,
    jsonify,
    request,
)
from flask_login import (
    LoginManager,
)
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Define version directly to avoid import issues
__version__ = "0.4.0"

# Handle other imports gracefully for direct file execution vs package import
try:
    # For when file is imported as part of the package
    from .db_adapters import DatabaseAdapter, get_db_adapter
    from .exceptions import (
        AccountLockedError,
        AuthError,
        InvalidCredentialsError,
        MFARequiredError,
        PasswordExpiredError,
        PasswordPolicyError,
        PermissionDeniedError,
        RateLimitedError,
        TokenInvalidError,
    )
    from .user_model import BaseUser, get_user_factory
except ImportError:
    # For when file is run directly
    import os
    import sys

    # Add parent directory to path to make absolute imports work
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

    try:
        from duo_flask_auth.db_adapters import DatabaseAdapter, get_db_adapter
        from duo_flask_auth.exceptions import (
            AccountLockedError,
            AuthError,
            InvalidCredentialsError,
            MFARequiredError,
            PasswordExpiredError,
            PasswordPolicyError,
            PermissionDeniedError,
            RateLimitedError,
            TokenInvalidError,
        )
        from duo_flask_auth.user_model import BaseUser, get_user_factory

        # Try to get version from module
        try:
            from duo_flask_auth import __version__
        except ImportError:
            # Define a fallback version if not available
            __version__ = "0.4.0"
    except ImportError:
        # If all else fails, define placeholder classes for documentation/IDE purposes
        print(
            "WARNING: Running in standalone mode with mock classes. This is not recommended for production use."
        )

        class DatabaseAdapter:
            """Mock DatabaseAdapter for documentation purposes"""

            pass

        def get_db_adapter(*args, **kwargs):
            """Mock get_db_adapter function"""
            return None

        class BaseUser:
            """Mock BaseUser for documentation purposes"""

            pass

        def get_user_factory(*args, **kwargs):
            """Mock get_user_factory function"""
            return None

        class AuthError(Exception):
            """Base exception for authentication errors."""

            def __init__(self, message: str, code: Optional[str] = None):
                self.message = message
                self.code = code
                super().__init__(self.message)

        class InvalidCredentialsError(AuthError):
            pass

        class AccountLockedError(AuthError):
            pass

        class MFARequiredError(AuthError):
            pass

        class RateLimitedError(AuthError):
            pass

        class PasswordPolicyError(AuthError):
            pass

        class TokenInvalidError(AuthError):
            pass

        class PermissionDeniedError(AuthError):
            pass

        class PasswordExpiredError(AuthError):
            pass

        # Define a fallback version
        __version__ = "0.4.0"


class DuoFlaskAuth:
    """
    Flask authentication library with Duo MFA support and enhanced flexibility.

    This class provides authentication functionality with optional Duo MFA integration
    for Flask applications, with support for different database backends,
    customizable routes, and user models.

    Security features include:
    - Multi-factor authentication via Duo
    - Rate limiting
    - Account lockout
    - Password policies
    - Security event logging
    - CSRF protection

    Performance features include:
    - Configurable caching
    - Connection pooling (through database adapters)
    - Optimized database queries

    Args:
        app: The Flask application to initialize with.
        db_config: Database connection configuration.
        db_adapter: Database adapter type ('mongodb', 'sqlalchemy') or instance.
        duo_config: Duo MFA configuration.
        template_folder: Folder for auth templates.
        routes_prefix: Prefix for authentication routes.
        user_model: User model type.
        rate_limit_config: Configuration for rate limiting.
        account_lockout_config: Configuration for account lockout.
        password_policy: Configuration for password policies.
        cache_config: Configuration for caching.
    """

    def __init__(
        self,
        app: Optional[Flask] = None,
        db_config: Optional[Dict[str, Any]] = None,
        db_adapter: Optional[Union[str, DatabaseAdapter]] = None,
        duo_config: Optional[Dict[str, Any]] = None,
        template_folder: str = "templates",
        routes_prefix: str = "/auth",
        user_model: str = "default",
        rate_limit_config: Optional[Dict[str, Any]] = None,
        account_lockout_config: Optional[Dict[str, Any]] = None,
        password_policy: Optional[Dict[str, Any]] = None,
        cache_config: Optional[Dict[str, Any]] = None,
        health_check_config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize the DuoFlaskAuth extension.

        Args:
            app: The Flask application to initialize with.
            db_config: Database connection configuration.
            db_adapter: Database adapter type ('mongodb', 'sqlalchemy') or instance.
            duo_config: Duo MFA configuration.
            template_folder: Folder for auth templates.
            routes_prefix: Prefix for authentication routes.
            user_model: User model type.
            rate_limit_config: Configuration for rate limiting.
            account_lockout_config: Configuration for account lockout.
            password_policy: Configuration for password policies.
            cache_config: Configuration for caching.
            health_check_config: Configuration for health check endpoint.
        """
        # Configure logger first to avoid "access before definition" errors
        self.logger = logging.getLogger("duo_flask_auth")
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self.login_manager = LoginManager()
        self.db_config = db_config or {}
        self.duo_config = duo_config or {}
        self.template_folder = template_folder
        self.routes_prefix = routes_prefix
        self.user_model = user_model
        self.duo_client = None
        self.csrf = CSRFProtect()
        self.health_check_config = health_check_config or {
            "enabled": True,
            "require_service_account": False,
            "service_account_token": "",
        }

        # Configure caching
        self.cache_config = cache_config or {
            "enabled": True,
            "type": "memory",
            "default_ttl": 300,  # 5 minutes default TTL
            "user_ttl": 60,  # 1 minute for user data
            "security_events_ttl": 300,  # 5 minutes for security events
            "cleanup_interval": 60,  # Clean up expired entries every minute
        }

        # Create cache instance based on configuration
        if self.cache_config.get("enabled", True):
            try:
                # First try to import from the package
                try:
                    from .cache import MemoryCache, NoCache
                except ImportError:
                    # Fall back to absolute import
                    try:
                        from duo_flask_auth.cache import MemoryCache, NoCache
                    except ImportError:
                        # Create minimal cache implementations if module not available
                        class CacheStats:
                            def __init__(self):
                                self.hits = 0
                                self.misses = 0
                                self.sets = 0
                                self.deletes = 0
                                self.clears = 0
                                self.hit_rate = 0

                        class NoCache:
                            def __init__(self):
                                self.stats = CacheStats()

                            def get(self, key):
                                return None

                            def set(self, key, value, ttl=None):
                                pass

                            def delete(self, key):
                                pass

                            def clear(self):
                                pass

                            def get_keys(self):
                                return []

                            def get_stats(self):
                                return self.stats

                        class MemoryCache(NoCache):
                            def __init__(self, default_ttl=300, cleanup_interval=60):
                                super().__init__()
                                self.default_ttl = default_ttl
                                self._store = {}

                            def get(self, key):
                                if key in self._store:
                                    self.stats.hits += 1
                                    return self._store[key]
                                self.stats.misses += 1
                                return None

                            def set(self, key, value, ttl=None):
                                self._store[key] = value
                                self.stats.sets += 1

                            def delete(self, key):
                                if key in self._store:
                                    del self._store[key]
                                    self.stats.deletes += 1

                            def clear(self):
                                self._store.clear()
                                self.stats.clears += 1

                            def get_keys(self):
                                return list(self._store.keys())

                if self.cache_config.get("type", "memory") == "memory":
                    self.cache = MemoryCache(
                        default_ttl=self.cache_config.get("default_ttl", 300),
                        cleanup_interval=self.cache_config.get("cleanup_interval", 60),
                    )
                    self.logger.info("Initialized memory cache")
                else:
                    # Default to memory cache if type is not recognized
                    self.cache = MemoryCache(default_ttl=self.cache_config.get("default_ttl", 300))
                    self.logger.info(
                        f"Unrecognized cache type '{self.cache_config.get('type')}', falling back to memory cache"
                    )
            except Exception as e:
                self.logger.error(f"Error initializing cache: {e}. Using NoCache fallback.")
                # Create a simple NoCache implementation if other attempts fail
                self.cache = NoCache()
        else:
            # Use dummy cache if caching is disabled
            try:
                # First try relative import
                try:
                    from .cache import NoCache
                except ImportError:
                    # Then try absolute import
                    try:
                        from duo_flask_auth.cache import NoCache
                    except ImportError:
                        # Create minimal implementation if not available
                        class CacheStats:
                            def __init__(self):
                                self.hits = 0
                                self.misses = 0
                                self.sets = 0
                                self.deletes = 0
                                self.clears = 0
                                self.hit_rate = 0

                        class NoCache:
                            def __init__(self):
                                self.stats = CacheStats()

                            def get(self, key):
                                return None

                            def set(self, key, value, ttl=None):
                                pass

                            def delete(self, key):
                                pass

                            def clear(self):
                                pass

                            def get_keys(self):
                                return []

                            def get_stats(self):
                                return self.stats

                self.cache = NoCache()
                self.logger.info("Caching is disabled")
            except Exception as e:
                self.logger.error(f"Error initializing NoCache: {e}")

                # Create a minimal implementation
                class DummyCache:
                    def get(self, key):
                        return None

                    def set(self, key, value, ttl=None):
                        pass

                    def delete(self, key):
                        pass

                    def clear(self):
                        pass

                    def get_keys(self):
                        return []

                    def get_stats(self):
                        return {"hits": 0, "misses": 0}

                self.cache = DummyCache()
                self.logger.info("Using minimal dummy cache implementation")

        # Initialize database adapter
        if isinstance(db_adapter, DatabaseAdapter):
            self.db_adapter = db_adapter
        elif isinstance(db_adapter, str):
            self.db_adapter = get_db_adapter(db_adapter, self.db_config)
        elif db_config:
            # Default to MongoDB if not specified but config is provided
            self.db_adapter = get_db_adapter("mongodb", self.db_config)
        else:
            self.db_adapter = None

        # Get user factory
        self.user_factory = get_user_factory(user_model)

        # Create blueprint with specified route prefix
        self.blueprint = Blueprint(
            "duo_flask_auth", __name__, url_prefix=routes_prefix, template_folder=template_folder
        )

        # Rate limiting configuration
        self.rate_limit_config = rate_limit_config or {
            "enabled": True,
            "type": "memory",  # 'memory' or 'redis'
            "redis_url": None,  # Optional Redis URL for distributed rate limiting
            "max_attempts": {"login": 5, "password_reset": 3},  # 5 attempts  # 3 attempts
            "window_seconds": {"login": 300, "password_reset": 600},  # 5 minutes  # 10 minutes
        }

        # Account lockout configuration
        self.account_lockout_config = account_lockout_config or {
            "enabled": True,
            "max_attempts": 5,  # Lock after 5 failed attempts
            "lockout_duration": 1800,  # 30 minutes
            "lockout_reset_on_success": True,
        }

        # Password policy configuration
        self.password_policy = password_policy or {
            "min_length": 8,
            "require_upper": True,
            "require_lower": True,
            "require_digit": True,
            "require_special": False,
            "max_age_days": 90,  # Maximum password age
            "prevent_common": True,  # Prevent common passwords
            "common_passwords": ["Password123", "Admin123", "Welcome123"],  # Example list
        }

        # Initialize rate limiter
        self._init_rate_limiter()

        # Configure logger
        self.logger = logging.getLogger("duo_flask_auth")
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        self._setup_routes()

        if app is not None:
            self.init_app(app)

    def _init_rate_limiter(self):
        """Initialize the appropriate rate limiter based on configuration."""
        rate_limit_type = self.rate_limit_config.get("type", "memory")

        if rate_limit_type == "redis" and self.rate_limit_config.get("redis_url"):
            try:
                import redis

                self.redis_client = redis.from_url(self.rate_limit_config.get("redis_url"))
                self.logger.info("Using Redis-based rate limiting")
                self._rate_limit_store = None  # We'll use Redis instead
                self._use_redis_rate_limiting = True
            except (ImportError, Exception) as e:
                self.logger.warning(
                    f"Failed to initialize Redis rate limiting: {e}. Falling back to memory-based."
                )
                self._rate_limit_store = {}
                self._use_redis_rate_limiting = False
        else:
            self.logger.info("Using memory-based rate limiting")
            self._rate_limit_store = {}
            self._use_redis_rate_limiting = False

    def init_app(self, app: Flask) -> None:
        """
        Initialize the extension with the given Flask application.

        Args:
            app: The Flask application to initialize with.

        Raises:
            ValueError: If required configuration is missing.
        """
        # Validate configuration
        if self.db_adapter is None and not self.db_config:
            self.logger.warning(
                "No database configuration provided - some features will be unavailable"
            )

        # Validate Duo configuration if provided
        if self.duo_config:
            if not self._validate_duo_config():
                self.logger.warning("Duo MFA configuration is incomplete or invalid")

        if not hasattr(app, "extensions"):
            app.extensions = {}
        app.extensions["duo_flask_auth"] = self

        # Set up CSRF protection
        self.csrf.init_app(app)

        # Set up the login manager
        self.login_manager.init_app(app)
        self.login_manager.login_view = "duo_flask_auth.login"
        self.login_manager.login_message = "Please log in to access this page."
        self.login_manager.login_message_category = "info"

        # Set up the database adapter if provided
        if self.db_adapter:
            self.db_adapter.initialize(app)

            # Verify database indexes after initialization
            # This ensures all necessary indexes exist
            if hasattr(self.db_adapter, "verify_indexes"):

                def verify_database_indexes():
                    try:
                        app.logger.info("Verifying database indexes...")
                        index_status = self.db_adapter.verify_indexes()

                        # Log any missing indexes
                        missing_indexes = [
                            name for name, exists in index_status.items() if not exists
                        ]
                        if missing_indexes:
                            app.logger.warning(
                                f"Missing database indexes: {', '.join(missing_indexes)}"
                            )
                        else:
                            app.logger.info("All database indexes are correctly configured")
                    except Exception as e:
                        app.logger.error(f"Error verifying database indexes: {e}")

                # Handle different Flask versions gracefully
                # First, try the modern Flask 2.2.0+ approach
                if hasattr(app, "before_serving"):
                    try:
                        app.before_serving(verify_database_indexes)
                        app.logger.debug("Registered index verification with before_serving")
                    except Exception as e:
                        app.logger.warning(f"Failed to use before_serving: {e}. Using fallback.")
                        verify_database_indexes()  # Execute directly as fallback
                # For Flask < 2.2.0, try before_first_request if available
                elif hasattr(app, "before_first_request"):
                    try:
                        app.before_first_request(verify_database_indexes)
                        app.logger.debug("Registered index verification with before_first_request")
                    except Exception as e:
                        app.logger.warning(
                            f"Failed to use before_first_request: {e}. Using fallback."
                        )
                        verify_database_indexes()  # Execute directly as fallback
                # Last resort: just run it immediately
                else:
                    app.logger.debug(
                        "No suitable hooks found, running index verification immediately"
                    )
                    verify_database_indexes()

        # Set up the Duo client if provided
        if self.duo_config:
            self._setup_duo_client(app)

        # Set up health check endpoint if enabled
        if self.health_check_config.get("enabled", True):
            self._setup_health_check(app)

        # Register the user loader
        @self.login_manager.user_loader
        def load_user(user_id):
            return self.load_user(user_id)

        # Register the blueprint with the app
        app.register_blueprint(self.blueprint)

        self.logger.info(f"DuoFlaskAuth initialized with routes at {self.routes_prefix}")

    # Define support methods used by health check early in the class
    def check_database_connection(self) -> Dict[str, Any]:
        """
        Check database connection health.

        This method performs a basic check of the database connection
        and returns information about the connection status.

        Returns:
            Dictionary with connection status information
        """
        if not self.db_adapter:
            return {
                "status": "not_configured",
                "message": "Database adapter is not configured",
                "timestamp": datetime.utcnow(),
            }

        try:
            # Test connection based on adapter type
            if hasattr(self.db_adapter, "check_connection_health"):
                # Use adapter's built-in health check if available
                is_healthy = self.db_adapter.check_connection_health()
            elif hasattr(self.db_adapter, "db") and hasattr(self.db_adapter.db, "command"):
                # For MongoDB adapter
                self.db_adapter.db.command("ping")
                is_healthy = True
            elif hasattr(self.db_adapter, "engine") and hasattr(self.db_adapter.engine, "connect"):
                # For SQLAlchemy adapter
                with self.db_adapter.engine.connect() as conn:
                    conn.execute("SELECT 1")
                is_healthy = True
            else:
                # Generic test - try to get a user
                self.db_adapter.get_user("__health_check__")
                is_healthy = True

            return {
                "status": "healthy" if is_healthy else "unhealthy",
                "message": "Database connection is operational",
                "adapter_type": self.db_adapter.__class__.__name__,
                "timestamp": datetime.utcnow(),
            }

        except Exception as e:
            self.logger.error(f"Database connection check failed: {e}")
            # Safely get adapter type without assuming specific structure
            try:
                if hasattr(self.db_adapter, "__class__") and self.db_adapter.__class__:
                    adapter_type = self.db_adapter.__class__.__name__
                else:
                    adapter_type = str(type(self.db_adapter))
            except Exception as type_error:
                self.logger.debug(f"Failed to determine adapter type: {type_error}")
                adapter_type = "Unknown"

            return {
                "status": "unhealthy",
                "message": f"Database connection failed: {str(e)}",
                "adapter_type": adapter_type,
                "timestamp": datetime.utcnow(),
            }

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        if not hasattr(self, "cache") or not hasattr(self.cache, "get_stats"):
            return {
                "hits": 0,
                "misses": 0,
                "sets": 0,
                "deletes": 0,
                "clears": 0,
                "hit_rate": 0,
                "active_keys": 0,
                "enabled": (
                    self.cache_config.get("enabled", True)
                    if hasattr(self, "cache_config")
                    else False
                ),
                "type": "unknown",
            }

        try:
            stats = self.cache.get_stats()

            # Handle different return types from get_stats
            if isinstance(stats, dict):
                # Already a dictionary
                return stats
            elif hasattr(stats, "__dict__"):
                # Convert object to dictionary
                result = {k: v for k, v in stats.__dict__.items() if not k.startswith("_")}
                # Add additional info
                result.update(
                    {
                        "active_keys": (
                            len(self.cache.get_keys()) if hasattr(self.cache, "get_keys") else 0
                        ),
                        "enabled": self.cache_config.get("enabled", True),
                        "type": self.cache_config.get("type", "memory"),
                    }
                )
                return result
            else:
                # Fallback for unknown type
                return {
                    "hits": getattr(stats, "hits", 0),
                    "misses": getattr(stats, "misses", 0),
                    "sets": getattr(stats, "sets", 0),
                    "deletes": getattr(stats, "deletes", 0),
                    "clears": getattr(stats, "clears", 0),
                    "hit_rate": getattr(stats, "hit_rate", 0),
                    "active_keys": (
                        len(self.cache.get_keys()) if hasattr(self.cache, "get_keys") else 0
                    ),
                    "enabled": self.cache_config.get("enabled", True),
                    "type": self.cache_config.get("type", "memory"),
                }
        except Exception as e:
            self.logger.error(f"Error getting cache stats: {e}")
            return {"error": str(e), "enabled": True, "type": "unknown"}

    def _validate_duo_config(self) -> bool:
        """
        Validate the Duo configuration.

        Returns:
            True if valid, False otherwise
        """
        if not self.duo_config:
            self.logger.debug("Duo MFA not configured")
            return False

        required_keys = ["client_id", "client_secret", "api_host", "redirect_uri"]
        missing_keys = [key for key in required_keys if key not in self.duo_config]

        if missing_keys:
            self.logger.warning(f"Duo MFA configuration missing keys: {', '.join(missing_keys)}")
            return False

        # Check for empty values
        empty_keys = [
            key for key in required_keys if key in self.duo_config and not self.duo_config[key]
        ]

        if empty_keys:
            self.logger.warning(
                f"Duo MFA configuration has empty values for: {', '.join(empty_keys)}"
            )
            return False

        return True

    def _setup_duo_client(self, app: Flask) -> None:
        """
        Set up Duo MFA client with improved error handling.

        Args:
            app: The Flask application.
        """
        # Initialize duo_client to None first
        self.duo_client = None

        # Validate Duo configuration
        if not self._validate_duo_config():
            app.logger.warning("Duo MFA not fully configured or invalid configuration.")
            return

        # Extract Duo configuration
        client_id = self.duo_config.get("client_id")
        client_secret = self.duo_config.get("client_secret")
        api_host = self.duo_config.get("api_host")
        redirect_uri = self.duo_config.get("redirect_uri")

        # Initialize Duo client
        try:
            self.duo_client = Client(
                client_id=client_id,
                client_secret=client_secret,
                host=api_host,
                redirect_uri=redirect_uri,
            )

            # Test connection to Duo
            try:
                # Check if duo_client is not None before calling health_check
                if self.duo_client is not None:
                    self.duo_client.health_check()
                    app.logger.info("Duo MFA client initialized and connection verified")
                else:
                    app.logger.warning("Duo MFA client initialization failed")
            except DuoException as e:
                app.logger.warning(f"Duo MFA client initialized but health check failed: {e}")
                # We'll keep the client initialized but log the warning

        except ImportError:
            app.logger.error(
                "Failed to import Duo Universal SDK. Install it with: pip install duo-universal"
            )
            self.duo_client = None
        except Exception as e:
            app.logger.error(f"Error initializing Duo client: {e}")
            self.duo_client = None

    def _setup_health_check(self, app: Flask) -> None:
        """
        Set up a health check endpoint for monitoring.

        Args:
            app: The Flask application
        """
        health_bp = Blueprint(
            "duo_flask_auth_health", __name__, url_prefix=f"{self.routes_prefix}/health"
        )

        # Store references to methods to avoid issues with self in the closure
        check_db_connection = self.check_database_connection
        get_cache_stats = self.get_cache_stats

        @health_bp.route("/")
        def health_check():
            # Check if service account is required
            if self.health_check_config.get("require_service_account", True):
                # Get auth header
                auth_header = request.headers.get("Authorization")
                if not auth_header or not auth_header.startswith("Bearer "):
                    return jsonify({"status": "error", "message": "Authentication required"}), 401

                # Validate token (simple version)
                token = auth_header[7:]  # Remove 'Bearer ' prefix
                if token != self.health_check_config.get("service_account_token"):
                    return (
                        jsonify({"status": "error", "message": "Invalid authentication token"}),
                        403,
                    )

            # Build health status
            health_status = {
                "status": "healthy",
                "version": __version__,
                "timestamp": datetime.utcnow().isoformat(),
                "components": {},
            }

            # Database status - using the stored reference to avoid "self" issues
            db_status = check_db_connection()
            health_status["components"]["database"] = db_status
            if db_status["status"] not in ["healthy", "not_configured"]:
                health_status["status"] = "degraded"

            # Cache status - using the stored reference to avoid "self" issues
            cache_stats = get_cache_stats()
            health_status["components"]["cache"] = {
                "status": "healthy",
                "type": cache_stats.get("type", "memory"),
                "enabled": cache_stats.get("enabled", True),
            }

            # Duo MFA status
            if self.duo_client is not None:
                try:
                    # Only call health_check if duo_client is not None
                    self.duo_client.health_check()
                    health_status["components"]["duo_mfa"] = {
                        "status": "healthy",
                        "api_host": self.duo_config.get("api_host"),
                    }
                except Exception as e:
                    health_status["components"]["duo_mfa"] = {
                        "status": "unhealthy",
                        "api_host": self.duo_config.get("api_host"),
                        "error": str(e),
                    }
                    health_status["status"] = "degraded"
            else:
                health_status["components"]["duo_mfa"] = {"status": "not_configured"}

            # Overall status code
            status_code = 200 if health_status["status"] == "healthy" else 503

            return jsonify(health_status), status_code

        # Register the blueprint
        app.register_blueprint(health_bp)

    def _setup_routes(self) -> None:
        """Set up authentication routes on the blueprint."""

        # Define a helper function for placeholder routes
        def not_implemented_route(*args, **kwargs):
            """
            Placeholder for route handlers that are not yet implemented.
            Returns a 501 Not Implemented response.
            """
            from flask import jsonify

            return jsonify({"error": "Method not implemented"}), 501

        # Use the helper function for all routes that don't have implementations yet
        if not hasattr(self, "login"):
            self.login = not_implemented_route
        if not hasattr(self, "duo_callback"):
            self.duo_callback = not_implemented_route
        if not hasattr(self, "logout"):
            self.logout = not_implemented_route
        if not hasattr(self, "enable_mfa"):
            self.enable_mfa = not_implemented_route
        if not hasattr(self, "disable_mfa"):
            self.disable_mfa = not_implemented_route
        if not hasattr(self, "add_user"):
            self.add_user = not_implemented_route
        if not hasattr(self, "unlock_account"):
            self.unlock_account = not_implemented_route
        if not hasattr(self, "password_expired"):
            self.password_expired = not_implemented_route
        if not hasattr(self, "forgot_password"):
            self.forgot_password = not_implemented_route
        if not hasattr(self, "reset_password"):
            self.reset_password = not_implemented_route
        if not hasattr(self, "login_success"):
            self.login_success = not_implemented_route

        # Now set up the routes
        self.blueprint.route("/login/", methods=["GET", "POST"])(self.login)
        self.blueprint.route("/duo-callback")(self.duo_callback)
        self.blueprint.route("/logout")(self.logout)
        self.blueprint.route("/enable-mfa", methods=["GET", "POST"])(self.enable_mfa)
        self.blueprint.route("/disable-mfa", methods=["GET", "POST"])(self.disable_mfa)
        self.blueprint.route("/add-user/<username>/<password>", methods=["GET", "POST"])(
            self.add_user
        )
        self.blueprint.route("/unlock-account/<username>", methods=["GET", "POST"])(
            self.unlock_account
        )
        self.blueprint.route("/password-expired", methods=["GET", "POST"])(self.password_expired)
        self.blueprint.route("/forgot-password", methods=["GET", "POST"])(self.forgot_password)
        self.blueprint.route("/reset-password/<username>/<token>", methods=["GET", "POST"])(
            self.reset_password
        )
        self.blueprint.route("/login-success")(self.login_success)

    def _get_template_context(self):
        """
        Get common template context including CSRF token.

        Returns:
            Dictionary with template context
        """
        return {"csrf_token": generate_csrf()}

    def _invalidate_user_cache(self, username: str) -> None:
        """
        Invalidate cache for a specific user.

        Args:
            username: The username to invalidate cache for
        """
        cache_key = f"user:{username}"
        self.cache.delete(cache_key)
        self.logger.debug(f"Invalidated cache for user '{username}'")

    def load_user(self, user_id: str) -> Optional[BaseUser]:
        """
        Load a user from the database or cache by their user ID.

        This method attempts to retrieve user data from the cache first.
        If not found in the cache, it queries the database and then caches the result.
        It also checks if the user's password has expired.

        Args:
            user_id: The ID of the user to load (typically the username).

        Returns:
            A User object if the user is found, otherwise None.

        Raises:
            Exception: If there is an error creating the user object.
        """
        current_app.logger.debug(f"Loading user: {user_id}")

        if not self.db_adapter:
            current_app.logger.error("Database adapter not configured")
            return None

        # Try to get user from cache first
        cache_key = f"user:{user_id}"
        cached_user = self.cache.get(cache_key)

        if cached_user:
            current_app.logger.debug(f"User '{user_id}' loaded from cache")

            # Check if password has expired (we always do this check even with cached data)
            if self._is_password_expired(cached_user):
                cached_user["password_expired"] = True

            # Create a User object with the cached data
            try:
                user = self.user_factory(cached_user)
                return user
            except Exception as e:
                current_app.logger.error(f"Error creating user object from cache: {e}")
                # Fall through to database lookup

        # User not in cache, get from database
        current_app.logger.debug(f"User '{user_id}' not found in cache, querying database")
        user_data = self.db_adapter.get_user(user_id)

        if not user_data:
            current_app.logger.debug(f"User '{user_id}' not found in database")
            return None

        # Check if password has expired
        if self._is_password_expired(user_data):
            user_data["password_expired"] = True

        # Cache the user data
        user_ttl = self.cache_config.get("user_ttl", 60)
        self.cache.set(cache_key, user_data, ttl=user_ttl)
        current_app.logger.debug(f"User '{user_id}' cached with TTL of {user_ttl}s")

        # Create a User object with the data from the database
        try:
            user = self.user_factory(user_data)
            return user
        except Exception as e:
            current_app.logger.error(f"Error creating user object: {e}")
            return None

    def is_valid_email(self, email: str) -> bool:
        """
        Validate email format using regex.

        Args:
            email: The email to validate

        Returns:
            True if valid email format, False otherwise
        """
        # Basic email validation pattern
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def _is_rate_limited(self, key: str, action: str) -> bool:
        """
        Check if an action from a key (IP or username) is rate limited.

        Args:
            key: The key to check (IP address or username)
            action: The action to check (login, password_reset, etc.)

        Returns:
            True if rate limited, False otherwise
        """
        if not self.rate_limit_config.get("enabled", True):
            return False

        # Get the maximum attempts and window for this action
        max_attempts = self.rate_limit_config.get("max_attempts", {}).get(action, 5)
        window_seconds = self.rate_limit_config.get("window_seconds", {}).get(action, 300)

        # Create a composite key
        cache_key = f"rate_limit:{key}:{action}"

        # Get the current time
        now = time.time()

        # Use Redis if configured
        if getattr(self, "_use_redis_rate_limiting", False) and hasattr(self, "redis_client"):
            try:
                # Check if key exists
                if not self.redis_client.exists(cache_key):
                    # If not, create a new entry with TTL
                    pipeline = self.redis_client.pipeline()
                    pipeline.hset(cache_key, "attempts", 1)
                    pipeline.hset(cache_key, "first_attempt", now)
                    pipeline.hset(cache_key, "last_attempt", now)
                    pipeline.expire(cache_key, window_seconds)
                    pipeline.execute()
                    return False

                # Get the existing entry
                attempts = int(self.redis_client.hget(cache_key, "attempts") or 1)
                first_attempt = float(self.redis_client.hget(cache_key, "first_attempt") or now)

                # Check if the entry has expired (should be handled by Redis TTL, but as a safeguard)
                if now - first_attempt > window_seconds:
                    # If so, reset it
                    pipeline = self.redis_client.pipeline()
                    pipeline.hset(cache_key, "attempts", 1)
                    pipeline.hset(cache_key, "first_attempt", now)
                    pipeline.hset(cache_key, "last_attempt", now)
                    pipeline.expire(cache_key, window_seconds)
                    pipeline.execute()
                    return False

                # Update the last attempt time and increment attempts
                pipeline = self.redis_client.pipeline()
                pipeline.hset(cache_key, "last_attempt", now)
                pipeline.hincrby(cache_key, "attempts", 1)
                pipeline.execute()

                # Check if the maximum attempts have been exceeded
                return attempts + 1 > max_attempts

            except Exception as e:
                self.logger.error(f"Redis rate limiting error: {e}. Falling back to permissive.")
                return False
        else:
            # Use memory store (original implementation)
            # Check if the key exists in the store
            if cache_key not in self._rate_limit_store:
                # If not, create a new entry
                self._rate_limit_store[cache_key] = {
                    "attempts": 1,
                    "first_attempt": now,
                    "last_attempt": now,
                }
                return False

            # Get the entry
            entry = self._rate_limit_store[cache_key]

            # Check if the entry has expired
            if now - entry["first_attempt"] > window_seconds:
                # If so, reset it
                entry["attempts"] = 1
                entry["first_attempt"] = now
                entry["last_attempt"] = now
                return False

            # Update the last attempt time
            entry["last_attempt"] = now

            # Increment the attempt counter
            entry["attempts"] += 1

            # Check if the maximum attempts have been exceeded
            return entry["attempts"] > max_attempts

    def _reset_rate_limit(self, key: str, action: str) -> None:
        """
        Reset the rate limit for a key and action.

        Args:
            key: The key to reset (IP address or username)
            action: The action to reset (login, password_reset, etc.)
        """
        cache_key = f"rate_limit:{key}:{action}"

        # Use Redis if configured
        if getattr(self, "_use_redis_rate_limiting", False) and hasattr(self, "redis_client"):
            try:
                self.redis_client.delete(cache_key)
            except Exception as e:
                self.logger.error(f"Redis error while resetting rate limit: {e}")
        else:
            # Use memory store
            if cache_key in self._rate_limit_store:
                del self._rate_limit_store[cache_key]

    def _check_account_lockout(self, username: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an account is locked.

        Args:
            username: The username to check

        Returns:
            Tuple containing:
              - Boolean indicating if the account is locked
              - Optional reason for lockout
        """
        if not self.account_lockout_config.get("enabled", True) or not self.db_adapter:
            return False, None

        # Get user data
        user_data = self.db_adapter.get_user(username)

        if not user_data:
            return False, None

        # Check if account is explicitly inactive
        if not user_data.get("is_active", True):
            return True, "Account is deactivated"

        # Check if there's a lockout timestamp and it's in the future
        locked_until = user_data.get("locked_until")
        if locked_until and isinstance(locked_until, datetime) and locked_until > datetime.utcnow():
            return True, f"Account is locked until {locked_until}"

        # Check if too many failed attempts
        login_attempts = user_data.get("login_attempts", 0)
        max_attempts = self.account_lockout_config.get("max_attempts", 5)

        if login_attempts >= max_attempts:
            # Lock the account
            lockout_duration = self.account_lockout_config.get(
                "lockout_duration", 1800
            )  # 30 minutes
            locked_until = datetime.utcnow() + timedelta(seconds=lockout_duration)

            # Update the user record
            self.db_adapter.update_user(username, {"locked_until": locked_until})

            # Invalidate cache
            self._invalidate_user_cache(username)

            return True, f"Account is locked until {locked_until}"

        return False, None

    def _unlock_account(self, username: str) -> bool:
        """
        Unlock an account and invalidate cache.

        Args:
            username: The username to unlock

        Returns:
            True if successful, False otherwise
        """
        if not self.db_adapter:
            self.logger.error("Database adapter not configured")
            return False

        try:
            # Reset login attempts and clear lockout
            result = self.db_adapter.update_user(
                username, {"login_attempts": 0, "locked_until": None}
            )

            if result:
                # Invalidate cache for this user
                self._invalidate_user_cache(username)

            self.logger.info(f"Account unlocked for user: {username}")
            return result

        except Exception as e:
            self.logger.error(f"Error unlocking account for user '{username}': {e}")
            return False

    def _is_password_expired(self, user_data: Dict[str, Any]) -> bool:
        """
        Check if a user's password has expired.

        Args:
            user_data: The user data from the database

        Returns:
            True if the password has expired, False otherwise
        """
        # Check if password expiration is enabled
        max_age_days = self.password_policy.get("max_age_days")
        if not max_age_days:
            return False

        # Check if there's a last password change timestamp
        last_password_change = user_data.get("last_password_change")
        if not last_password_change or not isinstance(last_password_change, datetime):
            return False

        # Check if the password is older than the maximum age
        password_age = (datetime.utcnow() - last_password_change).days
        return password_age > max_age_days
