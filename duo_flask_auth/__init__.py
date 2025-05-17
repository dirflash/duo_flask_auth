"""
duo_flask_auth - Flask Authentication Library with Duo MFA Support

This package provides authentication functionality with Duo MFA integration
for Flask applications.
"""

# Version information
__version__ = "0.4.0"

# Import classes after defining version to avoid circular imports
try:
    # The order of imports matters for resolving dependencies
    from duo_flask_auth.auth import DuoFlaskAuth
    from duo_flask_auth.cache import Cache, MemoryCache, NoCache
    from duo_flask_auth.db_adapters import (
        DatabaseAdapter,
        MongoDBAdapter,
        SQLAlchemyAdapter,
        get_db_adapter,
    )
    from duo_flask_auth.exceptions import (
        AccountLockedError,
        AuthError,
        InvalidCredentialsError,
        MFARequiredError,
        PasswordPolicyError,
        PermissionDeniedError,
        RateLimitedError,
        TokenInvalidError,
    )
    from duo_flask_auth.user_model import BaseUser, register_user_model

    # List of public classes/functions
    __all__ = [
        "DuoFlaskAuth",
        "BaseUser",
        "register_user_model",
        "DatabaseAdapter",
        "MongoDBAdapter",
        "SQLAlchemyAdapter",
        "get_db_adapter",
        "Cache",
        "MemoryCache",
        "NoCache",
        "AuthError",
        "InvalidCredentialsError",
        "AccountLockedError",
        "MFARequiredError",
        "RateLimitedError",
        "PasswordPolicyError",
        "TokenInvalidError",
        "PermissionDeniedError",
    ]
except ImportError as e:
    # Log the import error without causing the entire import to fail
    # This allows the version to be imported even if there are issues with other modules
    import logging

    logging.getLogger(__name__).warning(f"Error importing duo_flask_auth components: {e}")
