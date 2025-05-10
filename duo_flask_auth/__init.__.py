"""
duo_flask_auth - Flask Authentication Library with Duo MFA Support

This package provides authentication functionality with Duo MFA integration
for Flask applications.
"""

from .auth import DuoFlaskAuth
from .user_model import BaseUser, register_user_model
from .db_adapters import DatabaseAdapter, MongoDBAdapter, SQLAlchemyAdapter, get_db_adapter
from .exceptions import (
    AuthError,
    InvalidCredentialsError,
    AccountLockedError,
    MFARequiredError,
    RateLimitedError,
    PasswordPolicyError,
    TokenInvalidError,
    PermissionDeniedError
)

__version__ = '0.3.0'
__all__ = [
    'DuoFlaskAuth',
    'BaseUser',
    'register_user_model',
    'DatabaseAdapter',
    'MongoDBAdapter',
    'SQLAlchemyAdapter',
    'get_db_adapter',
    'AuthError',
    'InvalidCredentialsError',
    'AccountLockedError',
    'MFARequiredError',
    'RateLimitedError',
    'PasswordPolicyError',
    'TokenInvalidError',
    'PermissionDeniedError'
]