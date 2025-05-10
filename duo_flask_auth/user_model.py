"""
User model for the Duo Flask Auth library.

This module provides the base user model and factory for creating custom user models.
"""

from datetime import datetime
from typing import Dict, Any, Optional, Type, Callable

from flask_login import UserMixin
from werkzeug.security import check_password_hash


class BaseUser(UserMixin):
    """
    Base user class that can be extended for custom user models.

    This class provides the basic functionality required for Flask-Login
    and additional attributes for the Duo Flask Auth library.
    """

    def __init__(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        mfa_enabled: bool = False,
        **kwargs
    ):
        """
        Initialize a user.

        Args:
            user_id: The unique identifier for the user.
            username: The username of the user.
            password_hash: The hashed password of the user.
            mfa_enabled: Whether MFA is enabled for this user.
            **kwargs: Additional user attributes.
        """
        self.id = user_id
        self.username = username
        self.password_hash = password_hash
        self.mfa_enabled = mfa_enabled

        # Additional fields from the schema
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
        self.password_expired = kwargs.get('password_expired', False)
        self.locked_until = kwargs.get('locked_until')

        # Set any additional attributes
        for key, value in kwargs.items():
            if not hasattr(self, key):
                setattr(self, key, value)

    def check_password(self, password: str) -> bool:
        """
        Verify if the provided password matches the stored password hash.

        Args:
            password: The plaintext password to verify.

        Returns:
            True if the password matches the stored hash, False otherwise.
        """
        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:
        """
        Return the user ID for Flask-Login.

        Returns:
            The username (used as ID in this system).
        """
        return self.username

    @property
    def is_account_locked(self) -> bool:
        """
        Check if the account is currently locked.

        Returns:
            True if the account is locked, False otherwise.
        """
        if not self.is_active:
            return True

        if self.locked_until and self.locked_until > datetime.utcnow():
            return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert user object to a dictionary.

        Returns:
            Dictionary representation of the user.
        """
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith('_'):
                result[key] = value
        return result


# Default user factory function
def default_user_factory(user_data: Dict[str, Any]) -> BaseUser:
    """
    Create a BaseUser instance from user data.

    Args:
        user_data: User data from the database.

    Returns:
        A BaseUser instance.
    """
    return BaseUser(
        user_id=str(user_data.get("_id", user_data.get("id", ""))),
        username=user_data.get("username", ""),
        password_hash=user_data.get("password_hash", ""),
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
        reset_token_expires=user_data.get("reset_token_expires"),
        password_expired=user_data.get("password_expired", False),
        locked_until=user_data.get("locked_until")
    )


# Map of user model types to their factory functions
USER_MODELS = {
    'default': default_user_factory
}


def register_user_model(name: str, factory: Callable[[Dict[str, Any]], BaseUser]) -> None:
    """
    Register a custom user model factory.

    Args:
        name: Name of the user model.
        factory: Factory function to create the user model.
    """
    USER_MODELS[name] = factory


def get_user_factory(model_name: str = 'default') -> Callable[[Dict[str, Any]], BaseUser]:
    """
    Get a user factory function by name.

    Args:
        model_name: Name of the user model.

    Returns:
        Factory function for the user model.

    Raises:
        ValueError: If the user model is not registered.
    """
    if model_name not in USER_MODELS:
        raise ValueError(f"User model '{model_name}' is not registered")

    return USER_MODELS[model_name]


# Example of how to register a custom user model
"""
class CustomUser(BaseUser):
    def __init__(self, user_id, username, password_hash, mfa_enabled=False, **kwargs):
        super().__init__(user_id, username, password_hash, mfa_enabled, **kwargs)
        self.custom_field = kwargs.get('custom_field')

    def custom_method(self):
        return f"Custom method for {self.username}"

def custom_user_factory(user_data):
    return CustomUser(
        user_id=str(user_data.get("_id", user_data.get("id", ""))),
        username=user_data.get("username", ""),
        password_hash=user_data.get("password_hash", ""),
        mfa_enabled=user_data.get("mfa_enabled", False),
        # Include all other fields...
        custom_field=user_data.get("custom_field")
    )

# Register the custom user model
register_user_model('custom', custom_user_factory)
"""