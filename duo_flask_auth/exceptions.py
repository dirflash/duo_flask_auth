"""
Exceptions for the Duo Flask Auth library.

This module provides custom exception classes for various authentication-related errors.
"""

class AuthError(Exception):
    """Base exception for authentication errors."""

    def __init__(self, message: str, code: str = None):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: An optional error code for categorizing errors.
        """
        self.message = message
        self.code = code
        super().__init__(self.message)


class InvalidCredentialsError(AuthError):
    """Raised when credentials are invalid."""

    def __init__(self, message: str = "Invalid username or password", code: str = "invalid_credentials"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)


class AccountLockedError(AuthError):
    """Raised when an account is locked."""

    def __init__(self, message: str = "Account is locked", code: str = "account_locked"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)


class MFARequiredError(AuthError):
    """Raised when MFA is required but not completed."""

    def __init__(self, message: str = "Multi-factor authentication is required", code: str = "mfa_required"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)


class RateLimitedError(AuthError):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str = "Too many attempts. Please try again later", code: str = "rate_limited"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)


class PasswordPolicyError(AuthError):
    """Raised when a password does not meet policy requirements."""

    def __init__(self, message: str = "Password does not meet requirements", code: str = "password_policy"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)


class PasswordExpiredError(AuthError):
    """Raised when a password has expired."""

    def __init__(self, message: str = "Password has expired", code: str = "password_expired"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)


class TokenInvalidError(AuthError):
    """Raised when a token is invalid or expired."""

    def __init__(self, message: str = "Invalid or expired token", code: str = "token_invalid"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)


class PermissionDeniedError(AuthError):
    """Raised when a user does not have permission for an action."""

    def __init__(self, message: str = "Permission denied", code: str = "permission_denied"):
        """
        Initialize the exception.

        Args:
            message: The error message.
            code: The error code.
        """
        super().__init__(message, code)