"""
duo_flask_auth - Flask Authentication Library with Duo MFA Support

This package provides authentication functionality with Duo MFA integration
for Flask applications.
"""

from .auth import DuoFlaskAuth, User

__version__ = '0.1.0'
__all__ = ['DuoFlaskAuth', 'User']