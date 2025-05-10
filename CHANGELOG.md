# Changelog

All notable changes to the Duo Flask Auth library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-05-10

### Added

- Comprehensive security enhancements:
  - Rate limiting for login and password reset attempts
  - Account lockout policy for failed login attempts
  - CSRF protection using Flask-WTF
  - Enhanced password policies (complexity, expiration, etc.)
  - Security event logging system
  - Account status management (lock/unlock)
- New templates for security features:
  - Password expired template
  - Account locked template
  - Unlock account template (admin)
  - Forgot password template
  - Reset password template
- Custom exception classes for better error handling
- Additional user attributes for security tracking
- MongoDB schema updates for security features
- Security events collection for audit logging
- Admin-only account unlock functionality
- Secure password reset workflow

### Changed

- Enhanced user model with security-related attributes
- Updated login flow to include rate limiting and account lockout
- Improved error messages and handling
- Updated documentation with security features
- Enhanced example app with security features enabled

### Fixed

- IP address validation in security logging
- Improved MongoDB connection handling

## [0.1.0] - 2025-05-01

### Added

- Initial release of Duo Flask Auth library
- Basic authentication functionality
- Duo MFA integration
- MongoDB user storage
- User management (add users, enable/disable MFA)
- Customizable templates
- Blueprint-based architecture
