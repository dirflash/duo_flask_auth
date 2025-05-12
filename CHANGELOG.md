# Changelog

All notable changes to the Duo Flask Auth library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2025-05-20

### Added

- Performance enhancements:
  - Connection pooling:
    - Configurable MongoDB connection pool settings
    - Optimized connection management for high traffic applications
    - Automatic connection reuse to reduce database overhead
  - Caching system:
    - In-memory caching for frequently accessed user data
    - Configurable Time-To-Live (TTL) for different data types
    - Automatic cache invalidation on user data updates
    - Cache statistics for monitoring hit/miss rates
  - Database indexing:
    - Optimized MongoDB indexes for common authentication queries
    - TTL indexes for automatic token expiration
    - Compound indexes for complex query patterns
    - Background index creation to prevent blocking operations
    - Index health monitoring and verification
- New classes and modules:
  - `cache.py` with MemoryCache implementation
  - Enhanced database adapter with connection pooling support
  - Database index health checking functionality
- Additional documentation:
  - Performance tuning guide
  - Cache configuration examples
  - Database indexing best practices

### Changed

- Updated MongoDB connection handling with optimized settings
- Enhanced user loading with caching to reduce database load
- Improved MongoDB query methods with index awareness
- Added cache invalidation to all user update operations
- Added index verification on application startup

### Improved

- Authentication performance under high load
- Database query efficiency with optimized indexes
- Memory usage with configurable connection pooling
- Response times with in-memory caching
- Long-term stability with better connection management

## [0.3.0] - 2025-05-15

### Added

- Flexibility enhancements:
  - Multiple database backend support:
    - Added abstract `DatabaseAdapter` interface
    - Implemented MongoDB adapter
    - Added SQLAlchemy adapter for SQL databases
    - Added factory function for creating adapters
  - Customizable user model:
    - Created extensible `BaseUser` class
    - Added user factory pattern for creating different user types
    - Implemented registry for custom user models
  - Configurable routes:
    - Added ability to specify custom route prefix
    - Used Blueprint architecture for route organization
  - Enhanced error handling:
    - Created comprehensive exception hierarchy
    - Added specific exceptions for different error types
- New classes and modules:
  - `db_adapters.py` for database abstraction
  - `user_model.py` for user model customization
  - `exceptions.py` for error handling
- Additional documentation:
  - Added examples for different database backends
  - Added examples for custom user models
  - Added examples for route configuration

### Changed

- Refactored core authentication logic to use database adapters
- Updated user loading to use the user factory system
- Improved error handling with custom exceptions
- Enhanced documentation with flexibility examples
- Updated type hints for better IDE support

### Improved

- Better error messages for configuration issues
- More consistent method signatures
- Cleaner separation of concerns
- Better organization of code

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
