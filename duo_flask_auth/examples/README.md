# Duo Flask Auth Examples

This directory contains example applications demonstrating how to use the Duo Flask Auth library in various configurations. These examples show different features and integration patterns.

## Basic Example

The `basic_app.py` file demonstrates a minimal implementation of the Duo Flask Auth library with essential features:

- User authentication with username and password
- Duo MFA integration
- Basic user management
- Default templates and routes

Run the basic example:

```bash
# Set required environment variables
export FLASK_SECRET_KEY="your-secure-secret"
export MONGO_USERNAME="your-mongodb-username"
export MONGO_PASSWORD="your-mongodb-password"
export MONGO_HOST="your-mongodb-host"
export MONGO_DATABASE="your-database"
export DUO_CLIENT_ID="your-duo-client-id"
export DUO_CLIENT_SECRET="your-duo-client-secret"
export DUO_API_HOST="api-your-duo-host.duosecurity.com"
export DUO_REDIRECT_URI="https://your-app-url/duo-callback"

# Run the Flask app
python basic_app.py
```

## Secure Example

The `secure_app.py` file demonstrates a more comprehensive implementation with all security features enabled:

- Enhanced security features:
  - Rate limiting
  - Account lockout
  - Password policies
  - CSRF protection
  - Security event logging
- Admin features for user management
- Security event monitoring

Run the secure example:

```bash
# Set environment variables (as shown above)
# ...

# Run the Flask app
python secure_app.py
```

## Performance Example

The `performance_app.py` file demonstrates how to optimize the library for high-traffic applications:

- Connection pooling for MongoDB
- User data caching
- Optimized database indexes
- Performance monitoring

Run the performance example:

```bash
# Set environment variables (as shown above)
# ...

# Run the Flask app
python performance_app.py
```

## Custom Adapter Example

The `custom_adapter_app.py` file demonstrates how to implement a custom database adapter:

- Custom database adapter implementation
- Integration with a non-standard database
- Custom user model

## Custom User Model Example

The `custom_user_model_app.py` file demonstrates how to extend the user model with custom fields and methods:

- Extended user model with additional fields
- Custom user factory
- Role-based access control

## API Integration Example

The `api_integration_app.py` file demonstrates how to use the library in an API-based application:

- JWT token integration
- API routes and responses
- Headless authentication

## Testing the Examples

Each example includes a set of test scripts that demonstrate how to interact with the application:

```bash
# Install test dependencies
pip install requests pytest

# Run the test script for a specific example
python test_basic_app.py
```

## Directory Structure

```
examples/
├── README.md                     # This file
├── basic_app.py                  # Basic implementation example
├── secure_app.py                 # Security-focused example
├── performance_app.py            # Performance-optimized example
├── custom_adapter_app.py         # Custom database adapter example
├── custom_user_model_app.py      # Custom user model example
├── api_integration_app.py        # API integration example
├── templates/                    # Example templates
│   ├── admin/                    # Admin dashboard templates
│   ├── base.html                 # Base template
│   ├── dashboard.html            # Dashboard template
│   └── ...                       # Other templates
└── tests/                        # Test scripts
    ├── test_basic_app.py         # Tests for basic example
    ├── test_secure_app.py        # Tests for secure example
    └── ...                       # Other test scripts
```

## Performance Optimization Guide

### Connection Pooling

The MongoDB connection pool can be configured to match your application's traffic patterns:

```python
# Configure MongoDB connection pool
db_config = {
    'username': os.environ.get('MONGO_USERNAME'),
    'password': os.environ.get('MONGO_PASSWORD'),
    'host': os.environ.get('MONGO_HOST'),
    'database': os.environ.get('MONGO_DATABASE'),
    'pool_size': 50,               # Maximum connections in the pool
    'min_pool_size': 10,           # Minimum connections to maintain
    'max_idle_time_ms': 60000,     # 1 minute idle time
    'wait_queue_timeout_ms': 2000, # Wait queue timeout
    'connect_timeout_ms': 30000,   # Connection timeout
    'socket_timeout_ms': 45000     # Socket timeout
}

# Initialize with connection pooling
auth = DuoFlaskAuth(app, db_config=db_config)
```

### Caching Configuration

User data caching can significantly reduce database load:

```python
# Configure caching
cache_config = {
    'enabled': True,               # Enable caching
    'type': 'memory',              # Cache type (currently only 'memory' is supported)
    'default_ttl': 300,            # Default TTL (5 minutes)
    'user_ttl': 60,                # User data TTL (1 minute)
    'security_events_ttl': 300     # Security events TTL (5 minutes)
}

# Initialize with caching
auth = DuoFlaskAuth(app, db_config=db_config, cache_config=cache_config)

# Monitor cache performance
@app.route('/admin/cache-stats')
@login_required
def cache_stats():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    stats = auth.get_cache_stats()
    return render_template('admin/cache_stats.html', stats=stats)
```

### Database Index Monitoring

Monitor the health of your database indexes:

```python
# Check database index health on startup
@app.before_first_request
def check_db_health():
    index_health = auth.check_database_indexes()
    app.logger.info(f"Database index health: {index_health['status']}")

    if index_health['status'] != 'healthy':
        app.logger.warning(f"Database indexes need attention: {index_health['health_percentage']}% healthy")

        if index_health.get('missing_indexes'):
            app.logger.warning(f"Missing indexes: {', '.join(index_health['missing_indexes'])}")
```

## Best Practices

1. **Connection Pooling**:

   - Set `pool_size` based on your expected concurrent users
   - For high-traffic applications, increase `min_pool_size` to reduce connection creation overhead
   - Adjust `max_idle_time_ms` based on your traffic patterns

2. **Caching**:

   - Shorter TTL values (like 60 seconds) for frequently changing data
   - Longer TTL values (like 300 seconds) for relatively static data
   - Monitor cache hit rates to optimize TTL values

3. **Database Indexes**:

   - Regularly monitor index health with `check_database_indexes()`
   - Ensure indexes are properly created at application startup
   - Use background index creation to avoid blocking operations

4. **Performance Monitoring**:
   - Implement monitoring endpoints to track cache and database performance
   - Log cache hit rates and database query times
   - Set up alerts for performance degradation
