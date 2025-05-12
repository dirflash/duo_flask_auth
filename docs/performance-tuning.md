# Performance Tuning Guide

This guide provides information on optimizing the performance of the Duo Flask Auth library, particularly for high-traffic applications.

## Table of Contents

- [Connection Pooling](#connection-pooling)
- [Caching](#caching)
- [Database Indexing](#database-indexing)
- [Monitoring Performance](#monitoring-performance)
- [Benchmarking](#benchmarking)
- [Example Configurations](#example-configurations)

## Connection Pooling

Connection pooling allows the reuse of database connections, which significantly reduces the overhead of establishing new connections for each request. This is especially important for applications with high traffic.

### Configuration Options

```python
db_config = {
    'username': 'mongodb_username',
    'password': 'mongodb_password',
    'host': 'mongodb_host',
    'database': 'your_database',

    # Connection pooling configuration
    'pool_size': 50,              # Maximum number of connections in the pool
    'min_pool_size': 10,          # Minimum number of connections to maintain
    'max_idle_time_ms': 60000,    # How long connections can remain idle (1 minute)
    'wait_queue_timeout_ms': 2000 # How long to wait for an available connection
}

auth = DuoFlaskAuth(app, db_config=db_config)
```

### Tuning Recommendations

- **pool_size**: Set this based on the maximum number of concurrent requests your application needs to handle. A good starting point is 50-100 connections. For very high traffic applications, you might need to increase this further.

- **min_pool_size**: Setting a minimum pool size helps ensure that connections are ready when traffic suddenly increases. This is especially useful for applications with variable traffic patterns.

- **max_idle_time_ms**: This controls how long idle connections stay in the pool. For most applications, 60000 ms (1 minute) is a good default.

- **wait_queue_timeout_ms**: How long a thread will wait to get a connection from the pool if all connections are in use. This should be set based on your application's acceptable latency during peak loads.

### Example Sizing

- **Small applications**: pool_size=20, min_pool_size=5
- **Medium applications**: pool_size=50, min_pool_size=10
- **Large applications**: pool_size=100, min_pool_size=20
- **Very large applications**: Consider sharding your database and using multiple connection pools

## Caching

The library includes an in-memory caching system that can significantly reduce database load by caching frequently accessed user data.

### Configuration Options

```python
cache_config = {
    'enabled': True,              # Enable or disable caching
    'type': 'memory',             # Cache implementation (currently only 'memory' supported)
    'default_ttl': 300,           # Default TTL for cached items (5 minutes)
    'user_ttl': 60,               # TTL for user data (1 minute)
    'security_events_ttl': 300,   # TTL for security events (5 minutes)
    'cleanup_interval': 60        # Interval for cleaning up expired entries (1 minute)
}

auth = DuoFlaskAuth(app, db_config=db_config, cache_config=cache_config)
```

### Tuning Recommendations

- **TTL Values**: The Time-To-Live (TTL) values control how long data stays in the cache. Shorter TTL values ensure data freshness but may increase database load. Longer TTL values reduce database load but may serve stale data.

  - For user data, a TTL of 60 seconds is a good balance. This ensures that user data is relatively fresh while still significantly reducing database load.

  - For security events, a longer TTL (e.g., 300 seconds) is usually acceptable since these are typically used for reporting rather than real-time decisions.

- **Memory Usage**: The memory cache stores all data in-memory, so be mindful of your application's memory usage. For applications with a very large number of users, you may need to limit the TTL or switch to a distributed cache like Redis (coming in a future release).

- **Cache Invalidation**: The library automatically invalidates the cache when user data is updated. However, if you modify user data directly in the database, you should manually invalidate the cache by calling `auth.cache.delete(f"user:{username}")`.

### Monitoring Cache Performance

You can monitor the effectiveness of caching using the `get_cache_stats()` method:

```python
cache_stats = auth.get_cache_stats()
print(f"Cache hit rate: {cache_stats['hit_rate']*100:.1f}%")
print(f"Total hits: {cache_stats['hits']}, Misses: {cache_stats['misses']}")
```

A high hit rate (>80%) indicates that the cache is working effectively. If the hit rate is low, you may need to adjust the TTL values or review your application's user access patterns.

## Database Indexing

The library automatically creates optimized indexes for MongoDB collections to improve query performance. This is especially important for applications with large user databases.

### Verifying Index Health

You can check the health of your database indexes using the `check_database_indexes()` method:

```python
index_health = auth.check_database_indexes()
print(f"Database index health: {index_health['status']} ({index_health['health_percentage']}%)")
if index_health.get('missing_indexes'):
    print(f"Missing indexes: {', '.join(index_health['missing_indexes'])}")
```

This will provide information about which indexes exist and which ones are missing. Missing indexes can significantly impact query performance.

### Important Indexes

The library creates the following important indexes:

1. **username_idx**: Used for user lookup by username (primary authentication path)
2. **email_verified_idx**: Used for filtering users by email verification status
3. **reset_token_idx**: Used for password reset token lookup
4. **account_id_idx**: Used for user lookup by account ID
5. **role_idx**: Used for filtering users by role
6. **account_status_idx**: Compound index for checking account lockout status
7. **password_age_idx**: Used for checking password expiration

If any of these indexes are missing, you should ensure they are created. The library will attempt to create them automatically at startup, but in some cases (e.g., insufficient database permissions), this may fail.

## Monitoring Performance

### Request Timing

Monitoring request times is essential for understanding the performance of your application. You can add middleware to track request times:

```python
@app.before_request
def start_timer():
    request.start_time = time.time()

@app.after_request
def record_request_time(response):
    if hasattr(request, 'start_time'):
        request_time = time.time() - request.start_time
        # Log or store the request time
        current_app.logger.info(f"Request processed in {request_time:.4f}s")
        # Add a header with the request time
        response.headers['X-Request-Time'] = str(request_time)
    return response
```

### Cache Performance

As mentioned earlier, you can monitor cache performance using the `get_cache_stats()` method.

### Database Performance

MongoDB provides various tools for monitoring database performance:

- **MongoDB Atlas**: If you're using MongoDB Atlas, it provides detailed performance metrics and recommendations.
- **MongoDB Compass**: A GUI tool that can help you analyze query performance and index usage.
- **MongoDB Query Profiler**: You can enable the query profiler to log slow queries.

## Benchmarking

Before deploying changes to a production environment, it's important to benchmark the performance impact. Here's a simple benchmarking approach:

1. **Setup**: Create a test environment with a representative dataset.
2. **Baseline**: Measure the performance of the current version.
3. **Test**: Measure the performance of the new version with the same workload.
4. **Compare**: Compare the results and determine if the changes have a positive impact.

Example benchmarking script:

```python
import time
import statistics
import requests

def benchmark_endpoint(url, auth_header, num_requests=100):
    """Benchmark an endpoint by making multiple requests."""
    times = []
    for _ in range(num_requests):
        start_time = time.time()
        response = requests.get(url, headers=auth_header)
        end_time = time.time()
        times.append(end_time - start_time)

    avg_time = statistics.mean(times)
    p95_time = sorted(times)[int(num_requests * 0.95)]
    p99_time = sorted(times)[int(num_requests * 0.99)]

    return {
        'avg': avg_time,
        'p95': p95_time,
        'p99': p99_time,
        'min': min(times),
        'max': max(times)
    }

# Example usage
results = benchmark_endpoint(
    'https://your-app.com/api/user-profile',
    {'Authorization': 'Bearer your-token-here'},
    num_requests=1000
)

print(f"Average: {results['avg']:.4f}s")
print(f"95th percentile: {results['p95']:.4f}s")
print(f"99th percentile: {results['p99']:.4f}s")
```

## Example Configurations

### Small Application (< 100 concurrent users)

```python
db_config = {
    'username': 'mongodb_username',
    'password': 'mongodb_password',
    'host': 'mongodb_host',
    'database': 'your_database',
    'pool_size': 20,
    'min_pool_size': 5
}

cache_config = {
    'enabled': True,
    'type': 'memory',
    'default_ttl': 300,
    'user_ttl': 60,
    'security_events_ttl': 300
}

auth = DuoFlaskAuth(app, db_config=db_config, cache_config=cache_config)
```

### Medium Application (100-1000 concurrent users)

```python
db_config = {
    'username': 'mongodb_username',
    'password': 'mongodb_password',
    'host': 'mongodb_host',
    'database': 'your_database',
    'pool_size': 50,
    'min_pool_size': 10,
    'max_idle_time_ms': 60000,
    'wait_queue_timeout_ms': 2000
}

cache_config = {
    'enabled': True,
    'type': 'memory',
    'default_ttl': 300,
    'user_ttl': 60,
    'security_events_ttl': 300,
    'cleanup_interval': 60
}

auth = DuoFlaskAuth(app, db_config=db_config, cache_config=cache_config)
```

### Large Application (1000+ concurrent users)

```python
db_config = {
    'username': 'mongodb_username',
    'password': 'mongodb_password',
    'host': 'mongodb_host',
    'database': 'your_database',
    'pool_size': 100,
    'min_pool_size': 20,
    'max_idle_time_ms': 60000,
    'wait_queue_timeout_ms': 2000,
    'connect_timeout_ms': 30000,
    'socket_timeout_ms': 45000
}

cache_config = {
    'enabled': True,
    'type': 'memory',
    'default_ttl': 300,
    'user_ttl': 30,  # Shorter TTL to ensure fresher data
    'security_events_ttl': 300,
    'cleanup_interval': 30  # More frequent cleanup
}

auth = DuoFlaskAuth(app, db_config=db_config, cache_config=cache_config)

# Check index health on startup
@app.before_first_request
def check_db_health():
    index_health = auth.check_database_indexes()
    app.logger.info(f"Database index health: {index_health['status']} ({index_health['health_percentage']}%)")
    if index_health.get('missing_indexes'):
        app.logger.warning(f"Missing indexes: {', '.join(index_health['missing_indexes'])}")
```

For very large applications, consider a distributed architecture with:

- Multiple application servers
- A load balancer
- Sharded MongoDB deployment
- Distributed cache like Redis (future release)
