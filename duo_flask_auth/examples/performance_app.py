"""
Example Flask application with performance optimizations for Duo Flask Auth

This example demonstrates how to configure and use the Duo Flask Auth library
with performance optimizations for high-traffic applications.
"""

import os
import time
from datetime import datetime

from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from duo_flask_auth import DuoFlaskAuth

# Create the Flask app
app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "replace-with-strong-secret-key-in-production"
)

# Performance optimized database config with connection pooling
db_config = {
    "username": os.environ.get("MONGO_USERNAME", "mongodb_username"),
    "password": os.environ.get("MONGO_PASSWORD", "mongodb_password"),
    "host": os.environ.get("MONGO_HOST", "cluster0.example.mongodb.net"),
    "database": os.environ.get("MONGO_DATABASE", "auth-db"),
    # Connection pooling configuration
    "pool_size": int(os.environ.get("MONGO_POOL_SIZE", 50)),
    "min_pool_size": int(os.environ.get("MONGO_MIN_POOL_SIZE", 10)),
    "max_idle_time_ms": int(os.environ.get("MONGO_MAX_IDLE_TIME_MS", 60000)),
    "wait_queue_timeout_ms": int(os.environ.get("MONGO_WAIT_QUEUE_TIMEOUT_MS", 2000)),
    "connect_timeout_ms": int(os.environ.get("MONGO_CONNECT_TIMEOUT_MS", 30000)),
    "socket_timeout_ms": int(os.environ.get("MONGO_SOCKET_TIMEOUT_MS", 45000)),
}

# Configure Duo MFA (optional)
duo_config = {
    "client_id": os.environ.get("DUO_CLIENT_ID"),
    "client_secret": os.environ.get("DUO_CLIENT_SECRET"),
    "api_host": os.environ.get("DUO_API_HOST"),
    "redirect_uri": os.environ.get("DUO_REDIRECT_URI"),
}

# Cache configuration
cache_config = {
    "enabled": True,
    "type": "memory",
    "default_ttl": int(os.environ.get("CACHE_DEFAULT_TTL", 300)),
    "user_ttl": int(os.environ.get("CACHE_USER_TTL", 60)),
    "security_events_ttl": int(os.environ.get("CACHE_SECURITY_EVENTS_TTL", 300)),
    "cleanup_interval": int(os.environ.get("CACHE_CLEANUP_INTERVAL", 60)),
}

# Security configurations (as in secure_app.py)
rate_limit_config = {
    "enabled": True,
    "max_attempts": {"login": 5, "password_reset": 3},
    "window_seconds": {"login": 300, "password_reset": 600},
}

account_lockout_config = {
    "enabled": True,
    "max_attempts": 5,
    "lockout_duration": 1800,
    "lockout_reset_on_success": True,
}

password_policy = {
    "min_length": 10,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_special": True,
    "max_age_days": 90,
}

# Initialize the authentication library with performance enhancements
auth = DuoFlaskAuth(
    app,
    db_config=db_config,
    duo_config=duo_config,
    cache_config=cache_config,
    rate_limit_config=rate_limit_config,
    account_lockout_config=account_lockout_config,
    password_policy=password_policy,
)

# Performance metrics tracking
performance_metrics = {
    "request_times": [],
    "login_times": [],
    "database_accesses": 0,
    "cache_hits": 0,
    "cache_misses": 0,
}


# Check database index health on startup
@app.before_first_request
def check_db_health():
    """Check database index health at application startup."""
    index_health = auth.check_database_indexes()
    app.logger.info(
        f"Database index health: {index_health['status']} ({index_health['health_percentage']}%)"
    )

    if index_health.get("missing_indexes"):
        app.logger.warning(
            f"Missing indexes: {', '.join(index_health['missing_indexes'])}"
        )


# Request timing middleware
@app.before_request
def start_timer():
    """Record request start time."""
    request.start_time = time.time()


@app.after_request
def record_request_time(response):
    """Record request processing time."""
    if hasattr(request, "start_time"):
        request_time = time.time() - request.start_time

        # Only keep the last 1000 request times
        performance_metrics["request_times"].append(request_time)
        if len(performance_metrics["request_times"]) > 1000:
            performance_metrics["request_times"].pop(0)

        # Add timing header
        response.headers["X-Request-Time"] = str(request_time)

    return response


# Override the login_success route
@app.route("/login-success")
def login_success():
    """Handle successful login redirection with timing."""
    # Log the successful login event with additional context
    auth.log_security_event(
        event_type="login_success",
        username=current_user.username,
        details={
            "method": "password" if not current_user.mfa_enabled else "password_and_mfa"
        },
    )

    # Check if this is first login (never logged in before)
    if current_user.last_login is None:
        flash("Welcome! This appears to be your first login.", "info")

    return redirect(url_for("dashboard"))


@app.route("/")
def home():
    """Home page route."""
    return render_template("home.html")


@app.route("/dashboard")
@login_required
def dashboard():
    """Dashboard route (protected)."""
    return render_template("dashboard.html", user=current_user)


@app.route("/admin")
@login_required
def admin_panel():
    """Admin panel route (protected and role-restricted)."""
    # Check if the user has admin role
    if not current_user.role == "admin":
        auth.log_security_event(
            event_type="unauthorized_access",
            username=current_user.username,
            details={"resource": "admin_panel", "required_role": "admin"},
        )

        flash("You don't have permission to access the admin panel.", "error")
        return redirect(url_for("dashboard"))

    return render_template("admin/dashboard.html")


@app.route("/admin/users")
@login_required
def admin_users():
    """Admin user management panel."""
    # Check if the user has admin role
    if not current_user.role == "admin":
        return redirect(url_for("dashboard"))

    # Get users from the database
    users = auth.db_adapter.db["users"].find().limit(100)
    return render_template("admin/users.html", users=list(users))


@app.route("/admin/performance")
@login_required
def performance_dashboard():
    """Performance monitoring dashboard."""
    # Check if the user has admin role
    if not current_user.role == "admin":
        return redirect(url_for("dashboard"))

    # Get cache statistics
    cache_stats = auth.get_cache_stats()

    # Get database index health
    index_health = auth.check_database_indexes()

    # Calculate performance metrics
    avg_request_time = (
        sum(performance_metrics["request_times"])
        / len(performance_metrics["request_times"])
        if performance_metrics["request_times"]
        else 0
    )
    avg_login_time = (
        sum(performance_metrics["login_times"])
        / len(performance_metrics["login_times"])
        if performance_metrics["login_times"]
        else 0
    )

    return render_template(
        "admin/performance.html",
        cache_stats=cache_stats,
        index_health=index_health,
        avg_request_time=avg_request_time,
        avg_login_time=avg_login_time,
        database_accesses=performance_metrics["database_accesses"],
    )


@app.route("/admin/cache")
@login_required
def cache_dashboard():
    """Cache monitoring dashboard."""
    # Check if the user has admin role
    if not current_user.role == "admin":
        return redirect(url_for("dashboard"))

    # Get cache statistics
    cache_stats = auth.get_cache_stats()

    # Get cached keys if possible
    cached_keys = []
    if hasattr(auth.cache, "get_keys"):
        cached_keys = auth.cache.get_keys()

    # Get metadata if possible
    metadata = []
    if hasattr(auth.cache, "get_metadata"):
        metadata = auth.cache.get_metadata()

    return render_template(
        "admin/cache.html",
        cache_stats=cache_stats,
        cached_keys=cached_keys,
        metadata=metadata,
    )


@app.route("/admin/clear-cache", methods=["POST"])
@login_required
def clear_cache():
    """Clear the cache."""
    # Check if the user has admin role
    if not current_user.role == "admin":
        return redirect(url_for("dashboard"))

    # Clear the cache
    auth.cache.clear()
    flash("Cache cleared successfully.", "success")

    return redirect(url_for("cache_dashboard"))


# API endpoints for monitoring
@app.route("/api/health")
def health_check():
    """Health check endpoint."""
    # Check database connection
    db_healthy = False
    if auth.db_adapter and hasattr(auth.db_adapter, "client"):
        try:
            # Try to ping the database
            auth.db_adapter.client.admin.command("ping")
            db_healthy = True
        except:
            db_healthy = False

    # Check cache
    cache_healthy = hasattr(auth.cache, "get") and hasattr(auth.cache, "set")

    # Calculate overall health
    overall_healthy = db_healthy and cache_healthy

    return jsonify(
        {
            "status": "healthy" if overall_healthy else "unhealthy",
            "database": "connected" if db_healthy else "disconnected",
            "cache": "available" if cache_healthy else "unavailable",
            "timestamp": datetime.utcnow().isoformat(),
        }
    ), (200 if overall_healthy else 503)


@app.route("/api/performance")
def performance_check():
    """Performance metrics endpoint."""
    # Get cache statistics
    cache_stats = auth.get_cache_stats()

    # Calculate request time percentiles
    request_times = sorted(performance_metrics["request_times"])
    p50 = p95 = p99 = 0

    if request_times:
        p50 = request_times[len(request_times) // 2]
        p95 = request_times[int(len(request_times) * 0.95)]
        p99 = request_times[int(len(request_times) * 0.99)]

    return jsonify(
        {
            "request_times": {
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "count": len(request_times),
            },
            "cache": {
                "hit_rate": cache_stats.get("hit_rate", 0),
                "hits": cache_stats.get("hits", 0),
                "misses": cache_stats.get("misses", 0),
            },
            "db_accesses": performance_metrics["database_accesses"],
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    app.run(debug=True)
if __name__ == "__main__":
    app.run(debug=True)
