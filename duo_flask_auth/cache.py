"""
Caching system for the Duo Flask Auth library.

This module provides caching functionality to improve performance
by reducing database queries for frequently accessed data.
"""

import time
import logging
import threading
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Callable, TypeVar, Generic, List, Tuple

T = TypeVar('T')

class CacheStats:
    """Statistics for cache performance monitoring."""

    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.clears = 0

    def hit(self):
        """Record a cache hit."""
        self.hits += 1

    def miss(self):
        """Record a cache miss."""
        self.misses += 1

    def set(self):
        """Record a cache set operation."""
        self.sets += 1

    def delete(self):
        """Record a cache delete operation."""
        self.deletes += 1

    def clear(self):
        """Record a cache clear operation."""
        self.clears += 1

    @property
    def hit_rate(self) -> float:
        """Calculate the cache hit rate."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0

    def __str__(self) -> str:
        """Get a string representation of the cache stats."""
        return (f"CacheStats(hits={self.hits}, misses={self.misses}, "
                f"sets={self.sets}, deletes={self.deletes}, "
                f"clears={self.clears}, hit_rate={self.hit_rate:.2f})")


class Cache(ABC, Generic[T]):
    """Abstract base class for cache implementations."""

    def __init__(self):
        self.stats = CacheStats()

    @abstractmethod
    def get(self, key: str) -> Optional[T]:
        """
        Get a value from the cache.

        Args:
            key: The cache key

        Returns:
            The cached value, or None if not found or expired
        """
        pass

    @abstractmethod
    def set(self, key: str, value: T, ttl: int = 300) -> None:
        """
        Set a value in the cache.

        Args:
            key: The cache key
            value: The value to cache
            ttl: Time to live in seconds (default: 300s / 5min)
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> None:
        """
        Delete a value from the cache.

        Args:
            key: The cache key
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear all cached values."""
        pass

    @abstractmethod
    def get_keys(self) -> List[str]:
        """
        Get all keys in the cache.

        Returns:
            List of cache keys
        """
        pass

    def get_or_set(self, key: str, callback: Callable[[], T], ttl: int = 300) -> T:
        """
        Get a value from the cache, or set it if not found.

        Args:
            key: The cache key
            callback: Function to call to get the value if not in cache
            ttl: Time to live in seconds (default: 300s / 5min)

        Returns:
            The cached or computed value
        """
        value = self.get(key)
        if value is None:
            value = callback()
            if value is not None:
                self.set(key, value, ttl)
        return value

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        return self.stats


class MemoryCache(Cache[T]):
    """Simple in-memory cache implementation with TTL."""

    def __init__(self, default_ttl: int = 300, cleanup_interval: int = 60):
        """
        Initialize the memory cache.

        Args:
            default_ttl: Default time to live in seconds (default: 300s / 5min)
            cleanup_interval: Interval in seconds for cleanup (default: 60s)
        """
        super().__init__()
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        self.lock = threading.RLock()
        self.logger = logging.getLogger("duo_flask_auth.cache.MemoryCache")

        # Start cleanup thread
        self.cleanup_interval = cleanup_interval
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def _cleanup_loop(self):
        """Background thread to clean up expired entries."""
        while True:
            try:
                time.sleep(self.cleanup_interval)
                self._cleanup_expired()
            except Exception as e:
                self.logger.error(f"Error in cache cleanup: {e}")

    def _cleanup_expired(self):
        """Remove all expired entries from the cache."""
        now = time.time()
        with self.lock:
            expired_keys = [key for key, entry in self.cache.items()
                           if entry["expires"] < now]
            for key in expired_keys:
                del self.cache[key]

            if expired_keys:
                self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")

    def get(self, key: str) -> Optional[T]:
        """
        Get a value from the cache.

        Args:
            key: The cache key

        Returns:
            The cached value, or None if not found or expired
        """
        with self.lock:
            if key not in self.cache:
                self.stats.miss()
                return None

            entry = self.cache[key]
            if entry["expires"] < time.time():
                # Remove expired entry
                del self.cache[key]
                self.stats.miss()
                return None

            self.logger.debug(f"Cache hit: {key}")
            self.stats.hit()
            return entry["value"]

    def set(self, key: str, value: T, ttl: int = None) -> None:
        """
        Set a value in the cache.

        Args:
            key: The cache key
            value: The value to cache
            ttl: Time to live in seconds (default: use default_ttl)
        """
        if ttl is None:
            ttl = self.default_ttl

        with self.lock:
            self.cache[key] = {
                "value": value,
                "expires": time.time() + ttl
            }
            self.logger.debug(f"Cache set: {key}, TTL: {ttl}s")
            self.stats.set()

    def delete(self, key: str) -> None:
        """
        Delete a value from the cache.

        Args:
            key: The cache key
        """
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                self.logger.debug(f"Cache delete: {key}")
                self.stats.delete()

    def clear(self) -> None:
        """Clear all cached values."""
        with self.lock:
            self.cache.clear()
            self.logger.debug("Cache cleared")
            self.stats.clear()

    def get_keys(self) -> List[str]:
        """
        Get all keys in the cache.

        Returns:
            List of cache keys
        """
        with self.lock:
            return list(self.cache.keys())

    def get_metadata(self) -> List[Tuple[str, float, int]]:
        """
        Get metadata about cached items.

        Returns:
            List of tuples containing (key, expiry_time, ttl_remaining)
        """
        now = time.time()
        with self.lock:
            return [(key, entry["expires"], int(entry["expires"] - now))
                   for key, entry in self.cache.items()]


class NoCache(Cache[T]):
    """Dummy cache implementation that doesn't actually cache anything."""

    def get(self, key: str) -> Optional[T]:
        self.stats.miss()
        return None

    def set(self, key: str, value: T, ttl: int = 300) -> None:
        self.stats.set()
        pass

    def delete(self, key: str) -> None:
        self.stats.delete()
        pass

    def clear(self) -> None:
        self.stats.clear()
        pass

    def get_keys(self) -> List[str]:
        return []