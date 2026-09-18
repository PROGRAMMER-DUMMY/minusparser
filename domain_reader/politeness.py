"""
Web politeness, crawler hygiene, and rate-limiting safeguards.

Provides robots.txt compliance checking, domain rate limiting, and HTTP 429
Retry-After backoff handling to prevent agents from triggering IP bans.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser

logger = logging.getLogger(__name__)


class RobotsDisallowedError(Exception):
    """Raised when fetching a URL is disallowed by the target domain's robots.txt."""

    def __init__(self, message: str, url: str, user_agent: str = "*"):
        super().__init__(message)
        self.message = message
        self.url = url
        self.user_agent = user_agent


class RateLimitError(Exception):
    """Raised when the target host responds with HTTP 429 Too Many Requests."""

    def __init__(self, message: str, url: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.url = url
        self.retry_after = retry_after


class RobotsChecker:
    """
    Asynchronous robots.txt checker with in-memory TTL caching.
    Safely retrieves and parses robots.txt to respect web crawler politeness rules.
    """

    def __init__(self, cache_ttl: float = 3600.0):
        self.cache_ttl = cache_ttl
        # domain -> (timestamp, RobotFileParser)
        self._cache: Dict[str, Tuple[float, RobotFileParser]] = {}
        self._lock = asyncio.Lock()

    def _get_robots_url(self, target_url: str) -> Tuple[str, str]:
        parsed = urlparse(target_url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(domain, "/robots.txt")
        return domain, robots_url

    async def is_allowed(
        self,
        url: str,
        user_agent: str = "*",
        http_client: Optional[Any] = None,
    ) -> bool:
        """
        Check if the specified URL is allowed by robots.txt for the given user-agent.
        If robots.txt cannot be retrieved (404, connection error, etc.), web standard
        convention defaults to allowing access.
        """
        domain, robots_url = self._get_robots_url(url)
        now = time.time()

        async with self._lock:
            cached = self._cache.get(domain)
            if cached and (now - cached[0]) < self.cache_ttl:
                return cached[1].can_fetch(user_agent, url)

        # Need to fetch robots.txt
        parser = RobotFileParser()
        parser.set_url(robots_url)

        try:
            content = None
            if http_client is not None:
                # Use provided hardened client
                try:
                    resp = await http_client.get(robots_url)
                    if resp.status_code == 200:
                        content = resp.text
                    elif resp.status_code in (401, 403):
                        # Restricted robots.txt -> disallow all by default
                        parser.parse(["User-agent: *", "Disallow: /"])
                        async with self._lock:
                            self._cache[domain] = (now, parser)
                        return False
                except Exception as e:
                    logger.debug("Could not fetch robots.txt via client for %s: %s", domain, e)
            
            if content:
                parser.parse(content.splitlines())
            else:
                # If robots.txt returned 404 or empty, allow all
                parser.allow_all = True
        except Exception as e:
            logger.debug("Robots.txt check failed for %s (allowing by default): %s", domain, e)
            parser.allow_all = True

        async with self._lock:
            self._cache[domain] = (now, parser)

        return parser.can_fetch(user_agent, url)


class DomainRateLimiter:
    """
    In-memory per-domain rate limiter enforcing minimum delays between outbound requests.
    """

    def __init__(self, default_interval: float = 0.5):
        self.default_interval = default_interval
        # domain -> last_request_timestamp
        self._last_access: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, target_url: str, interval: Optional[float] = None) -> None:
        """Wait if necessary to ensure interval seconds have passed since the last request to this domain."""
        parsed = urlparse(target_url)
        domain = parsed.netloc.lower()
        required_delay = interval if interval is not None else self.default_interval

        if required_delay <= 0:
            return

        async with self._lock:
            now = time.time()
            last_time = self._last_access.get(domain, 0.0)
            elapsed = now - last_time
            wait_time = required_delay - elapsed

            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self._last_access[domain] = time.time()
            else:
                self._last_access[domain] = now


# Shared default instances
default_robots_checker = RobotsChecker()
default_rate_limiter = DomainRateLimiter()
