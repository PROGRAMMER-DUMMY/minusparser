"""Tests for top-level minusparser package, robots.txt politeness, rate limiting, and DoS safeguards."""

import asyncio
import io
import time
import pytest
import httpx

import minusparser
from minusparser import (
    safe_read,
    HardenedClient,
    RobotsChecker,
    DomainRateLimiter,
    RobotsDisallowedError,
    RateLimitError,
    PayloadTooLargeError,
    ArticleAnalysis,
    SQLiteResourceRegistry,
    ResourceRegistry,
    __version__,
)
from minusparser.cli import cli
from domain_reader.politeness import RobotsChecker, DomainRateLimiter


def test_top_level_package_exports():
    """Verify that import minusparser exposes all primary SDK primitives."""
    assert __version__ == "0.9.0"
    assert safe_read is not None
    assert HardenedClient is not None
    assert RobotsChecker is not None
    assert DomainRateLimiter is not None
    assert RobotsDisallowedError is not None
    assert RateLimitError is not None
    assert ArticleAnalysis is not None
    assert SQLiteResourceRegistry is not None
    assert ResourceRegistry is not None


@pytest.mark.asyncio
async def test_robots_checker_allow_and_disallow():
    """Test RobotsChecker parsing rules and caching."""
    checker = RobotsChecker(cache_ttl=60.0)

    # Mock response for robots.txt
    sample_robots = (
        "User-agent: *\n"
        "Disallow: /private/\n"
        "Disallow: /admin\n"
        "Allow: /public/\n"
    )

    domain = "https://example.com"
    robots_url = "https://example.com/robots.txt"

    # Pre-populate cache directly with parsed rules
    from urllib.robotparser import RobotFileParser
    parser = RobotFileParser()
    parser.set_url(robots_url)
    parser.parse(sample_robots.splitlines())
    checker._cache[domain] = (time.time(), parser)

    # Verify allowed vs disallowed paths
    assert await checker.is_allowed("https://example.com/public/doc") is True
    assert await checker.is_allowed("https://example.com/blog/article") is True
    assert await checker.is_allowed("https://example.com/private/secret") is False
    assert await checker.is_allowed("https://example.com/admin") is False


@pytest.mark.asyncio
async def test_domain_rate_limiter():
    """Test DomainRateLimiter delay enforcement between requests."""
    limiter = DomainRateLimiter(default_interval=0.1)

    t0 = time.time()
    await limiter.acquire("https://testdomain.com/page1")
    t1 = time.time()
    assert (t1 - t0) < 0.05  # First request is immediate

    await limiter.acquire("https://testdomain.com/page2")
    t2 = time.time()
    # Second request must wait at least 0.08s
    assert (t2 - t1) >= 0.08


@pytest.mark.asyncio
async def test_streaming_payload_limit_safeguard():
    """Verify that HardenedClient aborts when streaming decompressed payload exceeds max_payload_bytes."""
    
    # Mock transport that streams 300KB in chunks
    chunk = b"A" * 1024  # 1 KB
    total_chunks = 300     # 300 KB total

    async def mock_stream_handler(request: httpx.Request) -> httpx.Response:
        async def byte_generator():
            for _ in range(total_chunks):
                yield chunk
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=byte_generator(),
            request=request,
        )

    mock_transport = httpx.MockTransport(mock_stream_handler)

    # Set client max_payload_bytes to 50KB (51,200 bytes)
    async with HardenedClient(max_payload_bytes=51200, transport=mock_transport) as client:
        with pytest.raises(PayloadTooLargeError) as exc_info:
            await client.get("https://example.com/giant-article")

        assert "exceeded maximum payload size" in str(exc_info.value)
        assert exc_info.value.size > 51200


@pytest.mark.asyncio
async def test_rate_limit_429_retry_after():
    """Verify that HTTP 429 response raises RateLimitError with retry_after."""
    
    async def mock_429_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=429,
            headers={"Retry-After": "15"},
            content=b"Too Many Requests",
            request=request,
        )

    mock_transport = httpx.MockTransport(mock_429_handler)

    async with HardenedClient(transport=mock_transport) as client:
        with pytest.raises(RateLimitError) as exc_info:
            await client.get("https://example.com/busy-endpoint")

        assert exc_info.value.retry_after == 15
        assert "429 Too Many Requests" in str(exc_info.value)


@pytest.mark.asyncio
async def test_respect_robots_disallowed_raises():
    """Verify that respect_robots=True raises RobotsDisallowedError when path is blocked."""
    checker = RobotsChecker(cache_ttl=60.0)

    sample_robots = "User-agent: *\nDisallow: /restricted/\n"
    from urllib.robotparser import RobotFileParser
    parser = RobotFileParser()
    parser.set_url("https://example.com/robots.txt")
    parser.parse(sample_robots.splitlines())

    from domain_reader.politeness import default_robots_checker
    default_robots_checker._cache["https://example.com"] = (time.time(), parser)

    async with HardenedClient(respect_robots=True) as client:
        with pytest.raises(RobotsDisallowedError) as exc_info:
            await client.get("https://example.com/restricted/data")

        assert "disallowed by domain robots.txt" in str(exc_info.value)
