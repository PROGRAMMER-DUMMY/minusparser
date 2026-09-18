import ipaddress
import socket
import typing
import anyio
import httpcore
import httpx
from dataclasses import dataclass
from .security import validate_url, SSRFError, validate_ip_address, is_ip_blocked
from .politeness import (
    RobotsDisallowedError,
    RateLimitError,
    default_robots_checker,
    default_rate_limiter,
)

@dataclass
class CacheInfo:
    etag: str | None
    last_modified: str | None
    was_cached: bool

class PayloadTooLargeError(Exception):
    """Exception raised when the HTTP response payload exceeds the maximum allowed size."""
    def __init__(self, message: str, url: str, size: int):
        super().__init__(message)
        self.message = message
        self.url = url
        self.size = size

class PinnedNetworkBackend(httpcore.AnyIOBackend):
    """
    Network backend that resolves DNS and pins the validated IP address for every TCP connection,
    eliminating 0-TTL Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding SSRF vulnerabilities.
    """
    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            ip = ipaddress.ip_address(host)
            validate_ip_address(ip, host)
            validated_ips = [host]
        except ValueError:
            try:
                addrinfo = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except Exception as e:
                raise SSRFError(f"DNS resolution failed for hostname '{host}': {e}", host)

            if not addrinfo:
                raise SSRFError(f"No DNS records found for hostname '{host}'", host)

            validated_ips = []
            for res in addrinfo:
                ip_str = res[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                validate_ip_address(ip, host)
                if ip_str not in validated_ips:
                    validated_ips.append(ip_str)

            if not validated_ips:
                raise SSRFError(f"Hostname '{host}' did not resolve to any valid IP addresses", host)

        last_exc = None
        for pinned_ip in validated_ips:
            try:
                return await super().connect_tcp(
                    host=pinned_ip,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_exc = exc
                continue

        if last_exc:
            raise last_exc
        raise httpcore.ConnectError(f"Failed to connect to {host}:{port}")

class PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """
    HTTPX Async Transport that pins the resolved IP address for every TCP connection,
    preventing 0-TTL DNS rebinding SSRF attacks while preserving the original SNI hostname
    for TLS verification and Host header.
    """
    def __init__(
        self,
        *args,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._network_backend = network_backend or PinnedNetworkBackend()
        self._pool._network_backend = self._network_backend

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Guarantee SNI hostname extension matches original host for TLS verification
        request.extensions.setdefault("sni_hostname", request.url.host)
        return await super().handle_async_request(request)

class HardenedClient:
    """A hardened HTTP client with SSRF protection, IP pinning against DNS rebinding, and payload limits."""
    
    def __init__(
        self, 
        timeout: float = 8.0, 
        max_payload_bytes: int = 2_097_152, 
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        transport: httpx.AsyncHTTPTransport | None = None,
        limits: httpx.Limits | None = None,
        respect_robots: bool = False,
        rate_limit_delay: float = 0.0,
    ):
        self.timeout = timeout
        self.max_payload_bytes = max_payload_bytes
        self.user_agent = user_agent
        self.custom_transport = transport
        self.limits = limits or httpx.Limits(
            max_keepalive_connections=20,
            max_connections=50,
            keepalive_expiry=30.0,
        )
        self.respect_robots = respect_robots
        self.rate_limit_delay = rate_limit_delay
        self._transport: httpx.AsyncHTTPTransport | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._transport = self.custom_transport or PinnedAsyncHTTPTransport(
            verify=True,
            http1=True,
            http2=False,
            limits=self.limits,
        )
        self._client = httpx.AsyncClient(
            transport=self._transport,
            timeout=self.timeout,
            follow_redirects=False,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
            },
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
            self._client = None
        self._transport = None

    async def _make_request(
        self,
        url: str,
        headers: dict | None = None,
        skip_robots: bool = False,
    ) -> httpx.Response:
        """Internal helper to make requests, enforce robots.txt, rate limit, follow redirects, and stream limits."""
        if not self._client:
            raise RuntimeError("HardenedClient must be used as an async context manager")
            
        # Syntactic and IP/DNS validation; socket DNS pinning handles low-level connect
        validate_url(url)

        # Politeness Check: Robots.txt compliance
        if self.respect_robots and not skip_robots and not url.lower().endswith("/robots.txt"):
            allowed = await default_robots_checker.is_allowed(
                url,
                user_agent=self.user_agent,
                http_client=self,
            )
            if not allowed:
                raise RobotsDisallowedError(
                    f"Fetching URL is disallowed by domain robots.txt: {url}",
                    url=url,
                    user_agent=self.user_agent,
                )

        # Politeness Check: Per-domain request rate limiting
        if self.rate_limit_delay > 0:
            await default_rate_limiter.acquire(url, self.rate_limit_delay)
        
        req_headers = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)
            
        current_url = url
        response = None
        
        # Follow up to 5 redirects manually to check SSRF on each jump
        for _ in range(6):
            async with self._client.stream("GET", current_url, headers=req_headers) as resp:
                if resp.is_redirect:
                    next_url = resp.headers.get("location")
                    if not next_url:
                        break
                    
                    # Resolve relative redirects
                    next_url = str(resp.url.join(next_url))
                    
                    # SSRF validation on redirect target
                    validate_url(next_url)
                    current_url = next_url
                    continue

                # Egress hygiene: HTTP 429 Too Many Requests with Retry-After
                if resp.status_code == 429:
                    retry_after = resp.headers.get("retry-after")
                    retry_after_int = int(retry_after) if (retry_after and retry_after.isdigit()) else None
                    raise RateLimitError(
                        f"Target host returned HTTP 429 Too Many Requests. Retry-After: {retry_after or 'unspecified'}",
                        url=current_url,
                        retry_after=retry_after_int,
                    )

                # DoS Safeguard: Upfront Content-Length check
                content_length = resp.headers.get("content-length")
                if content_length and content_length.isdigit() and int(content_length) > self.max_payload_bytes:
                    raise PayloadTooLargeError(
                        f"Response Content-Length ({content_length} bytes) exceeds maximum payload size of {self.max_payload_bytes} bytes",
                        current_url,
                        int(content_length),
                    )

                # DoS Safeguard: Stream decompressed chunks with threshold to defeat gzip/compression bombs
                body_parts = []
                total_bytes = 0
                async for chunk in resp.aiter_bytes():
                    total_bytes += len(chunk)
                    if total_bytes > self.max_payload_bytes:
                        raise PayloadTooLargeError(
                            f"Response exceeded maximum payload size of {self.max_payload_bytes} bytes (decompression bomb or oversized stream)",
                            current_url,
                            total_bytes,
                        )
                    body_parts.append(chunk)

                content = b"".join(body_parts)
                # Strip content-encoding and content-length since aiter_bytes() has already decompressed the stream
                clean_headers = dict(resp.headers)
                clean_headers.pop("content-encoding", None)
                clean_headers.pop("content-length", None)
                response = httpx.Response(
                    status_code=resp.status_code,
                    headers=clean_headers,
                    content=content,
                    request=resp.request,
                    extensions=resp.extensions,
                )
                break
                
        if response is None or response.is_redirect:
            raise httpx.TooManyRedirects("Exceeded maximum redirects (5)")
            
        return response

    async def get(self, url: str, headers: dict | None = None) -> httpx.Response:
        """Make a GET request with SSRF protection and payload limits."""
        return await self._make_request(url, headers)

    async def get_with_cache(self, url: str, etag: str | None = None, last_modified: str | None = None) -> tuple[httpx.Response, CacheInfo]:
        """Make a GET request including caching headers, returning cache information."""
        headers = {}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
            
        response = await self._make_request(url, headers)
        
        was_cached = response.status_code == 304
        new_etag = response.headers.get("etag")
        new_last_modified = response.headers.get("last-modified")
        
        cache_info = CacheInfo(etag=new_etag, last_modified=new_last_modified, was_cached=was_cached)
        return response, cache_info
