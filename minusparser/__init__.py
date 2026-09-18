"""MinusParser — High-performance local web ingress reader and sanitizer for AI agents."""

from domain_reader import (
    HardenedClient,
    PayloadTooLargeError,
    RobotsDisallowedError,
    RateLimitError,
    RobotsChecker,
    DomainRateLimiter,
    ResourceRegistry,
    SQLiteResourceRegistry,
    QuarantinedArticle,
    safe_read,
    ArticleAnalysis,
    EpistemicTaintReport,
    get_taint_metadata,
    is_field_tainted,
    get_untrusted_fields,
    __version__,
)
from domain_reader.security import SSRFError, GuardrailReport, sanitize_content
from domain_reader.discovery import DiscoveryEngine, ContentItem, DiscoveryResult
from domain_reader.extractor import ContentExtractor, ArticleContent

__all__ = [
    "HardenedClient",
    "PayloadTooLargeError",
    "RobotsDisallowedError",
    "RateLimitError",
    "RobotsChecker",
    "DomainRateLimiter",
    "ResourceRegistry",
    "SQLiteResourceRegistry",
    "QuarantinedArticle",
    "safe_read",
    "ArticleAnalysis",
    "EpistemicTaintReport",
    "get_taint_metadata",
    "is_field_tainted",
    "get_untrusted_fields",
    "SSRFError",
    "GuardrailReport",
    "sanitize_content",
    "DiscoveryEngine",
    "ContentItem",
    "DiscoveryResult",
    "ContentExtractor",
    "ArticleContent",
    "__version__",
]
