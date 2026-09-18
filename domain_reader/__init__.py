"""Domain Content Reader — MCP server for agentic web exploration.

A production-grade Model Context Protocol server that gives AI agents
the ability to discover and read content from any website using a
multi-strategy approach: RSS/Atom feeds → sitemaps → direct URLs.
"""

from .http_client import HardenedClient, PayloadTooLargeError
from .politeness import (
    RobotsDisallowedError,
    RateLimitError,
    RobotsChecker,
    DomainRateLimiter,
)
from .registry import ResourceRegistry, SQLiteResourceRegistry, QuarantinedArticle
from .safe_api import (
    safe_read,
    ArticleAnalysis,
    EpistemicTaintReport,
    get_taint_metadata,
    is_field_tainted,
    get_untrusted_fields,
)

__version__ = "0.9.0"

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
    "__version__",
]



