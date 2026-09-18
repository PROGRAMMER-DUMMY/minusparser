"""Model Context Protocol (MCP) server for MinusParser.

Exposes discover_content, read_web_article, read_feed_article, and quarantine_web_article
as MCP tools and resource://article/{article_id} as an air-gapped resource.
"""

import logging
import os

from mcp.server.fastmcp import FastMCP

from .discovery import DiscoveryEngine
from .errors import ToolError
from .extractor import ContentExtractor
from .http_client import HardenedClient, PayloadTooLargeError
from .registry import ResourceRegistry, SQLiteResourceRegistry
from .security import SSRFError, sanitize_content

mcp = FastMCP("DomainContentReader")
logger = logging.getLogger("domain-content-reader")


def init_registry() -> ResourceRegistry:
    """Initialize ResourceRegistry backend configured via MINUSPARSER_STORAGE_BACKEND."""
    backend = os.environ.get("MINUSPARSER_STORAGE_BACKEND", "sqlite").lower().strip()
    if backend == "memory":
        logger.info("Using in-memory ResourceRegistry")
        return ResourceRegistry()
    db_path = os.environ.get("MINUSPARSER_DB_PATH", None)
    logger.info("Using persistent SQLiteResourceRegistry (db_path=%s)", db_path)
    return SQLiteResourceRegistry(db_path=db_path)


# Resource Registry for air-gapped untrusted web payloads
resource_registry = init_registry()


@mcp.tool()
async def discover_content(
    url: str,
    query: str | None = None,
    category: str | None = None,
    limit: int = 10,
) -> dict:
    """Discover articles and content on any website. Automatically negotiates Tier 0 machine-native /llms.txt, RSS/Atom feeds, and sitemaps. Use this to find what's available before reading specific articles.

    Args:
        url: Any website URL (e.g., 'https://www.databricks.com/blog' or domain root)
        query: Optional keyword to filter results by title/summary
        category: Optional category/tag name to filter by
        limit: Maximum number of results to return (default 10)
    """
    try:
        async with HardenedClient() as client:
            engine = DiscoveryEngine(client)
            result = await engine.discover(url, query, category, limit)

            output = {
                "items": [
                    {
                        "title": item.title,
                        "url": item.url,
                        "published": item.published,
                        "summary": item.summary,
                        "categories": item.categories,
                        "has_full_content": item.full_content is not None and len(item.full_content) > 0,
                        "source_strategy": item.source_strategy,
                    }
                    for item in result.items
                ],
                "strategy_used": result.strategy_used,
                "feed_url": result.feed_url,
            }
            if not result.items:
                output["fallback_hints"] = result.fallback_hints
            return output
    except SSRFError as e:
        return ToolError(error_type="ssrf_blocked", message=str(e), url=e.url).to_dict()
    except Exception as e:
        logger.exception("Error discovering content")
        return {"error": "discovery_failed", "message": str(e)}


@mcp.tool()
async def read_web_article(
    url: str,
    max_chars: int = 10000,
    prefer_markdown: bool = True,
    wrap_provenance: bool = False,
    defang_all_images: bool = False,
) -> dict:
    """Fetch and read the full content of any web article or blog post with enterprise security guardrails.

    Protects against:
    - Indirect prompt injections & system override attempts
    - Leaked credentials, API keys (AWS, GitHub, OpenAI, Anthropic), and passwords
    - Dangerous remote shell execution pipes (curl|bash, powershell memory execution)
    - SSRF attacks against internal network metadata and 0-TTL DNS rebinding
    - Tracking pixels and markdown image exfiltration channels

    Args:
        url: The full URL of the article to read
        max_chars: Maximum characters to return (default 10000, prevents context window flooding)
        prefer_markdown: If True, returns markdown-formatted text; if False, plain text
        wrap_provenance: If True, wraps content in an explicit <untrusted_web_content> boundary fence
        defang_all_images: If True, defangs all external images in the content
    """
    try:
        async with HardenedClient() as client:
            extractor = ContentExtractor(client)
            result = await extractor.extract(
                url,
                max_chars=max_chars,
                prefer_markdown=prefer_markdown,
                wrap_provenance=wrap_provenance,
                defang_all_images=defang_all_images,
            )
            return {
                "url": result.url,
                "title": result.title,
                "content": result.content,
                "content_format": result.content_format,
                "is_truncated": result.is_truncated,
                "total_length": result.total_length,
                "guardrails": result.guardrails,
                "internal_links": result.internal_links,
            }
    except SSRFError as e:
        return {"error": "ssrf_blocked", "message": str(e)}
    except PayloadTooLargeError as e:
        return {"error": "payload_too_large", "message": str(e), "hint": "Try reducing the page size or checking if it's a media file."}
    except Exception as e:
        logger.exception("Error reading article")
        return {"error": "extraction_failed", "message": str(e)}


@mcp.tool()
async def read_feed_article(
    url: str,
    feed_content: str | None = None,
    max_chars: int = 10000,
    prefer_markdown: bool = True,
    wrap_provenance: bool = False,
    defang_all_images: bool = False,
) -> dict:
    """Read an article discovered via discover_content. If the feed provided full content, uses it directly with security guardrails.

    Args:
        url: The article URL
        feed_content: Optional pre-fetched content from RSS feed
        max_chars: Maximum characters to return
        prefer_markdown: If True, returns markdown format
        wrap_provenance: If True, wraps content in an untrusted boundary fence
        defang_all_images: If True, defangs all external images in the content
    """
    try:
        async with HardenedClient() as client:
            extractor = ContentExtractor(client)
            if feed_content:
                result = extractor.extract_from_feed_content(
                    url,
                    feed_content,
                    max_chars=max_chars,
                    wrap_provenance=wrap_provenance,
                    defang_all_images=defang_all_images,
                )
            else:
                result = await extractor.extract(
                    url,
                    max_chars=max_chars,
                    prefer_markdown=prefer_markdown,
                    wrap_provenance=wrap_provenance,
                    defang_all_images=defang_all_images,
                )

            return {
                "url": result.url,
                "title": result.title,
                "content": result.content,
                "content_format": result.content_format,
                "is_truncated": result.is_truncated,
                "total_length": result.total_length,
                "guardrails": result.guardrails,
            }
    except SSRFError as e:
        return {"error": "ssrf_blocked", "message": str(e)}
    except PayloadTooLargeError as e:
        return {"error": "payload_too_large", "message": str(e)}
    except Exception as e:
        logger.exception("Error reading feed article")
        return {"error": "extraction_failed", "message": str(e)}


@mcp.resource("resource://article/{article_id}", mime_type="text/markdown")
def get_quarantined_article(article_id: str) -> str:
    """Fetch quarantined untrusted web article content out-of-band by article ID.

    Allows unprivileged reader agents to read the untrusted payload via its resource URI
    without dumping raw text into a privileged agent's instruction context.
    """
    content = resource_registry.get_content(article_id)
    if content is None:
        raise ValueError(f"Quarantined article not found: {article_id}")
    return content


@mcp.tool()
async def quarantine_web_article(
    url: str,
    content: str | None = None,
    prefer_markdown: bool = True,
    defang_all_images: bool = False,
) -> dict:
    """Fetch and quarantine any web article, storing content in an air-gapped MCP resource.

    Protects privileged agent contexts against indirect prompt injection (IPI) by returning
    ONLY an opaque handle with essential metadata. Unprivileged reader agents can then
    safely inspect the content out-of-band using the returned resource_uri.

    Args:
        url: The full URL of the article to quarantine
        content: Optional raw content to quarantine directly without network fetching
        prefer_markdown: If True, returns markdown-formatted text; if False, plain text
        defang_all_images: If True, defangs all external images in the content
    """
    try:
        if content is not None:
            clean_content, report = sanitize_content(content, source_url=url, wrap_provenance=True, defang_all_images=defang_all_images)
            article_id = resource_registry.store(
                content=clean_content,
                url=url,
                title="Quarantined Web Payload",
                content_format="markdown" if prefer_markdown else "text",
                total_length=len(clean_content),
                guardrails=report.to_dict(),
                internal_links=[],
            )
            record = resource_registry.get(article_id)
            if record:
                return record.to_handle()
            return {
                "status": "quarantined",
                "article_id": article_id,
                "resource_uri": f"resource://article/{article_id}",
                "title": "Quarantined Web Payload",
                "url": url,
                "char_count": len(clean_content),
                "guardrails": report.to_dict(),
                "internal_links": [],
                "message": "Content stored in air-gapped MCP resource. Read via Quarantined Worker using resource_uri.",
            }

        async with HardenedClient() as client:
            extractor = ContentExtractor(client)
            result = await extractor.extract(
                url,
                prefer_markdown=prefer_markdown,
                defang_all_images=defang_all_images,
            )
            article_id = resource_registry.store(
                content=result.content,
                url=result.url,
                title=result.title,
                content_format=result.content_format,
                total_length=result.total_length,
                guardrails=result.guardrails,
                internal_links=result.internal_links,
            )
            record = resource_registry.get(article_id)
            if record:
                return record.to_handle()
            return {
                "status": "quarantined",
                "article_id": article_id,
                "resource_uri": f"resource://article/{article_id}",
                "title": result.title,
                "url": result.url,
                "char_count": result.total_length,
                "guardrails": result.guardrails,
                "internal_links": result.internal_links[:5],
                "message": "Content stored in air-gapped MCP resource. Read via Quarantined Worker using resource_uri.",
            }
    except SSRFError as e:
        return {"error": "ssrf_blocked", "message": str(e)}
    except PayloadTooLargeError as e:
        return {"error": "payload_too_large", "message": str(e), "hint": "Try reducing the page size or checking if it's a media file."}
    except Exception as e:
        logger.exception("Error quarantining article")
        return {"error": "extraction_failed", "message": str(e)}


if __name__ == "__main__":
    mcp.run()
