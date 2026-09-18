from dataclasses import dataclass, field
from typing import Any

@dataclass
class ToolError:
    """Structured error returned by MCP tools to help agents self-correct."""
    error_type: str          # e.g., 'feed_not_found', 'extraction_failed', 'ssrf_blocked', 'rate_limited'
    message: str             # Human-readable explanation
    url: str                 # The URL that caused the error
    fallback_hints: list[str] = field(default_factory=list)  # Actionable suggestions for the agent
    
    def to_dict(self) -> dict[str, Any]:
        return {
            'error': self.error_type,
            'message': self.message,
            'url': self.url,
            'fallback_hints': self.fallback_hints,
        }

def make_discovery_error(url: str, strategies_tried: list[str]) -> ToolError:
    """Creates a structured error when all discovery strategies fail."""
    hints = []
    if 'rss' in strategies_tried:
        hints.append('No RSS/Atom feed found.')
    if 'sitemap' in strategies_tried:
        hints.append('No sitemap.xml found.')
    hints.append(f'Try using read_web_article with a direct article URL from {url}')
    hints.append('Try providing a more specific URL (e.g., the /blog page).')
    return ToolError(
        error_type='discovery_failed',
        message=f'Could not discover content at {url} using any strategy.',
        url=url,
        fallback_hints=hints,
    )
