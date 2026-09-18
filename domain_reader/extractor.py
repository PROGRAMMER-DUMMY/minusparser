import html
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from bs4 import BeautifulSoup
import trafilatura

from .http_client import HardenedClient, PayloadTooLargeError
from .security import sanitize_content, GuardrailReport, SSRFError

logger = logging.getLogger(__name__)


@dataclass
class ArticleContent:
    """Result of content extraction."""
    url: str
    title: Optional[str]
    content: str
    content_format: str
    is_truncated: bool
    total_length: int
    extraction_method: str
    guardrails: dict = field(default_factory=dict)
    internal_links: list[dict] = field(default_factory=list)
    is_spa_shell: bool = False
    spa_advisory: Optional[str] = None


class ContentExtractor:
    """Extracts article content from URLs and feeds using trafilatura with graceful fallbacks and smart security guardrails."""

    def __init__(self, client: HardenedClient, default_max_chars: int = 10_000) -> None:
        """
        Initialize the ContentExtractor.
        
        Args:
            client: The HTTP client for fetching content.
            default_max_chars: Default maximum length for extracted text.
        """
        self.client = client
        self.default_max_chars = default_max_chars

    async def extract(
        self,
        url: str,
        max_chars: Optional[int] = None,
        prefer_markdown: bool = True,
        wrap_provenance: bool = False,
        defang_all_images: bool = False,
    ) -> ArticleContent:
        """
        Extract article content from a URL with smart guardrails and internal link navigation.
        
        Args:
            url: The URL to extract from.
            max_chars: Maximum characters to return. Defaults to instance default.
            prefer_markdown: Whether to prefer markdown over plain text.
            wrap_provenance: If True, wraps content in an explicit provenance boundary fence.
            
        Returns:
            ArticleContent object containing the sanitized text, security report, and internal links.
        """
        max_c = max_chars if max_chars is not None else self.default_max_chars
        fmt = 'markdown' if prefer_markdown else 'text'
        method = 'trafilatura'

        try:
            response = await self.client.get(url)
            html_content = response.text
        except (SSRFError, PayloadTooLargeError):
            raise
        except Exception as e:
            logger.error(f"Failed to fetch {url}: {e}")
            html_content = ""

        title = None
        content = ""
        internal_links: list[dict] = []

        if html_content:
            # Extract domain-scoped internal navigation links
            try:
                internal_links = self._extract_internal_links(html_content, url, max_links=25)
            except Exception as e:
                logger.warning(f"Failed to extract internal links for {url}: {e}")

            # Try trafilatura extraction
            try:
                extracted = trafilatura.extract(
                    html_content,
                    output_format=fmt,
                    include_comments=False,
                    include_tables=True,
                    no_fallback=False
                )
                if extracted:
                    content = extracted
                else:
                    raise ValueError("trafilatura returned None")
            except Exception as e:
                logger.warning(f"trafilatura extract failed for {url}: {e}")
                method = 'fallback'
                content = self._strip_html_fallback(html_content)
                fmt = 'text'

            try:
                # Attempt to extract title
                meta = trafilatura.bare_extraction(html_content)
                if meta and isinstance(meta, dict) and 'title' in meta:
                    title = meta['title']
            except Exception as e:
                logger.warning(f"trafilatura bare_extraction failed for {url}: {e}")

        # Run content through comprehensive Smart Guardrails
        try:
            clean_content, report = sanitize_content(
                content,
                source_url=url,
                wrap_provenance=wrap_provenance,
                defang_all_images=defang_all_images,
            )
            guardrails_data = report.to_dict()
        except Exception as e:
            logger.exception(f"Guardrail sanitization error for {url}: {e}")
            clean_content = content
            guardrails_data = GuardrailReport(is_safe=False, findings=[f"Sanitization error: {e}"]).to_dict()

        total_length = len(clean_content)
        is_truncated = False

        if total_length > max_c:
            clean_content = clean_content[:max_c]
            is_truncated = True

        is_spa_shell, spa_advisory = self._detect_spa_shell(clean_content, html_content)

        return ArticleContent(
            url=url,
            title=title,
            content=clean_content,
            content_format=fmt,
            is_truncated=is_truncated,
            total_length=total_length,
            extraction_method=method,
            guardrails=guardrails_data,
            internal_links=internal_links,
            is_spa_shell=is_spa_shell,
            spa_advisory=spa_advisory,
        )

    def extract_from_feed_content(
        self,
        url: str,
        raw_html: str,
        max_chars: Optional[int] = None,
        wrap_provenance: bool = False,
        defang_all_images: bool = False,
    ) -> ArticleContent:
        """
        Clean and extract content provided directly from a feed snippet.
        
        Args:
            url: The source URL.
            raw_html: The raw HTML content from the feed.
            max_chars: Maximum characters to return. Defaults to instance default.
            wrap_provenance: If True, wraps content in an explicit provenance boundary fence.
            defang_all_images: If True, defangs all external images in the content.
            
        Returns:
            ArticleContent object.
        """
        max_c = max_chars if max_chars is not None else self.default_max_chars
        method = 'feed_content'
        fmt = 'text'

        try:
            extracted = trafilatura.extract(
                raw_html,
                output_format='text',
                include_comments=False,
                include_tables=True,
                no_fallback=False
            )
            if extracted:
                content = extracted
            else:
                raise ValueError("trafilatura returned None for feed content")
        except Exception as e:
            logger.warning(f"trafilatura feed extract failed for {url}: {e}")
            content = self._strip_html_fallback(raw_html)

        try:
            clean_content, report = sanitize_content(
                content,
                source_url=url,
                wrap_provenance=wrap_provenance,
                defang_all_images=defang_all_images,
            )
            guardrails_data = report.to_dict()
        except Exception as e:
            logger.exception(f"Guardrail sanitization error for {url}: {e}")
            clean_content = content
            guardrails_data = GuardrailReport(is_safe=False, findings=[f"Sanitization error: {e}"]).to_dict()

        total_length = len(clean_content)
        is_truncated = False

        if total_length > max_c:
            clean_content = clean_content[:max_c]
            is_truncated = True

        is_spa_shell, spa_advisory = self._detect_spa_shell(clean_content, raw_html)

        return ArticleContent(
            url=url,
            title=None,
            content=clean_content,
            content_format=fmt,
            is_truncated=is_truncated,
            total_length=total_length,
            extraction_method=method,
            guardrails=guardrails_data,
            internal_links=[],
            is_spa_shell=is_spa_shell,
            spa_advisory=spa_advisory,
        )

    def _extract_internal_links(self, html_content: str, base_url: str, max_links: int = 25) -> list[dict]:
        """
        Extracts same-origin internal links with descriptive anchor text.
        """
        if not html_content:
            return []

        soup = BeautifulSoup(html_content, 'html.parser')
        parsed_base = urllib.parse.urlparse(base_url)
        base_netloc = parsed_base.netloc.lower()

        links = []
        seen_urls = set()

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            # Resolve relative URLs
            full_url = urllib.parse.urljoin(base_url, href)
            parsed_url = urllib.parse.urlparse(full_url)

            # Strip fragments and query parameters for deduplication if desired
            clean_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                '', '', ''
            ))

            # Only retain internal (same host) links
            if parsed_url.netloc.lower() == base_netloc and clean_url != base_url:
                if clean_url not in seen_urls:
                    anchor_text = a_tag.get_text(strip=True)
                    if anchor_text and len(anchor_text) >= 2:
                        seen_urls.add(clean_url)
                        links.append({
                            "text": anchor_text[:100],
                            "url": clean_url
                        })
                        if len(links) >= max_links:
                            break

        return links

    def _strip_html_fallback(self, html_str: str) -> str:
        """
        Regex-based fallback for removing HTML tags when trafilatura fails.
        """
        if not html_str:
            return ""
        no_script = re.sub(r'<(script|style).*?>.*?</\1>', ' ', html_str, flags=re.IGNORECASE | re.DOTALL)
        no_tags = re.sub(r'<[^>]+>', ' ', no_script)
        decoded = html.unescape(no_tags)
        return decoded.strip()

    @staticmethod
    def _detect_spa_shell(substantive_text: str, raw_html: str = "") -> tuple[bool, Optional[str]]:
        """
        Detect client-side JavaScript Single Page Application (SPA) shells.
        Checks if extracted content/markdown has minimal substantive text (< 150 chars)
        while containing characteristic SPA signatures:
        <div id="root"></div>, <div id="app"></div>, You need to enable JavaScript to run this app,
        __NEXT_DATA__, window.__INITIAL_STATE__.
        """
        clean = substantive_text.strip() if substantive_text else ""
        if len(clean) >= 150:
            return False, None

        spa_signatures = [
            '<div id="root"></div>',
            "<div id='root'></div>",
            '<div id="app"></div>',
            "<div id='app'></div>",
            'You need to enable JavaScript to run this app',
            '__NEXT_DATA__',
            'window.__INITIAL_STATE__',
        ]
        combined = f"{raw_html}\n{substantive_text}"
        for sig in spa_signatures:
            if sig in combined:
                return True, "Client-side JavaScript SPA shell detected. Static HTML extraction returned empty container."

        flexible_patterns = [
            r'<div\s+id=["\']?root["\']?\s*>\s*</div>',
            r'<div\s+id=["\']?app["\']?\s*>\s*</div>',
        ]
        for pat in flexible_patterns:
            if re.search(pat, combined, re.IGNORECASE):
                return True, "Client-side JavaScript SPA shell detected. Static HTML extraction returned empty container."

        return False, None
