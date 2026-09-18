import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, List, Optional
from urllib.parse import urljoin, urlparse

import feedparser
from bs4 import BeautifulSoup

from .http_client import CacheInfo, HardenedClient
from .security import sanitize_content

logger = logging.getLogger(__name__)


@dataclass
class ContentItem:
    """Represents a discovered piece of content."""
    title: str
    url: str
    published: str
    summary: str
    categories: list[str] = field(default_factory=list)
    full_content: Optional[str] = None
    source_strategy: str = "direct"


@dataclass
class DiscoveryResult:
    """The result of a discovery operation."""
    items: list[ContentItem]
    feed_url: Optional[str]
    strategy_used: str
    fallback_hints: list[str] = field(default_factory=list)
    cache_info: Optional[CacheInfo] = None


class DiscoveryEngine:
    """Multi-strategy content discovery engine for finding articles on a domain.
    
    Strategies (in priority order):
    0. Machine-native /llms.txt and /.well-known/llms.txt (sub-50ms, $0)
    1. RSS / Atom feeds (via link headers, discovery tags, or common paths)
    2. Sitemap.xml / Sitemap index files
    3. Graceful fallback hints
    """

    def __init__(self, client: HardenedClient):
        """
        Initialize the discovery engine.

        Args:
            client: An instance of HardenedClient for making network requests.
        """
        self.client = client

    async def discover(
        self,
        url: str,
        query: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 10
    ) -> DiscoveryResult:
        """
        Discover content items using /llms.txt first, then RSS/Atom, then Sitemap, falling back to hints.

        Args:
            url: The root URL to discover content for.
            query: Optional keyword filter.
            category: Optional category filter.
            limit: Maximum number of items to return.

        Returns:
            A DiscoveryResult containing the found items and strategy information.
        """
        try:
            # 0. Try /llms.txt (Machine-native Tier 0)
            llms_result = await self._try_llms_txt(url)
            if llms_result and llms_result.items:
                llms_result.items = self._filter_items(llms_result.items, query, category)[:limit]
                return llms_result

            # 1. Try RSS/Atom
            rss_result = await self._try_rss(url)
            if rss_result and rss_result.items:
                rss_result.items = self._filter_items(rss_result.items, query, category)[:limit]
                return rss_result

            # 2. Try Sitemap
            sitemap_result = await self._try_sitemap(url)
            if sitemap_result and sitemap_result.items:
                sitemap_result.items = self._filter_items(sitemap_result.items, query, category)[:limit]
                return sitemap_result

        except Exception as e:
            logger.error(f"Error during discovery for {url}: {e}")

        # 3. Fallback
        return DiscoveryResult(
            items=[],
            feed_url=None,
            strategy_used="none",
            fallback_hints=[
                f"Try direct URL fetching using read_web_article on specific links within {url}",
                "Try manually looking for a /sitemap.xml or /feed URL if this domain is known to have one."
            ]
        )

    async def _try_llms_txt(self, url: str) -> Optional[DiscoveryResult]:
        """Attempt to discover content via machine-native /llms.txt or /.well-known/llms.txt."""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            for path in ("/.well-known/llms.txt", "/llms.txt"):
                target_url = urljoin(base_url, path)
                try:
                    resp = await self.client.get(target_url)
                    if resp.status_code == 200 and resp.text:
                        text = resp.text.strip()
                        # Verify it's plain markdown, not an HTML soft 404
                        if "<html" in text.lower() or "<body" in text.lower():
                            continue

                        items = []
                        # Extract markdown links: [Title](url) or - [Title](url): Summary
                        pattern = re.compile(r'\[([^\]]+)\]\((https?:\/\/[^\)]+|\/[^\)]+)\)(?::\s*([^\n]+))?')
                        for match in pattern.finditer(text):
                            title = match.group(1).strip()
                            link_url = match.group(2).strip()
                            summary = match.group(3).strip() if match.group(3) else ""
                            full_link = urljoin(base_url, link_url)
                            items.append(ContentItem(
                                title=title,
                                url=full_link,
                                published="",
                                summary=summary,
                                categories=["llms.txt"],
                                full_content=None,
                                source_strategy="llms.txt"
                            ))

                        if items:
                            logger.info(f"Discovered {len(items)} items via {target_url}")
                            return DiscoveryResult(
                                items=items,
                                feed_url=target_url,
                                strategy_used="llms.txt",
                                cache_info=None
                            )
                except Exception as e:
                    logger.debug(f"llms.txt probe failed for {target_url}: {e}")
        except Exception as e:
            logger.warning(f"Error during llms.txt discovery for {url}: {e}")
        return None

    async def _try_rss(self, url: str) -> Optional[DiscoveryResult]:
        """Attempt to discover content via RSS/Atom feeds."""
        try:
            logger.debug(f"Trying RSS discovery for {url}")
            response = await self.client.get(url)
            content_type = response.headers.get("Content-Type", "").lower()

            feed_url = None
            feed_content = None
            cache_info = None

            if "xml" in content_type or "rss" in content_type or "atom" in content_type:
                feed_url = url
                feed_content = response.content
            elif "html" in content_type:
                # Look for <link rel="alternate"> tags
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.find_all("link", rel="alternate"):
                    link_type = link.get("type", "").lower()
                    if link_type in ("application/rss+xml", "application/atom+xml"):
                        href = link.get("href")
                        if href:
                            feed_url = urljoin(url, href)
                            logger.debug(f"Found RSS link tag pointing to {feed_url}")
                            feed_resp = await self.client.get(feed_url)
                            feed_content = feed_resp.content
                            break
                
                if not feed_content:
                    # Try common fallback paths
                    fallbacks = [
                        "/feed", "/rss", "/feed.xml", "/rss.xml", 
                        "/blog/feed", "/atom.xml"
                    ]
                    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    for path in fallbacks:
                        test_url = urljoin(base_url, path)
                        try:
                            test_resp = await self.client.get(test_url)
                            if test_resp.status_code == 200:
                                ct = test_resp.headers.get("Content-Type", "").lower()
                                if "xml" in ct or "rss" in ct or "atom" in ct:
                                    feed_url = test_url
                                    feed_content = test_resp.content
                                    break
                        except Exception as e:
                            logger.debug(f"Fallback check failed for {test_url}: {e}")
                            continue

            if feed_content:
                parsed_feed = feedparser.parse(feed_content)
                if not parsed_feed.bozo or parsed_feed.entries:
                    items = [self._parse_feed_entry(entry) for entry in parsed_feed.entries]
                    if items:
                        return DiscoveryResult(
                            items=items,
                            feed_url=feed_url,
                            strategy_used="rss",
                            cache_info=cache_info
                        )
        except Exception as e:
            logger.warning(f"RSS discovery failed for {url}: {e}")

        return None

    async def _try_sitemap(self, url: str) -> Optional[DiscoveryResult]:
        """Attempt to discover content via sitemap.xml."""
        try:
            logger.debug(f"Trying sitemap discovery for {url}")
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            sitemap_url = urljoin(base_url, "/sitemap.xml")
            
            response = await self.client.get(sitemap_url)
            if response.status_code != 200:
                return None
            
            # Simple XML parsing, ignoring namespaces
            root = ET.fromstring(response.content)
            
            # Check if it's a sitemap index
            is_index = False
            for elem in root:
                if 'sitemapindex' in str(elem.tag).lower():
                    is_index = True
                    break
            
            if is_index or 'sitemapindex' in str(root.tag).lower():
                # Find the first sitemap in the index
                loc_elem = None
                for elem in root.iter():
                    if 'loc' in str(elem.tag).lower():
                        loc_elem = elem
                        break
                
                if loc_elem is not None and loc_elem.text:
                    sub_sitemap_url = loc_elem.text.strip()
                    logger.debug(f"Following sitemap index to {sub_sitemap_url}")
                    response = await self.client.get(sub_sitemap_url)
                    if response.status_code != 200:
                        return None
                    root = ET.fromstring(response.content)

            items = []
            for elem in root.iter():
                if 'loc' in str(elem.tag).lower():
                    loc_url = elem.text.strip() if elem.text else ""
                    if loc_url:
                        # Humanize title from URL
                        path = urlparse(loc_url).path.strip('/')
                        raw_title = path.split('/')[-1] if path else "Home"
                        title = re.sub(r'[-_]', ' ', raw_title).title()
                        
                        items.append(ContentItem(
                            title=title,
                            url=loc_url,
                            published="",
                            summary="",
                            categories=[],
                            full_content=None,
                            source_strategy="sitemap"
                        ))
            
            if items:
                return DiscoveryResult(
                    items=items,
                    feed_url=sitemap_url,
                    strategy_used="sitemap"
                )
        except Exception as e:
            logger.warning(f"Sitemap discovery failed for {url}: {e}")

        return None

    def _filter_items(
        self,
        items: List[ContentItem],
        query: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[ContentItem]:
        """Filter items by query string and category."""
        filtered = items
        
        if query:
            q = query.lower()
            filtered = [
                item for item in filtered
                if q in item.title.lower() or q in item.summary.lower()
            ]
            
        if category:
            c = category.lower()
            filtered = [
                item for item in filtered
                if any(c in cat.lower() for cat in item.categories)
            ]
            
        return filtered

    def _parse_feed_entry(self, entry: Any) -> ContentItem:
        """Parse a feedparser entry into a ContentItem."""
        title = getattr(entry, 'title', 'Untitled')
        link = getattr(entry, 'link', '')
        
        published = getattr(entry, 'published', getattr(entry, 'updated', ''))
        
        summary_raw = getattr(entry, 'summary', '')
        if summary_raw:
            clean_sum, _ = sanitize_content(summary_raw)
            summary = clean_sum[:300]
        else:
            summary = ""
        
        categories = []
        for tag in getattr(entry, 'tags', []):
            if hasattr(tag, 'term'):
                categories.append(tag.term)
                
        full_content = None
        if hasattr(entry, 'content') and isinstance(entry.content, list) and len(entry.content) > 0:
            first_content = entry.content[0]
            if hasattr(first_content, 'value'):
                clean_full, _ = sanitize_content(first_content.value)
                full_content = clean_full
                
        return ContentItem(
            title=title,
            url=link,
            published=published,
            summary=summary,
            categories=categories,
            full_content=full_content,
            source_strategy="rss"
        )
