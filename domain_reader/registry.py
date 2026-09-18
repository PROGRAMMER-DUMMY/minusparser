"""Thread-safe Resource Registries for storing quarantined untrusted web payloads.

Provides in-memory and SQLite-backed implementations with LRU capacity bounds
and sliding TTL auto-expiration to eliminate fragility and OOM risks.
"""
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional


@dataclass
class QuarantinedArticle:
    """Stored representation of an untrusted article isolated from privileged LLM context."""
    article_id: str
    url: str
    content: str
    title: Optional[str] = None
    content_format: str = "markdown"
    total_length: int = 0
    guardrails: dict = field(default_factory=dict)
    internal_links: list[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600.0)

    @property
    def resource_uri(self) -> str:
        """Returns standard MCP resource URI for this quarantined article."""
        return f"resource://article/{self.article_id}"

    @property
    def is_expired(self) -> bool:
        """Check if article expiration timestamp has passed."""
        return self.expires_at > 0 and time.time() >= self.expires_at

    def to_handle(self) -> dict[str, Any]:
        """Generate an opaque handle safe for privileged agent context."""
        return {
            "status": "quarantined",
            "article_id": self.article_id,
            "resource_uri": self.resource_uri,
            "title": self.title,
            "url": self.url,
            "char_count": self.total_length,
            "guardrails": self.guardrails,
            "internal_links": self.internal_links[:5],
            "message": "Content stored in air-gapped MCP resource. Read via Quarantined Worker using resource_uri.",
        }


class ResourceRegistry:
    """Thread-safe in-memory registry for air-gapped article payloads with LRU bounds and sliding TTL."""

    def __init__(
        self,
        max_capacity: int = 1000,
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        self.max_capacity = max_capacity
        self.default_ttl_seconds = default_ttl_seconds
        self._articles: OrderedDict[str, QuarantinedArticle] = OrderedDict()
        self._lock = threading.RLock()

    @staticmethod
    def generate_id(url: str = "", content: str = "") -> str:
        """Generate a deterministic 16-char hex hash ID from URL or content (or fallback to UUID)."""
        if url:
            return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        if content:
            return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        return uuid.uuid4().hex[:16]

    def _evict_expired(self) -> int:
        """Thread-safe eviction of expired articles."""
        now = time.time()
        with self._lock:
            expired_keys = [
                k for k, v in self._articles.items()
                if v.expires_at > 0 and v.expires_at < now
            ]
            for k in expired_keys:
                del self._articles[k]
            return len(expired_keys)

    def _enforce_lru(self) -> int:
        """Thread-safe eviction of least-recently-used items when max_capacity is exceeded."""
        with self._lock:
            evicted = 0
            while len(self._articles) > self.max_capacity:
                self._articles.popitem(last=False)
                evicted += 1
            return evicted

    def store(
        self,
        content: str,
        url: str = "",
        title: Optional[str] = None,
        article_id: Optional[str] = None,
        content_format: str = "markdown",
        total_length: Optional[int] = None,
        guardrails: Optional[dict] = None,
        internal_links: Optional[list[dict]] = None,
        ttl_seconds: Optional[float] = None,
    ) -> str:
        """Store an article payload and return its unique article_id."""
        if not article_id:
            article_id = self.generate_id(url=url, content=content)

        length = total_length if total_length is not None else len(content)
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        expires_at = now + ttl if ttl > 0 else 0.0

        record = QuarantinedArticle(
            article_id=article_id,
            url=url,
            content=content,
            title=title,
            content_format=content_format,
            total_length=length,
            guardrails=guardrails or {},
            internal_links=internal_links or [],
            created_at=now,
            expires_at=expires_at,
        )

        with self._lock:
            self._evict_expired()
            self._articles[article_id] = record
            self._articles.move_to_end(article_id)
            self._enforce_lru()

        return article_id

    def get(self, article_id: str) -> Optional[QuarantinedArticle]:
        """Retrieve a quarantined article record by ID with sliding TTL."""
        with self._lock:
            self._evict_expired()
            record = self._articles.get(article_id)
            if record is None:
                return None
            self._articles.move_to_end(article_id)
            if self.default_ttl_seconds > 0:
                record.expires_at = time.time() + self.default_ttl_seconds
            return record

    def get_content(self, article_id: str) -> Optional[str]:
        """Retrieve raw quarantined content string by article ID."""
        with self._lock:
            record = self.get(article_id)
            return record.content if record else None

    def remove(self, article_id: str) -> bool:
        """Remove an article from quarantine."""
        with self._lock:
            return self._articles.pop(article_id, None) is not None

    def clear(self) -> None:
        """Clear all stored articles."""
        with self._lock:
            self._articles.clear()

    def list_ids(self) -> list[str]:
        """List all quarantined article IDs."""
        with self._lock:
            self._evict_expired()
            return list(self._articles.keys())

    def list_all(self) -> list[QuarantinedArticle]:
        """List all quarantined article records."""
        with self._lock:
            self._evict_expired()
            return list(self._articles.values())

    def __contains__(self, article_id: str) -> bool:
        with self._lock:
            self._evict_expired()
            return article_id in self._articles

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired()
            return len(self._articles)

    def __getitem__(self, article_id: str) -> QuarantinedArticle:
        with self._lock:
            record = self.get(article_id)
            if record is None:
                raise KeyError(article_id)
            return record

    def __setitem__(self, article_id: str, article: QuarantinedArticle) -> None:
        with self._lock:
            self._evict_expired()
            now = time.time()
            if article.expires_at <= now and self.default_ttl_seconds > 0:
                article.expires_at = now + self.default_ttl_seconds
            self._articles[article_id] = article
            self._articles.move_to_end(article_id)
            self._enforce_lru()

    def __delitem__(self, article_id: str) -> None:
        with self._lock:
            if article_id not in self._articles:
                raise KeyError(article_id)
            del self._articles[article_id]

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            self._evict_expired()
            return iter(list(self._articles.keys()))

    def keys(self) -> list[str]:
        """List all active article IDs."""
        return self.list_ids()

    def values(self) -> list[QuarantinedArticle]:
        """List all active article records."""
        return self.list_all()

    def items(self) -> list[tuple[str, QuarantinedArticle]]:
        """List all active (article_id, article) pairs."""
        with self._lock:
            self._evict_expired()
            return list(self._articles.items())


class SQLiteResourceRegistry(ResourceRegistry):
    """Persistent SQLite-backed registry for quarantined article payloads with TTL and LRU bounds."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        max_capacity: int = 1000,
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        super().__init__(max_capacity=max_capacity, default_ttl_seconds=default_ttl_seconds)
        if db_path is None:
            db_path = os.environ.get(
                "MINUSPARSER_DB_PATH",
                os.path.expanduser("~/.minusparser/quarantine.db"),
            )
        elif db_path != ":memory:":
            db_path = os.path.expanduser(db_path)

        self.db_path = db_path
        if self.db_path != ":memory:":
            dir_name = os.path.dirname(os.path.abspath(self.db_path))
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)

        self._init_db()

    def _init_db(self) -> None:
        """Initialize database connection, schema, and indexes."""
        with self._lock:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,
            )
            self._conn.row_factory = sqlite3.Row
            with self._conn:
                if self.db_path != ":memory:":
                    self._conn.execute("PRAGMA journal_mode = WAL;")
                self._conn.execute("PRAGMA busy_timeout = 5000;")
                self._conn.execute("PRAGMA synchronous = NORMAL;")
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS articles (
                        article_id TEXT PRIMARY KEY,
                        url TEXT NOT NULL,
                        content TEXT NOT NULL,
                        title TEXT,
                        content_format TEXT DEFAULT 'markdown',
                        total_length INTEGER DEFAULT 0,
                        guardrails TEXT,
                        internal_links TEXT,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        last_accessed_at REAL NOT NULL
                    )
                    """
                )
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_articles_expires_at ON articles(expires_at);"
                )
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_articles_last_accessed_at ON articles(last_accessed_at);"
                )

    def _row_to_article(self, row: sqlite3.Row) -> QuarantinedArticle:
        """Deserialize an SQLite Row into a QuarantinedArticle object."""
        guardrails = json.loads(row["guardrails"]) if row["guardrails"] else {}
        internal_links = json.loads(row["internal_links"]) if row["internal_links"] else []
        return QuarantinedArticle(
            article_id=row["article_id"],
            url=row["url"],
            content=row["content"],
            title=row["title"],
            content_format=row["content_format"] or "markdown",
            total_length=row["total_length"] or 0,
            guardrails=guardrails,
            internal_links=internal_links,
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def _evict_expired(self) -> int:
        """Automatic TTL cleanup query: DELETE FROM articles WHERE expires_at < ?"""
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM articles WHERE expires_at < ?",
                (now,),
            )
            return cur.rowcount

    def _enforce_lru(self) -> int:
        """Enforce max_capacity bound by evicting oldest accessed articles."""
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM articles")
            count = cur.fetchone()[0]
            if count <= self.max_capacity:
                return 0
            excess = count - self.max_capacity
            del_cur = self._conn.execute(
                """
                DELETE FROM articles WHERE article_id IN (
                    SELECT article_id FROM articles
                    ORDER BY last_accessed_at ASC
                    LIMIT ?
                )
                """,
                (excess,),
            )
            return del_cur.rowcount

    def store(
        self,
        content: str,
        url: str = "",
        title: Optional[str] = None,
        article_id: Optional[str] = None,
        content_format: str = "markdown",
        total_length: Optional[int] = None,
        guardrails: Optional[dict] = None,
        internal_links: Optional[list[dict]] = None,
        ttl_seconds: Optional[float] = None,
    ) -> str:
        """Store an article payload in SQLite and return its unique article_id."""
        if not article_id:
            article_id = self.generate_id(url=url, content=content)

        length = total_length if total_length is not None else len(content)
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        expires_at = now + ttl if ttl > 0 else 0.0

        guardrails_json = json.dumps(guardrails or {})
        internal_links_json = json.dumps(internal_links or [])

        with self._lock:
            self._evict_expired()
            self._conn.execute(
                """
                INSERT OR REPLACE INTO articles (
                    article_id, url, content, title, content_format,
                    total_length, guardrails, internal_links,
                    created_at, expires_at, last_accessed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    article_id,
                    url,
                    content,
                    title,
                    content_format,
                    length,
                    guardrails_json,
                    internal_links_json,
                    now,
                    expires_at,
                    now,
                ),
            )
            self._enforce_lru()

        return article_id

    def get(self, article_id: str) -> Optional[QuarantinedArticle]:
        """Retrieve a quarantined article record by ID from SQLite with sliding TTL."""
        with self._lock:
            self._evict_expired()
            cur = self._conn.execute(
                "SELECT * FROM articles WHERE article_id = ?",
                (article_id,),
            )
            row = cur.fetchone()
            if not row:
                return None

            now = time.time()
            new_expires = now + self.default_ttl_seconds
            self._conn.execute(
                "UPDATE articles SET last_accessed_at = ?, expires_at = ? WHERE article_id = ?",
                (now, new_expires, article_id),
            )
            article = self._row_to_article(row)
            article.expires_at = new_expires
            return article

    def get_content(self, article_id: str) -> Optional[str]:
        """Retrieve raw quarantined content string by article ID from SQLite."""
        record = self.get(article_id)
        return record.content if record else None

    def remove(self, article_id: str) -> bool:
        """Remove an article from quarantine in SQLite."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM articles WHERE article_id = ?",
                (article_id,),
            )
            return cur.rowcount > 0

    def clear(self) -> None:
        """Clear all stored articles from SQLite."""
        with self._lock:
            self._conn.execute("DELETE FROM articles")

    def list_ids(self) -> list[str]:
        """List all non-expired quarantined article IDs from SQLite."""
        with self._lock:
            self._evict_expired()
            cur = self._conn.execute(
                "SELECT article_id FROM articles ORDER BY last_accessed_at DESC"
            )
            return [row["article_id"] for row in cur.fetchall()]

    def list_all(self) -> list[QuarantinedArticle]:
        """List all non-expired quarantined article records from SQLite."""
        with self._lock:
            self._evict_expired()
            cur = self._conn.execute(
                "SELECT * FROM articles ORDER BY last_accessed_at DESC"
            )
            return [self._row_to_article(row) for row in cur.fetchall()]

    def __contains__(self, article_id: str) -> bool:
        with self._lock:
            self._evict_expired()
            cur = self._conn.execute(
                "SELECT 1 FROM articles WHERE article_id = ?",
                (article_id,),
            )
            return cur.fetchone() is not None

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired()
            cur = self._conn.execute("SELECT COUNT(*) FROM articles")
            return cur.fetchone()[0]

    def __getitem__(self, article_id: str) -> QuarantinedArticle:
        record = self.get(article_id)
        if record is None:
            raise KeyError(article_id)
        return record

    def __setitem__(self, article_id: str, article: QuarantinedArticle) -> None:
        now = time.time()
        expires_at = article.expires_at if article.expires_at > now else (now + self.default_ttl_seconds)
        guardrails_json = json.dumps(article.guardrails or {})
        internal_links_json = json.dumps(article.internal_links or [])
        with self._lock:
            self._evict_expired()
            self._conn.execute(
                """
                INSERT OR REPLACE INTO articles (
                    article_id, url, content, title, content_format,
                    total_length, guardrails, internal_links,
                    created_at, expires_at, last_accessed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    article_id,
                    article.url,
                    article.content,
                    article.title,
                    article.content_format,
                    article.total_length,
                    guardrails_json,
                    internal_links_json,
                    article.created_at,
                    expires_at,
                    now,
                ),
            )
            self._enforce_lru()

    def __delitem__(self, article_id: str) -> None:
        if not self.remove(article_id):
            raise KeyError(article_id)

    def __iter__(self) -> Iterator[str]:
        return iter(self.list_ids())

    def keys(self) -> list[str]:
        """List all active article IDs."""
        return self.list_ids()

    def values(self) -> list[QuarantinedArticle]:
        """List all active article records."""
        return self.list_all()

    def items(self) -> list[tuple[str, QuarantinedArticle]]:
        """List all active (article_id, article) pairs."""
        with self._lock:
            self._evict_expired()
            cur = self._conn.execute(
                "SELECT * FROM articles ORDER BY last_accessed_at DESC"
            )
            return [(row["article_id"], self._row_to_article(row)) for row in cur.fetchall()]

    def close(self) -> None:
        """Close database connection."""
        with self._lock:
            if hasattr(self, "_conn") and self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass

    def __enter__(self) -> "SQLiteResourceRegistry":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

