"""Verification test suite for safe_read one-liner SDK, SPA shell detection, and epistemic taint tracking."""
import asyncio
import sys
from pydantic import BaseModel, Field

# Ensure stdout uses UTF-8 on Windows
sys.stdout.reconfigure(encoding="utf-8")

from domain_reader import (
    safe_read,
    ArticleAnalysis,
    SQLiteResourceRegistry,
    ResourceRegistry,
    is_field_tainted,
    get_taint_metadata,
    get_untrusted_fields,
)
from domain_reader.extractor import ContentExtractor, ArticleContent
from domain_reader.security import SSRFError


async def test_all():
    print("=" * 70)
    print("  TESTING INVISIBLE SECURITY ONE-LINER SDK (safe_read) & TAINT TRACKING")
    print("=" * 70)

    # 1. Test Exports
    print("\n--- [1/6] Verifying Module Exports ---")
    assert safe_read is not None
    assert ArticleAnalysis is not None
    assert SQLiteResourceRegistry is not None
    assert ResourceRegistry is not None
    print("  [PASS] safe_read, ArticleAnalysis, SQLiteResourceRegistry imported cleanly from domain_reader.")

    # 2. Test SPA Shell Detection Mechanics
    print("\n--- [2/6] Verifying SPA / Client-Side JS Shell Detection ---")
    spa_samples = [
        '<div id="root"></div>',
        "<div id='root'></div>",
        '<div id="app"></div>',
        "You need to enable JavaScript to run this app",
        "<script>window.__INITIAL_STATE__ = {};</script>",
        "<html><head><script>window.__NEXT_DATA__ = {};</script></head><body><div id=\"root\"></div></body></html>",
    ]
    for sample in spa_samples:
        is_spa, advisory = ContentExtractor._detect_spa_shell("Short extracted text", sample)
        assert is_spa is True, f"Failed to detect SPA on sample: {sample}"
        assert advisory == "Client-side JavaScript SPA shell detected. Static HTML extraction returned empty container."

    # Verify non-SPA / substantial text (>150 chars) returns False
    long_text = "This is a comprehensive article explaining architectural patterns in distributed database design. " * 3
    is_spa_neg, adv_neg = ContentExtractor._detect_spa_shell(long_text, '<div id="root"></div>')
    assert is_spa_neg is False
    assert adv_neg is None
    print(f"  [PASS] SPA shell detection validated on {len(spa_samples)} SPA variants + negative control.")

    # 3. Test SSRF Guard in safe_read
    print("\n--- [3/6] Verifying SSRF Protection in safe_read ---")
    try:
        await safe_read("http://169.254.169.254/latest/meta-data")
        assert False, "SSRF attempt was NOT blocked by safe_read!"
    except SSRFError as e:
        print(f"  [PASS] SSRF target safely blocked with SSRFError: {e}")

    # 4. Test Live safe_read Ingestion
    print("\n--- [4/6] Verifying End-to-End safe_read Functionality ---")
    target_url = "https://www.databricks.com/blog/five-ai-questions-were-hearing-financial-services-leaders"
    model, handle = await safe_read(
        target_url,
        schema=ArticleAnalysis,
        prefer_markdown=True,
        force_offline=True,
        custom_policy="Extract financial leadership AI perspectives.",
    )

    assert isinstance(model, ArticleAnalysis)
    assert isinstance(handle, dict)
    assert handle["status"] == "quarantined"
    assert "article_id" in handle
    assert handle["resource_uri"].startswith("resource://article/")
    assert handle["raw_content_handle"].startswith("$CONTENT_REF_")
    assert handle["raw_content_handle"] == model.raw_content_handle
    assert len(model.title) > 0
    assert len(model.summary) > 0
    assert len(model.primary_topic) > 0

    print(f"  [PASS] safe_read succeeded:")
    print(f"    - Title: {model.title}")
    print(f"    - Topic: {model.primary_topic}")
    print(f"    - Entities extracted: {len(model.entities)}")
    print(f"    - Content Handle: {model.raw_content_handle}")
    print(f"    - Opaque Resource URI: {handle['resource_uri']}")

    # 5. Test Epistemic Taint Tracking
    print("\n--- [5/6] Verifying Epistemic Taint Tracking ---")
    taint_meta = get_taint_metadata(model)
    assert taint_meta["is_tainted"] is True
    assert taint_meta["taint_level"] == "UNTRUSTED_WEB_DERIVED"
    assert "title" in taint_meta["untrusted_fields"]
    assert "summary" in taint_meta["untrusted_fields"]
    assert "raw_content_handle" in taint_meta["trusted_system_fields"]

    # Check model convenience methods
    assert model.is_tainted("title") is True
    assert model.is_tainted("summary") is True
    assert model.is_tainted("raw_content_handle") is False
    assert is_field_tainted(model, "entities") is True
    assert is_field_tainted(model, "raw_content_handle") is False

    # Check handle dict taint tracking
    assert "epistemic_taint" in handle
    assert handle["epistemic_taint"]["source_url"] == target_url
    assert "title" in handle["tainted_fields"]
    assert "raw_content_handle" in handle["trusted_fields"]

    print(f"  [PASS] Epistemic taint metadata accurately classified:")
    print(f"    - Untrusted Fields: {taint_meta['untrusted_fields']}")
    print(f"    - Trusted System Fields: {taint_meta['trusted_system_fields']}")

    # 6. Test Custom Schema with extra='forbid'
    print("\n--- [6/6] Verifying Custom Schema with extra='forbid' ---")
    class CustomAdvisory(BaseModel):
        title: str
        summary: str
        raw_content_handle: str

    custom_model, custom_handle = await safe_read(
        target_url,
        schema=CustomAdvisory,
        prefer_markdown=True,
        force_offline=True,
    )
    assert isinstance(custom_model, CustomAdvisory)
    assert is_field_tainted(custom_model, "title") is True
    assert is_field_tainted(custom_model, "raw_content_handle") is False
    print(f"  [PASS] Custom schema successfully validated and taint-tracked.")

    print("\n" + "=" * 70)
    print("  ALL 6 safe_read & TAINT TRACKING TESTS PASSED PERFECTLY!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_all())
