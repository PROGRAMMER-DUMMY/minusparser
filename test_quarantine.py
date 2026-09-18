"""Tests for MCP Resource Registry and Quarantined Web Article Handle."""
import asyncio
import sys

sys.stdout.reconfigure(encoding="utf-8")


async def test_quarantine_flow():
    print("=" * 60)
    print("  TESTING MCP QUARANTINE & OUT-OF-BAND RESOURCE SUITE")
    print("=" * 60)

    import server
    from domain_reader.registry import ResourceRegistry, QuarantinedArticle

    # --- [1/5] Test ResourceRegistry Unit Mechanics ---
    print("\n--- [1/5] Testing ResourceRegistry Data Structures ---")
    reg = ResourceRegistry()
    assert len(reg) == 0

    custom_id = reg.store(
        content="# Confidential Payload\nDon't leak this.",
        url="https://example.com/test",
        title="Test Article",
        article_id="custom_handle_123",
        guardrails={"is_safe": True, "findings": []},
        internal_links=[{"text": f"Link {i}", "url": f"https://example.com/{i}"} for i in range(10)],
    )
    assert custom_id == "custom_handle_123"
    assert "custom_handle_123" in reg
    assert len(reg) == 1

    record = reg.get("custom_handle_123")
    assert isinstance(record, QuarantinedArticle)
    assert record.resource_uri == "resource://article/custom_handle_123"
    assert record.total_length == len("# Confidential Payload\nDon't leak this.")

    # Check handle formatting
    handle = record.to_handle()
    assert handle["status"] == "quarantined"
    assert handle["article_id"] == "custom_handle_123"
    assert handle["resource_uri"] == "resource://article/custom_handle_123"
    assert handle["title"] == "Test Article"
    assert handle["char_count"] == record.total_length
    assert len(handle["internal_links"]) == 5  # Capped at 5
    assert "content" not in handle, "Raw content leaked in opaque handle!"
    print("  [PASS] ResourceRegistry unit mechanisms & handle formatting verified.")

    # --- [2/5] Test SSRF Blocking on quarantine_web_article ---
    print("\n--- [2/5] Testing SSRF Guard on quarantine_web_article ---")
    ssrf_res = await server.quarantine_web_article("http://169.254.169.254/latest/meta-data")
    assert ssrf_res.get("error") == "ssrf_blocked", f"Expected ssrf_blocked, got {ssrf_res}"
    print("  [PASS] quarantine_web_article blocked SSRF target.")

    # --- [3/5] Test End-to-End quarantine_web_article Tool Execution ---
    print("\n--- [3/5] Testing End-to-End quarantine_web_article ---")
    target_url = "https://www.databricks.com/blog/five-ai-questions-were-hearing-financial-services-leaders"
    quarantine_result = await server.quarantine_web_article(target_url, prefer_markdown=True)

    assert "error" not in quarantine_result, f"Quarantine failed: {quarantine_result}"
    assert quarantine_result["status"] == "quarantined"
    assert "article_id" in quarantine_result
    assert quarantine_result["resource_uri"] == f"resource://article/{quarantine_result['article_id']}"
    assert quarantine_result["url"] == target_url
    assert "char_count" in quarantine_result and quarantine_result["char_count"] > 0
    assert "guardrails" in quarantine_result
    assert "internal_links" in quarantine_result
    assert len(quarantine_result["internal_links"]) <= 5, "Internal links exceeded limit of 5!"
    assert "content" not in quarantine_result, "CRITICAL: Raw untrusted content leaked into tool output!"
    assert quarantine_result["message"] == "Content stored in air-gapped MCP resource. Read via Quarantined Worker using resource_uri."

    print("  [PASS] quarantine_web_article returned opaque air-gapped handle:")
    for k, v in quarantine_result.items():
        if k == "internal_links":
            print(f"    - {k}: {len(v)} links")
        else:
            print(f"    - {k}: {v}")

    # --- [4/5] Test Out-of-Band Resource Fetch via MCP Protocol ---
    print("\n--- [4/5] Testing Out-of-Band MCP Resource Fetch ---")
    article_id = quarantine_result["article_id"]
    resource_uri = quarantine_result["resource_uri"]

    # Verify article is present in server.resource_registry
    assert article_id in server.resource_registry
    stored_content = server.resource_registry.get_content(article_id)
    assert stored_content is not None and len(stored_content) > 0

    # Fetch through FastMCP read_resource protocol
    resource_read_result = await server.mcp.read_resource(resource_uri)
    assert len(resource_read_result) > 0
    content_payload = resource_read_result[0].content
    assert content_payload == stored_content
    assert len(content_payload) == quarantine_result["char_count"]

    print(f"  [PASS] MCP read_resource fetched {len(content_payload)} chars out-of-band.")
    print(f"  Snippet: {content_payload[:120].strip()}...")

    # --- [5/5] Test Missing Resource Handling ---
    print("\n--- [5/5] Testing Missing Resource Handling ---")
    try:
        await server.mcp.read_resource("resource://article/non_existent_id")
        assert False, "Should have raised ValueError on missing article resource"
    except ValueError as e:
        assert "not found" in str(e).lower()
        print(f"  [PASS] Missing resource correctly raised ValueError: {e}")

    # --- [6/7] Test In-Memory LRU & Sliding TTL Auto-Eviction ---
    print("\n--- [6/7] Testing In-Memory LRU & Sliding TTL Auto-Eviction ---")
    import time

    mem_reg = ResourceRegistry(max_capacity=3, default_ttl_seconds=0.2)
    assert mem_reg.max_capacity == 3
    assert mem_reg.default_ttl_seconds == 0.2

    # Test LRU Eviction
    mem_reg.store(content="Content 1", article_id="art_1")
    mem_reg.store(content="Content 2", article_id="art_2")
    mem_reg.store(content="Content 3", article_id="art_3")
    assert len(mem_reg) == 3
    assert mem_reg.list_ids() == ["art_1", "art_2", "art_3"]

    # Touch art_1 so LRU order becomes [art_2, art_3, art_1]
    _ = mem_reg.get("art_1")

    # Add art_4 -> art_2 (least recently used) must be evicted
    mem_reg.store(content="Content 4", article_id="art_4")
    assert len(mem_reg) == 3
    assert "art_2" not in mem_reg
    assert "art_1" in mem_reg
    assert "art_3" in mem_reg
    assert "art_4" in mem_reg
    print("  [PASS] In-memory LRU bounds eviction verified.")

    # Test TTL Expiration
    ttl_reg = ResourceRegistry(max_capacity=10, default_ttl_seconds=0.1)
    ttl_reg.store(content="Ephemeral", article_id="ephemeral_1")
    assert "ephemeral_1" in ttl_reg
    time.sleep(0.15)
    assert "ephemeral_1" not in ttl_reg
    assert ttl_reg.get("ephemeral_1") is None
    assert len(ttl_reg) == 0
    print("  [PASS] In-memory TTL auto-expiration verified.")

    # Test Sliding TTL (access extends TTL)
    sliding_reg = ResourceRegistry(max_capacity=10, default_ttl_seconds=0.2)
    sliding_reg.store(content="Sliding payload", article_id="sliding_1")
    time.sleep(0.12)
    # Access at 0.12s refreshes TTL for another 0.2s (expires at ~0.32s)
    rec = sliding_reg.get("sliding_1")
    assert rec is not None
    time.sleep(0.12)
    # Total time 0.24s > initial 0.20s, but < extended 0.32s (last accessed at 0.12s)
    assert "sliding_1" in sliding_reg
    time.sleep(0.12)
    # Total elapsed from access is 0.24s > 0.20s -> expired
    assert sliding_reg.get("sliding_1") is None
    print("  [PASS] In-memory sliding TTL extension on access verified.")

    # --- [7/7] Test SQLite Persistent Registry & Process Restart Simulation ---
    print("\n--- [7/7] Testing SQLite Persistent Registry ---")
    import os
    import tempfile
    from domain_reader.registry import SQLiteResourceRegistry

    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = os.path.join(tmpdir, "test_quarantine.db")
        with SQLiteResourceRegistry(db_path=db_file, max_capacity=3, default_ttl_seconds=0.3) as sql_reg:
            # Store articles
            sql_reg.store(content="SQLite Content 1", article_id="sql_1", url="https://example.com/1")
            sql_reg.store(content="SQLite Content 2", article_id="sql_2", url="https://example.com/2")
            assert len(sql_reg) == 2
            assert "sql_1" in sql_reg
            assert sql_reg.get_content("sql_1") == "SQLite Content 1"

            # Dict protocol tests (sql_1 was accessed most recently by get_content)
            assert list(sql_reg.keys()) == ["sql_1", "sql_2"]
            assert len(sql_reg.values()) == 2
            assert len(sql_reg.items()) == 2
            sql_reg["sql_3"] = QuarantinedArticle(
                article_id="sql_3",
                url="https://example.com/3",
                content="SQLite Content 3",
                expires_at=time.time() + 10.0,
            )
            assert len(sql_reg) == 3
            del sql_reg["sql_2"]
            assert len(sql_reg) == 2
            assert "sql_2" not in sql_reg

        # Test persistence across reload (simulate worker reload / restart)
        with SQLiteResourceRegistry(db_path=db_file, max_capacity=3, default_ttl_seconds=0.3) as sql_reloaded:
            assert len(sql_reloaded) == 2
            assert "sql_1" in sql_reloaded
            assert "sql_3" in sql_reloaded
            assert sql_reloaded.get_content("sql_1") == "SQLite Content 1"
            assert sql_reloaded.get_content("sql_3") == "SQLite Content 3"
            print("  [PASS] SQLite persistence across restart/reload verified.")

            # Test SQLite LRU eviction
            sql_reloaded.store(content="SQLite Content 4", article_id="sql_4")
            # Touch sql_1 so sql_3 is least recently accessed
            _ = sql_reloaded.get("sql_1")
            sql_reloaded.store(content="SQLite Content 5", article_id="sql_5")
            assert len(sql_reloaded) == 3
            assert "sql_3" not in sql_reloaded, "Oldest accessed item sql_3 was not LRU-evicted!"
            assert "sql_1" in sql_reloaded
            assert "sql_4" in sql_reloaded
            assert "sql_5" in sql_reloaded
            print("  [PASS] SQLite LRU capacity bound eviction verified.")

            # Test SQLite TTL expiration query
            sql_reloaded.store(content="Short-lived", article_id="sql_short", ttl_seconds=0.1)
            time.sleep(0.15)
            evicted_count = sql_reloaded._evict_expired()
            assert evicted_count >= 1
            assert "sql_short" not in sql_reloaded
            assert sql_reloaded.get("sql_short") is None
            print("  [PASS] SQLite TTL auto-eviction query (DELETE FROM articles WHERE expires_at < ?) verified.")

            sql_reloaded.clear()
            assert len(sql_reloaded) == 0
            print("  [PASS] SQLite clear and cleanup verified.")

        # Test Backend Switching via environment variable
        os.environ["MINUSPARSER_STORAGE_BACKEND"] = "memory"
        mem_backend = server.init_registry()
        assert isinstance(mem_backend, ResourceRegistry)
        assert not isinstance(mem_backend, SQLiteResourceRegistry)

        os.environ["MINUSPARSER_STORAGE_BACKEND"] = "sqlite"
        sqlite_backend = server.init_registry()
        assert isinstance(sqlite_backend, SQLiteResourceRegistry)
        sqlite_backend.close()
        print("  [PASS] MINUSPARSER_STORAGE_BACKEND configuration switching verified.")

    print("\n" + "=" * 60)
    print("  ALL QUARANTINE & RESOURCE TESTS PASSED PERFECTLY!")
    print("=" * 60)



if __name__ == "__main__":
    asyncio.run(test_quarantine_flow())
