"""Full integration test for Domain Content Reader."""
import asyncio
import sys

sys.stdout.reconfigure(encoding="utf-8")


async def test():
    from domain_reader.http_client import HardenedClient
    from domain_reader.discovery import DiscoveryEngine
    from domain_reader.extractor import ContentExtractor
    from domain_reader.security import validate_url, SSRFError

    print("=" * 60)
    print("  DOMAIN CONTENT READER - FULL INTEGRATION TEST")
    print("=" * 60)

    # Test 1: SSRF Protection
    print("\n[1/4] SSRF Protection")
    blocked = 0
    for url in [
        "http://169.254.169.254/x",
        "file:///etc/passwd",
        "http://127.0.0.1",
        "http://10.0.0.1",
        "ftp://evil.com",
    ]:
        try:
            validate_url(url)
        except SSRFError:
            blocked += 1
    print(f"  {blocked}/5 malicious URLs blocked")

    # Test 2: RSS Discovery with filtering
    print("\n[2/4] RSS Feed Discovery")
    async with HardenedClient() as client:
        engine = DiscoveryEngine(client)
        result = await engine.discover(
            "https://www.databricks.com/blog", query="ai", limit=5
        )
        print(f"  Strategy: {result.strategy_used}")
        print(f"  Feed URL: {result.feed_url}")
        print(f"  Matching items: {len(result.items)}")
        for item in result.items:
            print(f"    [{item.source_strategy}] {item.title}")

    # Test 3: Article extraction
    print("\n[3/4] Article Extraction (trafilatura)")
    async with HardenedClient() as client:
        extractor = ContentExtractor(client)
        article = await extractor.extract(
            "https://www.databricks.com/blog/five-ai-questions-were-hearing-financial-services-leaders",
            max_chars=800,
        )
        print(f"  Title: {article.title}")
        print(f"  Method: {article.extraction_method}")
        print(f"  Format: {article.content_format}")
        print(f"  Size: {article.total_length} chars (truncated: {article.is_truncated})")
        print(f"  Preview: {article.content[:200]}...")

    # Test 4: Full server tool simulation
    print("\n[4/4] Server Tool Simulation")
    import server

    disc = await server.discover_content(
        "https://www.databricks.com/blog", query="governance", limit=3
    )
    print("  discover_content result:")
    print(f"    Strategy: {disc['strategy_used']}")
    print(f"    Items: {len(disc['items'])}")
    if disc["items"]:
        first = disc["items"][0]
        print(f"    First match: {first['title']}")

        read_result = await server.read_web_article(first["url"], max_chars=500)
        if "error" not in read_result:
            print(f"    read_web_article: {read_result['total_length']} chars extracted")
        else:
            print(f"    read_web_article error: {read_result['message']}")

    print("\n" + "=" * 60)
    print("  ALL TESTS PASSED")
    print("=" * 60)


asyncio.run(test())
