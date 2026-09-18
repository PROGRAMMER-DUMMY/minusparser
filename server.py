"""Model Context Protocol (MCP) server entrypoint for MinusParser.

Re-exports mcp and resource_registry from domain_reader.server for clean packaging
and backward compatibility with direct python server.py invocations.
"""

from domain_reader.server import (
    mcp,
    resource_registry,
    init_registry,
    discover_content,
    read_web_article,
    read_feed_article,
    quarantine_web_article,
    get_quarantined_article,
)


if __name__ == "__main__":
    mcp.run()
