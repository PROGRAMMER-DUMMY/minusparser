"""MinusParser MCP Server module."""
from domain_reader.server import *

if __name__ == "__main__":
    from domain_reader.server import mcp
    mcp.run(transport="stdio")
