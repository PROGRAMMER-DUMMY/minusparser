"""MinusParser Command Line Interface (CLI).

High-performance, secure web content discovery, parsing, and MCP server
with strict stdout/stderr stream discipline for autonomous AI agents.
"""

import asyncio
import json
import logging
import os
import pathlib
import sys
from typing import List, Optional, Tuple

import click

from .discovery import DiscoveryEngine
from .errors import ToolError
from .extractor import ContentExtractor
from .http_client import HardenedClient, PayloadTooLargeError
from .politeness import RobotsDisallowedError, RateLimitError
from .registry import QuarantinedArticle, SQLiteResourceRegistry
from .security import SSRFError, is_ip_blocked
from .skill_template import SKILL_MD_CONTENT

# Configure default logging to strictly route to stderr
logging.basicConfig(
    level=logging.WARNING,
    format="[%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("minusparser.cli")


def filter_content_by_query(content: str, query: str, max_chars: int) -> Tuple[str, bool]:
    """Filter content paragraphs or markdown sections matching a query to conserve token budget."""
    if not query:
        return (content[:max_chars], False)

    q_lower = query.lower().strip()
    # Split content by double newlines or markdown headers
    paragraphs = content.split("\n\n")
    matching_chunks: List[str] = []
    total_len = 0

    for p in paragraphs:
        p_clean = p.strip()
        if not p_clean:
            continue
        if q_lower in p_clean.lower():
            if total_len + len(p_clean) + 4 > max_chars and matching_chunks:
                break
            matching_chunks.append(p_clean)
            total_len += len(p_clean) + 4

    if matching_chunks:
        filtered = "\n\n".join(matching_chunks)
        header = f"> [MinusParser Token-Budget: Extracted {len(matching_chunks)} sections matching '{query}']\n\n"
        return (header + filtered, True)

    # Fallback to truncated full content with notice
    notice = f"> [MinusParser Token-Budget: Query '{query}' had no exact section matches. Showing initial content]\n\n"
    return (notice + content[:max_chars], False)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.9.0", prog_name="minusparser")
def cli() -> None:
    """MinusParser: Enterprise-grade web content ingestion & discovery CLI for AI agents."""
    pass


@cli.command("read")
@click.argument("url", type=str)
@click.option("--max-chars", "-m", type=int, default=10000, help="Maximum characters to return.")
@click.option("--query", "-q", type=str, default=None, help="Filter sections matching keyword to save context tokens.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Emit output as structured JSON.")
@click.option("--plain", is_flag=True, default=False, help="Prefer plain text over markdown.")
@click.option("--wrap-provenance", is_flag=True, default=False, help="Wrap output in <untrusted_web_content> fences.")
@click.option("--quarantine", is_flag=True, default=False, help="Store payload in SQLite quarantine database.")
@click.option("--defang-images/--no-defang-images", default=True, help="Defang tracking pixels and exfiltration channels.")
@click.option("--defang-all-images", is_flag=True, default=False, help="Defang all external images.")
@click.option("--respect-robots", is_flag=True, default=False, help="Respect domain robots.txt rules.")
@click.option("--rate-limit", type=float, default=0.0, help="Enforce minimum seconds delay between domain requests.")
def read_cmd(
    url: str,
    max_chars: int,
    query: Optional[str],
    json_output: bool,
    plain: bool,
    wrap_provenance: bool,
    quarantine: bool,
    defang_images: bool,
    defang_all_images: bool,
    respect_robots: bool,
    rate_limit: float,
) -> None:
    """Fetch and parse clean, security-hardened content from URL.

    Exit codes:
      0: Clean content extracted successfully.
      1: Network, SSRF, or parsing error.
      2: Suspicious payload or indirect prompt injection detected.
    """
    async def _run() -> int:
        try:
            async with HardenedClient(respect_robots=respect_robots, rate_limit_delay=rate_limit) as client:
                extractor = ContentExtractor(client)
                result = await extractor.extract(
                    url=url,
                    max_chars=max_chars if not query else None,
                    prefer_markdown=not plain,
                    wrap_provenance=wrap_provenance,
                    defang_all_images=defang_all_images,
                )

                # Check if prompt injection was flagged by security filters
                injection_detected = bool(result.guardrails.get("prompt_injection_detected", False))
                redacted_count = len(result.guardrails.get("redacted_patterns", {}))
                defanged_count = result.guardrails.get("defanged_images_count", 0)

                # Diagnostic logging strictly to stderr
                if defanged_count > 0:
                    sys.stderr.write(f"[SECURITY] Defanged {defanged_count} tracking/exfiltration pixels.\n")
                if redacted_count > 0:
                    sys.stderr.write(f"[SECURITY] Redacted {redacted_count} sensitive secret patterns.\n")
                if injection_detected:
                    sys.stderr.write("[SECURITY ALERT] Potential indirect prompt injection detected in payload!\n")

                # Handle quarantine if requested or if threat detected
                if quarantine or (injection_detected and not json_output and not query):
                    with SQLiteResourceRegistry() as registry:
                        article_id = registry.store(
                            content=result.content,
                            url=result.url,
                            title=result.title or "Quarantined Web Payload",
                            content_format=result.content_format,
                            total_length=result.total_length,
                            guardrails=result.guardrails,
                            internal_links=result.internal_links,
                        )
                        handle = registry.get(article_id)
                        handle_data = handle.to_handle() if handle else {"article_id": article_id}

                    if json_output:
                        click.echo(json.dumps(handle_data, indent=2))
                    else:
                        click.echo(f"# [QUARANTINED PAYLOAD]")
                        click.echo(f"Article ID: {article_id}")
                        click.echo(f"Resource URI: resource://article/{article_id}")
                        click.echo(f"URL: {result.url}")
                        click.echo(f"Title: {result.title}")
                        click.echo(f"Total Chars: {result.total_length}")
                        click.echo("Status: Stored in air-gapped quarantine. Safe to inspect via unprivileged agent.")
                    return 2 if injection_detected else 0

                # Apply query filter for token budgeting if specified
                final_content = result.content
                if query:
                    final_content, matched = filter_content_by_query(result.content, query, max_chars)
                    if not matched:
                        sys.stderr.write(f"[NOTICE] No exact sections matched '{query}'. Truncated to max-chars.\n")

                if json_output:
                    payload = {
                        "url": result.url,
                        "title": result.title,
                        "content": final_content,
                        "content_format": result.content_format,
                        "is_truncated": result.is_truncated,
                        "total_length": result.total_length,
                        "guardrails": result.guardrails,
                        "internal_links": result.internal_links,
                        "is_spa_shell": result.is_spa_shell,
                    }
                    click.echo(json.dumps(payload, indent=2))
                else:
                    click.echo(final_content)

                return 2 if injection_detected else 0

        except RobotsDisallowedError as e:
            sys.stderr.write(f"[ERROR] Robots.txt Disallowed: {e}\n")
            return 1
        except RateLimitError as e:
            sys.stderr.write(f"[ERROR] Rate Limited: {e}\n")
            return 1
        except SSRFError as e:
            sys.stderr.write(f"[ERROR] SSRF Guardrail Blocked Request: {e}\n")
            return 1
        except PayloadTooLargeError as e:
            sys.stderr.write(f"[ERROR] Payload Too Large: {e}\n")
            return 1
        except Exception as e:
            sys.stderr.write(f"[ERROR] Ingestion Failed: {e}\n")
            return 1

    exit_code = asyncio.run(_run())
    sys.exit(exit_code)


@cli.command("discover")
@click.argument("url", type=str)
@click.option("--query", "-q", type=str, default=None, help="Filter discovered links by keyword.")
@click.option("--category", "-c", type=str, default=None, help="Filter by category or tag.")
@click.option("--limit", "-l", type=int, default=10, help="Maximum items to return.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Emit output as JSON.")
@click.option("--respect-robots", is_flag=True, default=False, help="Respect domain robots.txt rules.")
@click.option("--rate-limit", type=float, default=0.0, help="Enforce minimum seconds delay between domain requests.")
def discover_cmd(
    url: str,
    query: Optional[str],
    category: Optional[str],
    limit: int,
    json_output: bool,
    respect_robots: bool,
    rate_limit: float,
) -> None:
    """Discover articles, feeds, and sitemaps from a domain or blog URL."""
    async def _run() -> int:
        try:
            async with HardenedClient(respect_robots=respect_robots, rate_limit_delay=rate_limit) as client:
                engine = DiscoveryEngine(client)
                res = await engine.discover(url, query=query, category=category, limit=limit)

                items_data = [
                    {
                        "title": item.title,
                        "url": item.url,
                        "published": item.published,
                        "summary": item.summary,
                        "categories": item.categories,
                        "has_full_content": bool(item.full_content),
                        "source_strategy": item.source_strategy,
                    }
                    for item in res.items
                ]

                if json_output:
                    out = {
                        "strategy_used": res.strategy_used,
                        "feed_url": res.feed_url,
                        "count": len(items_data),
                        "items": items_data,
                    }
                    if res.fallback_hints:
                        out["fallback_hints"] = res.fallback_hints
                    click.echo(json.dumps(out, indent=2))
                else:
                    sys.stderr.write(f"[INFO] Discovery Strategy: {res.strategy_used}\n")
                    if res.feed_url:
                        sys.stderr.write(f"[INFO] Feed URL: {res.feed_url}\n")

                    if not items_data:
                        click.echo(f"No articles discovered for {url}.")
                        if res.fallback_hints:
                            click.echo("\nFallback Hints:")
                            for h in res.fallback_hints:
                                click.echo(f"- {h}")
                        return 0

                    click.echo(f"## Discovered Articles ({len(items_data)} matches):\n")
                    for i, item in enumerate(items_data, 1):
                        click.echo(f"{i}. **{item['title']}**")
                        click.echo(f"   URL: {item['url']}")
                        if item.get("published"):
                            click.echo(f"   Published: {item['published']}")
                        if item.get("summary"):
                            click.echo(f"   Summary: {item['summary'][:160]}...")
                        click.echo("")

                return 0

        except RobotsDisallowedError as e:
            sys.stderr.write(f"[ERROR] Robots.txt Disallowed: {e}\n")
            return 1
        except RateLimitError as e:
            sys.stderr.write(f"[ERROR] Rate Limited: {e}\n")
            return 1
        except SSRFError as e:
            sys.stderr.write(f"[ERROR] SSRF Blocked: {e}\n")
            return 1
        except Exception as e:
            sys.stderr.write(f"[ERROR] Discovery Failed: {e}\n")
            return 1

    exit_code = asyncio.run(_run())
    sys.exit(exit_code)


@cli.command("serve")
@click.option("--transport", "-t", type=click.Choice(["stdio", "sse"]), default="stdio", help="MCP transport protocol.")
@click.option("--port", "-p", type=int, default=8000, help="Port for SSE transport.")
@click.option("--host", "-h", type=str, default="localhost", help="Host for SSE transport.")
def serve_cmd(transport: str, port: int, host: str) -> None:
    """Launch the MinusParser Model Context Protocol (MCP) server."""
    from .server import mcp as server_instance
    sys.stderr.write(f"[MinusParser] Launching MCP server (transport={transport})...\n")
    if transport == "stdio":
        server_instance.run(transport="stdio")
    else:
        server_instance.run(transport="sse")


@cli.command("doctor")
def doctor_cmd() -> None:
    """Run system diagnostics: network egress, SSRF guards, and DB health."""
    sys.stderr.write("[MinusParser Doctor] Performing system diagnostic checks...\n\n")

    checks = []

    # 1. Python Runtime
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 10):
        checks.append(("Python Runtime", f"v{py_ver} ({sys.platform})", True))
    else:
        checks.append(("Python Runtime", f"v{py_ver} (Requires >= 3.10)", False))

    # 2. Critical Dependencies
    dependencies = [
        ("httpx", "httpx"),
        ("httpcore", "httpcore"),
        ("trafilatura", "trafilatura"),
        ("feedparser", "feedparser"),
        ("beautifulsoup4", "bs4"),
        ("click", "click"),
        ("mcp", "mcp"),
        ("brotli", "brotli"),
    ]
    for dep_name, mod_name in dependencies:
        try:
            mod = __import__(mod_name)
            ver = getattr(mod, "__version__", "available")
            checks.append((f"Package: {dep_name}", f"v{ver}", True))
        except ImportError:
            is_optional = dep_name == "brotli"
            checks.append((f"Package: {dep_name}", "NOT INSTALLED", is_optional))

    # 3. SSRF Guardrail Subnet Integrity
    try:
        loopback_blocked = is_ip_blocked("127.0.0.1")
        meta_blocked = is_ip_blocked("169.254.169.254")
        lan_blocked = is_ip_blocked("10.0.0.1")
        public_allowed = not is_ip_blocked("8.8.8.8")
        ssrf_healthy = loopback_blocked and meta_blocked and lan_blocked and public_allowed
        checks.append(("SSRF Guardrails", "All 4 subnet boundaries enforced", ssrf_healthy))
    except Exception as e:
        checks.append(("SSRF Guardrails", f"Verification failed: {e}", False))

    # 4. SQLite Quarantine Database Health
    try:
        with SQLiteResourceRegistry() as registry:
            test_id = registry.store(
                content="# Diagnostic Test Payload",
                url="https://doctor.minusparser.internal",
                title="Doctor Healthcheck",
                content_format="markdown",
                total_length=25,
                guardrails={},
                internal_links=[],
            )
            rec = registry.get(test_id)
            if rec and rec.article_id == test_id:
                checks.append(("Quarantine Database", f"WAL SQLite verified at {registry.db_path}", True))
            else:
                checks.append(("Quarantine Database", "Record read mismatch", False))
    except Exception as e:
        checks.append(("Quarantine Database", f"SQLite failure: {e}", False))

    # 5. Outbound Network & DNS Pinned Backend
    async def _test_dns() -> bool:
        test_urls = ["https://example.com", "https://httpbin.org/status/200"]
        for target_url in test_urls:
            try:
                async with HardenedClient(timeout=4.0) as client:
                    res = await client.get(target_url)
                    if res.status_code in (200, 301, 302):
                        return True
            except Exception:
                continue
        return False

    net_ok = asyncio.run(_test_dns())
    checks.append(("Outbound Egress & DNS", "HTTPS connection & pinned backend verified" if net_ok else "Outbound test failed or offline", net_ok))

    # Render Summary
    sep_line = "+--------------------------+--------------------------------------------------------+--------+"
    click.echo(sep_line)
    click.echo(f"| {'Check':<24} | {'Details':<54} | {'Status':<6} |")
    click.echo(sep_line)
    all_passed = True
    for name, details, status in checks:
        if not status:
            all_passed = False
        stat_str = click.style(" PASS ", fg="green", bold=True) if status else click.style(" FAIL ", fg="red", bold=True)
        det_clean = (details[:52] + "..") if len(details) > 54 else details
        click.echo(f"| {name:<24} | {det_clean:<54} | {stat_str} |")
    click.echo(sep_line)

    if all_passed:
        click.echo(click.style("\n[SUCCESS] MinusParser system environment is fully operational and hardened.\n", fg="green", bold=True))
        sys.exit(0)
    else:
        click.echo(click.style("\n[WARNING] One or more diagnostic checks failed. Review details above.\n", fg="yellow", bold=True))
        sys.exit(1)


@cli.group("skill")
def skill_group() -> None:
    """Manage AI Agent skill definitions (SKILL.md) for automated tool discovery."""
    pass


@skill_group.command("show")
@click.argument("subcommand", type=str, required=False, default=None)
@click.option("--json", "json_output", is_flag=True, default=False, help="Emit schema as machine-readable JSON.")
@click.pass_context
def skill_show(ctx: click.Context, subcommand: Optional[str], json_output: bool) -> None:
    """Print the complete static SKILL.md definition or dynamically introspect a specific subcommand schema."""
    if not subcommand:
        click.echo(SKILL_MD_CONTENT)
        return

    root_cli = ctx.find_root().command
    if not isinstance(root_cli, click.Group):
        click.echo("Error: Root command is not a Group.", err=True)
        ctx.exit(1)

    cmd = root_cli.get_command(ctx, subcommand)
    if not cmd:
        available = [c for c in root_cli.list_commands(ctx) if c != "skill"]
        click.echo(f"Unknown subcommand '{subcommand}'. Available commands: {', '.join(available)}", err=True)
        ctx.exit(1)

    params_data = []
    for param in cmd.params:
        params_data.append({
            "name": param.name,
            "opts": list(param.opts) if hasattr(param, "opts") else [param.name],
            "type": param.type.name if hasattr(param.type, "name") else str(param.type),
            "required": param.required,
            "default": param.default,
            "help": getattr(param, "help", "") or "",
        })

    if json_output:
        schema = {
            "command": subcommand,
            "help": cmd.help or "",
            "parameters": params_data,
        }
        click.echo(json.dumps(schema, indent=2))
    else:
        click.echo(f"# Command Schema: `minusparser {subcommand}`\n")
        click.echo(f"{cmd.help or 'No description provided.'}\n")
        click.echo("## Parameters & Options:\n")
        for p in params_data:
            flags = ", ".join(f"`{o}`" for o in p["opts"])
            req_str = "**[REQUIRED]**" if p["required"] else f"(default: `{p['default']}`)"
            click.echo(f"- {flags} ({p['type']}) {req_str}: {p['help']}")



@skill_group.command("install")
@click.option(
    "--target",
    "-t",
    type=click.Choice(["auto", "antigravity", "cursor", "claude", "stdout"]),
    default="auto",
    help="Target agent harness.",
)
@click.option("--dest", "-d", type=click.Path(), default=None, help="Explicit destination directory or file path.")
@click.option("--force", "-f", is_flag=True, default=False, help="Overwrite existing skill file without prompt.")
def skill_install(target: str, dest: Optional[str], force: bool) -> None:
    """Install or export SKILL.md into local agent environment."""
    if target == "stdout":
        click.echo(SKILL_MD_CONTENT)
        return

    # Determine target filepath
    out_path: pathlib.Path

    if dest:
        p = pathlib.Path(dest).resolve()
        if p.is_dir() or dest.endswith(("/", "\\")):
            out_path = p / ("SKILL.md" if target != "cursor" else "minusparser.mdc")
        else:
            out_path = p
    elif target == "cursor":
        out_path = pathlib.Path.cwd() / ".cursor" / "rules" / "minusparser.mdc"
    elif target == "claude":
        out_path = pathlib.Path.cwd() / ".claude" / "skills" / "minusparser" / "SKILL.md"
    elif target == "antigravity":
        # Check ~/.gemini/config/skills/minusparser/SKILL.md or workspace .agents
        gemini_home = pathlib.Path.home() / ".gemini" / "config" / "skills" / "minusparser"
        out_path = gemini_home / "SKILL.md"
    else:  # auto
        cwd = pathlib.Path.cwd()
        if (cwd / ".cursor").is_dir():
            out_path = cwd / ".cursor" / "rules" / "minusparser.mdc"
        elif (cwd / ".agents").is_dir():
            out_path = cwd / ".agents" / "skills" / "minusparser" / "SKILL.md"
        elif (pathlib.Path.home() / ".gemini").is_dir():
            out_path = pathlib.Path.home() / ".gemini" / "config" / "skills" / "minusparser" / "SKILL.md"
        else:
            out_path = cwd / "SKILL.md"

    if out_path.exists() and not force:
        sys.stderr.write(f"[WARN] File already exists at {out_path}. Use --force to overwrite.\n")
        sys.exit(1)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(SKILL_MD_CONTENT, encoding="utf-8")

    sys.stderr.write(f"[SUCCESS] Agent skill installed to: {out_path}\n")
    click.echo(f"Installed MinusParser skill to {out_path}")
    click.echo("AI agents can now discover and invoke 'minusparser' in this environment.")


# Convenience alias: minusparser setup-agent
@cli.command("setup-agent")
@click.option("--target", "-t", type=click.Choice(["auto", "antigravity", "cursor", "claude", "stdout"]), default="auto")
@click.option("--dest", "-d", type=click.Path(), default=None)
@click.option("--force", "-f", is_flag=True, default=False)
@click.pass_context
def setup_agent_alias(ctx: click.Context, target: str, dest: Optional[str], force: bool) -> None:
    """Convenience alias for 'minusparser skill install'."""
    ctx.forward(skill_install)


def main() -> None:
    """CLI script entrypoint."""
    cli()


if __name__ == "__main__":
    main()
