# MinusParser: High-Performance Local Web Reader & Sanitizer for AI Agents

> **When your AI agent reads a webpage, that page can hijack it, leak secrets, or blow out its context window with 80,000 tokens of junk. MinusParser stops that.**

MinusParser is a high-performance, security-hardened web ingestion engine and CLI for AI coding tools (Antigravity, Cursor, Claude Code) and autonomous LLM pipelines. It defangs tracking pixels, blocks SSRF and 0-TTL DNS rebinding at the socket level, sanitizes indirect prompt injections, and delivers clean, token-budgeted Markdown stripped of HTML boilerplate.

## Architecture

```mermaid
flowchart LR
    A[AI Agent / Pipeline] -->|CLI / SDK / MCP| B(MinusParser Ingress Engine)
    B -->|Fast DNS Check| C{SSRF & 0-TTL Pinning}
    C -->|Blocked LAN/Cloud Meta| D[Exit Code 1 / SSRFError]
    C -->|Validated Public IP| E[Pinned TCP Socket]
    E --> F[Content Extraction Engine]
    F --> G{Security Guardrails}
    G -->|Defang Pixels & Redact Secrets| H[Token-Budgeted Markdown]
    G -->|Indirect Prompt Injection Detected| I[Exit Code 2 / SQLite Quarantine]
    H --> A
```

## The Air-Gapped Privacy & Security Moat

Unlike cloud-hosted scrapers (such as Firecrawl or Jina Reader) that route your URLs and company data through third-party servers:
* **100% Local & Air-Gapped**: Runs entirely on your local machine or private cluster. Zero third-party data egress, zero external proxy logging.
* **Socket-Level SSRF Hardening**: Blocks loopback, cloud metadata (`169.254.169.254`), and 0-TTL DNS rebinding directly at the socket level before connection.
* **Opportunistic Ingress Hygiene**: Neutralizes tracking pixels and redacts live credentials (AWS, GitHub, OpenAI, Anthropic keys) before returning text to your LLM.
* **Epistemic Taint Tracking**: Separates trusted system metadata from untrusted web-derived text at the type level.
* **Web Politeness & Anti-Ban Safeguards**: Honors target domain `robots.txt` directives, enforces per-domain rate-limits, and respects HTTP 429 `Retry-After` headers.

## Installation

```bash
# Standard installation
pip install minusparser

# Or install from source for local development
git clone https://github.com/minusbrain/minusparser.git
cd minusparser
pip install -e .
```

---

## 1. MinusParser CLI

MinusParser provides a high-performance command line interface engineered with strict `stdout`/`stderr` stream discipline for autonomous AI agents.

### Read Web Content (`minusparser read`)
```bash
# Clean markdown extraction
minusparser read https://example.com/blog/article

# Token-budgeted extraction: Only retrieve sections matching a keyword
minusparser read https://example.com/blog/article --query "vector search" --max-chars 4000

# Structured JSON metadata output
minusparser read https://example.com/blog/article --json

# Defend against untrusted payloads: Quarantine directly to local SQLite
minusparser read https://suspicious-site.com --quarantine

# Polite crawler hygiene: Respect robots.txt and enforce rate limiting
minusparser read https://example.com/blog/article --respect-robots --rate-limit 0.5
```

**Standard Exit Codes:**
- `0`: Success (clean content extracted).
- `1`: Error (network, parse failure, SSRF blocked, or robots.txt disallowed).
- `2`: Threat Detected (prompt injection or suspicious payload quarantined).

### Discover Domain Articles (`minusparser discover`)
```bash
# Discover RSS feeds, sitemaps, and llms.txt entries
minusparser discover https://databricks.com/blog --query "data engineering" --limit 5

# Discover with polite crawling rules
minusparser discover https://databricks.com/blog --respect-robots --rate-limit 1.0
```

### Install Agent Skill (`minusparser skill install` or `setup-agent`)
```bash
# Automatically install SKILL.md into Antigravity, Cursor (.mdc), or Claude Code
minusparser skill install --target antigravity
minusparser setup-agent --target cursor
```

### Run Diagnostics (`minusparser doctor`)
```bash
# Verify Python runtime, SSRF guardrails, DNS pinning, SQLite DB, and dependencies
minusparser doctor
```

### Launch MCP Server (`minusparser serve`)
```bash
# Run over stdio for Claude Desktop / Cursor
minusparser serve --transport stdio
```

---

## 2. Python SDK (`safe_read`)

For agents executing Python in-memory, use the 1-liner typed SDK to eliminate subprocess and JSON-RPC overhead:

```python
from minusparser import safe_read, ArticleAnalysis

# Ingest and sanitize web content with epistemic taint classification
analysis = safe_read("https://example.com/article", schema=ArticleAnalysis)

print(analysis.summary)
print("Untrusted fields:", analysis._taint_report.untrusted_fields)
print("Trusted metadata:", analysis._taint_report.trusted_system_fields)
```

---

## 3. MCP Server Configuration

To register MinusParser with an MCP client (such as Claude Desktop, Cursor, or Windsurf), add it to your MCP client configuration (`claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "minusparser": {
      "command": "minusparser",
      "args": ["serve"]
    }
  }
}
```

Or when running within a specific Python virtual environment:

```json
{
  "mcpServers": {
    "minusparser": {
      "command": "python",
      "args": ["-m", "domain_reader.server"]
    }
  }
}
```

## Tool Documentation

### 1. `discover_content`
Discover articles and content on any website. Automatically tries RSS/Atom feeds first, then sitemaps, then suggests direct URLs.

**Parameters**:
- `url` (string): Any website URL
- `query` (string, optional): Keyword filter
- `category` (string, optional): Tag filter
- `limit` (int, default 10): Max results

**Example JSON Call**:
```json
{
  "url": "https://www.databricks.com/blog",
  "limit": 5
}
```

### 2. `read_web_article`
Fetch and read the full content of any web article or blog post, returned in a clean format.

**Parameters**:
- `url` (string): Full URL of the article
- `max_chars` (int, default 10000): Character limit
- `prefer_markdown` (bool, default true): Markdown format

**Example JSON Call**:
```json
{
  "url": "https://www.databricks.com/blog/example-article",
  "max_chars": 5000,
  "prefer_markdown": true
}
```

### 3. `read_feed_article`
Reads pre-fetched feed entries or falls back to full URL extraction.

**Parameters**:
- `url` (string): Article URL
- `feed_content` (string, optional): Pre-fetched content
- `max_chars` (int, default 10000): Character limit
- `prefer_markdown` (bool, default true): Markdown format

### 4. `quarantine_web_article` (Air-Gapped Quarantine)
Fetches and sanitizes any web article, storing the untrusted payload **out-of-band** in the native MCP Resource Registry. Protects privileged orchestrators from Indirect Prompt Injections (IPI) by returning **only** an opaque reference handle and metadata without leaking raw untrusted text into the primary tool response context.

**Parameters**:
- `url` (string): Article URL to extract and quarantine
- `prefer_markdown` (bool, default true): Markdown format

**Returns**:
```json
{
  "status": "quarantined",
  "article_id": "547de81a8632694c",
  "resource_uri": "resource://article/547de81a8632694c",
  "title": "Article Title",
  "url": "https://example.com/article",
  "char_count": 6167,
  "guardrails": {"is_safe": true, "injections_detected": 0, ...},
  "internal_links": [{"text": "Doc 1", "url": "..."}],
  "message": "Content stored in air-gapped MCP resource. Read via Quarantined Worker using resource_uri."
}
```

## Native MCP Resources
- **`resource://article/{article_id}`**:
  Allows unprivileged reader agents (quarantined workers) to read quarantined payloads out-of-band using standard MCP resource fetching (`mcp.read_resource(...)`), ensuring privileged orchestrator contexts remain clean.

## Dual-LLM Reference Architecture & Attack Defense
To resolve the **Confused Deputy Problem** described in *"LLM Guardrail Bypass Analysis"*, MinusParser provides a production-grade Dual-LLM reference implementation in [`examples/dual_llm_agent.py`](examples/dual_llm_agent.py):
- **Privileged Planner LLM**: Holds executive tools (databases, shell, alerting), but **never** ingests untrusted text. Ingests only validated Pydantic models (`ArticleAnalysis`, with `extra="forbid"`).
- **Quarantined Reader LLM**: Isolated worker with **zero tools** and **zero network authority**. Ingests untrusted markdown fenced by `<untrusted_web_content>` and outputs strictly typed JSON.
- **Deterministic Orchestrator**: Brokers opaque memory handles (`$CONTENT_REF_...`) and enforces hard air-gaps.
- **Attack Simulation Suite**: [`test_dual_llm_attack.py`](test_dual_llm_attack.py) empirically verifies 100% containment across SQL injection drops, remote shell pipes (`curl | bash`), and exfiltration directives where monolithic single-agents fail.

## Invisible Security: One-Liner SDK (`safe_read`)

For developers who want ironclad security without writing manual dual-agent plumbing:

```python
from minusparser import safe_read, ArticleAnalysis

# 1-liner secure ingestion pipeline:
analysis, handle = await safe_read(
    "https://example.com/blog/article",
    respect_robots=True,
    rate_limit_delay=0.5,
)

print("Title:", analysis.title)
print("Summary:", analysis.summary)
print("Opaque Handle:", handle["resource_uri"])

# Epistemic Taint Inspection:
print("Is title tainted?", analysis.is_tainted("title"))  # True (web-derived)
print("Is handle tainted?", analysis.is_tainted("raw_content_handle"))  # False (system-verified)
```

## Production Hardening & Operational Resilience
1. **0-TTL DNS Rebinding SSRF Protection (Pinned IP Socket)**:
   `HardenedClient` and `PinnedNetworkBackend` resolve and validate DNS at connection time, pinning the exact validated IP literal directly in `connect_tcp` while maintaining original SNI hostnames for TLS. 0-TTL rebinding attacks to `169.254.169.254` are mathematically blocked at the socket level.

2. **Streaming Decompression Bomb & Memory Guard**:
   Streams decompressed chunks with threshold limits, aborting in-flight if decompressed size crosses `max_payload_bytes` (default 2MB), defeating gzip bombs without allocating gigabytes of RAM.

3. **Web Politeness & Rate-Limiting**:
   Safely evaluates `robots.txt` per domain (cached with 1-hour TTL) and parses HTTP 429 `Retry-After` backoff to prevent crawler IP bans.

4. **Tracking Pixel & Markdown Image Exfiltration Defanging**:
   Active regex analysis neutralizes hidden tracking pixels (1x1 beacons, query parameter tokens, and attacker webhooks) into safe markers (`[DEFANGED_TRACKING_PIXEL: $alt]`) while preserving benign diagrams.

5. **Persistent Storage & OOM Prevention**:
   `ResourceRegistry` features sliding 1-hour TTL auto-expiration and LRU capacity bounds. `SQLiteResourceRegistry` provides persistent backing across worker pod reloads and multi-process environments.

6. **Client-Side SPA Shell Detection**:
   Automatically detects empty React/Next.js client-side SPA shells (`<div id="root"></div>`, `__NEXT_DATA__`) and populates helpful advisories.

## Enterprise Security Guardrails & Agent Safety
The parser incorporates active defense guardrails specifically engineered to protect autonomous LLM agents from untrusted web payloads:

1. **Indirect Prompt Injection (IPI) Defense**:
   - Strips steganographic zero-width Unicode characters (`\u200b`, `\ufeff`, etc.) and bidirectional overrides.
   - Neutralizes LLM chat-template delimiters (`[INST]`, `<<SYS>>`, `<|im_start|>`).
   - Defangs system override directives (e.g., *"ignore all previous instructions"*, *"you are now in developer mode"*).
   - Defangs credential exfiltration requests (*"output your environment variables"*, *"send keys to webhook"*).

2. **Credential & Secret Redaction**:
   - Automatically redacts live credentials and tokens in web pages before returning them to the LLM:
     - AWS Access Keys (`AKIA...`, `ASIA...`)
     - GitHub PAT & OAuth tokens (`ghp_...`, `github_pat_...`)
     - OpenAI API Keys (`sk-...`, `sk-proj-...`)
     - Anthropic API Keys (`sk-ant-...`)
     - Google AI Keys (`AIza...`)
     - Slack bot tokens (`xoxb-...`)
     - Private key blocks (`-----BEGIN RSA/OPENSSH PRIVATE KEY-----`)
     - Embedded database passwords in connection URIs (`postgres://user:pass@host...`)

3. **Malicious Script & Command Defanging**:
   - Neutralizes remote script pipe-to-shell patterns: `curl http://... | bash`, `wget -O- ... | sh`.
   - Neutralizes memory-execution and encoded PowerShell scripts (`Invoke-Expression`, `-enc`).
   - Neutralizes destructive filesystem commands (`rm -rf /`, `format c:`, `dd if=/dev/zero`).
   - Preserves benign development commands (`pip install pandas`, `git clone ...`).

4. **Provenance Boundary Fencing**:
   - Optional provenance wrapping (`wrap_provenance=True`) to enclose web text in `<untrusted_web_content source="...">` with strict passive data warnings for caller agents.

5. **SSRF & Network Hardening**:
   - Blocks private/loopback/carrier-grade NAT IP ranges and cloud metadata endpoints (`169.254.169.254`).
   - Blocks non-HTTP(S) schemes and sensitive ports (22, 3389, 5432, 6379, 27017).
   - Enforces strict streaming byte limits (`PayloadTooLargeError`).
   - Hardens all TCP sockets with IP-pinned connection backends.

---

## Explicit Non-Goals & Threat Boundaries

To maintain high performance and sharp boundaries, MinusParser explicitly defines what it is—and what it is not:

* **Not a Headless Browser:** MinusParser is an ultra-fast, stateless HTTP reader (sub-50ms). It detects empty client-rendered React/Next.js shells (`<div id="root"></div>`) and flags them with advisories, but does not execute JavaScript or bundle a 500MB Chromium instance. For dynamic interactive browsing, pipe web pages through browser sidecars.
* **Not an OS Sandbox:** MinusParser sanitizes incoming untrusted data streams to protect the LLM. It does not replace OS-level isolation (Docker, gVisor, Firecracker) for executing code generated by agents.
* **Opportunistic Defense vs. Formal Proofs:** Natural language prompt injection is an open AI safety challenge. MinusParser provides deterministic pattern neutralization and type-level epistemic taint tracking (`taint=UNTRUSTED_WEB_DERIVED`), enabling downstream agents to isolate untrusted fields rather than blindly executing them.

