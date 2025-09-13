# BugBounty MCP Server AI Agent Guide

This is a Model Context Protocol (MCP) server that provides 92+ security testing tools for bug bounty hunting and penetration testing through natural language conversations with LLMs.

## Architecture Overview

### MCP Server Structure
- **Entry Point**: `run.sh` script activates venv and starts `bugbounty-mcp serve`
- **Main Server**: `server.py` implements MCP protocol with 8 tool categories
- **Tool Organization**: Each category in `tools/` inherits from `BaseTools` with standardized patterns
- **Configuration**: Pydantic-based config in `config.py` with environment variable loading

### Critical Tool Categories (92+ total tools)
```
ReconTools (13)      → Subdomain enum, DNS, WHOIS, cert transparency
ScanningTools (15)   → Port/service scanning, directory bruteforce, nuclei
VulnerabilityTools   → SQLi, XSS, command injection, auth bypass
WebApplicationTools  → API testing, file upload, session analysis  
NetworkTools (10)    → Network discovery, firewall detection
OSINTTools (10)      → Person/company investigation, dark web
ExploitationTools    → Payload generation, privilege escalation
ReportingTools (10)  → Vulnerability reports, compliance mapping
```

## Development Patterns

### Tool Implementation Pattern
```python
# All tools inherit from BaseTools in tools/base.py
class NewToolCategory(BaseTools):
    def get_tools(self) -> List[Tool]:
        # Return MCP Tool objects with JSON Schema
    
    async def tool_method(self, **kwargs) -> str:
        # 1. Rate limiting: await self.rate_limit()
        # 2. Target validation: self.check_target_allowed(target)
        # 3. Caching: result = self.get_cached(cache_key)
        # 4. External tool execution via utils.run_command_async()
        # 5. Return formatted results via self.format_result()
```

### Configuration System
- **Environment Loading**: `.env` file auto-loaded, API keys from ENV vars
- **Pydantic Models**: Nested config (APIKeys, ToolConfig, ScanConfig, OutputConfig)
- **Safety Features**: `allowed_targets`, `blocked_targets`, `safe_mode` for responsible testing
- **Tool Paths**: Auto-detection in PATH with fallback to custom paths

### Key Utilities (`utils.py`)
```python
validate_target()      # Parse domains/IPs/URLs with comprehensive validation
run_command_async()    # Execute external security tools (nmap, nuclei, etc)
RateLimiter           # Async rate limiting for API calls
Cache                 # TTL-based caching for expensive operations
```

## Working with This Codebase

### Adding New Security Tools
1. Choose appropriate category in `tools/` or create new one
2. Inherit from `BaseTools` and implement required methods
3. Use `Tool` objects with proper JSON Schema for input validation
4. Follow the standard pattern: rate limit → validate → cache check → execute → format
5. Add external tool paths to `ToolConfig` in `config.py`

### Integration Points
- **External Tools**: Expects nmap, nuclei, subfinder, gobuster, etc. in PATH
- **API Services**: Shodan, Censys, VirusTotal, GitHub tokens via environment
- **MCP Protocol**: Server runs stdio transport for LLM integration
- **Safety Validation**: All tools check target allowlists before execution

### CLI Commands (via run.sh)
```bash
./run.sh serve                    # Start MCP server
./run.sh validate-config          # Check tool availability & API keys  
./run.sh list-tools              # Show all 92+ available tools
./run.sh quick-scan -t domain.com # Demo scan workflow
./run.sh download-wordlists       # Fetch SecLists wordlists
```

### Common Debugging
- **Tool Not Found**: Check `validate-config` for missing binaries in PATH
- **API Failures**: Verify environment variables for service API keys
- **Target Blocked**: Check `allowed_targets`/`blocked_targets` in config
- **MCP Issues**: Server logs to console, check stdio communication

### Project-Specific Conventions
- **Async Everything**: All tool methods are async for concurrent execution
- **Structured Results**: Use `format_result()` for consistent output formatting
- **External Tool Wrapping**: Shell commands via `run_command_async()` with timeout/retry
- **Safety First**: Target validation and rate limiting are mandatory patterns
- **Configuration Override**: Environment variables always take precedence over defaults

### File Structure Significance
- `wordlists/` → Downloaded SecLists for bruteforce attacks
- `output/` → Scan results and generated reports  
- `data/` → Persistent storage and caching
- `cache/` → Temporary cache files
- `logs/` → Application logs

The codebase emphasizes security tool orchestration through natural language, with robust safety controls and standardized patterns for adding new security testing capabilities.