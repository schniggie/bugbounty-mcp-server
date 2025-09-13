# Usage Guide

This guide provides detailed examples of how to use the BugBounty MCP Server for various security testing scenarios.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Reconnaissance](#basic-reconnaissance)
3. [Web Application Testing](#web-application-testing)
4. [Network Security Assessment](#network-security-assessment)
5. [Vulnerability Assessment](#vulnerability-assessment)
6. [OSINT Gathering](#osint-gathering)
7. [Reporting and Analysis](#reporting-and-analysis)
8. [Advanced Workflows](#advanced-workflows)

## Getting Started

### First Run

#### Docker Method (Recommended)

The easiest way to get started is with Docker:

```bash
# Navigate to the project directory
cd bugbounty-mcp-server

# Build and run with Docker Compose
docker-compose up --build -d

# Or use the Docker management script
chmod +x docker.sh
./docker.sh build
./docker.sh run --api-keys

# Validate setup
./docker.sh validate

# View logs
./docker.sh logs --follow
```

#### Native Method

After installation, validate your setup using the convenient `run.sh` script:

```bash
# Navigate to the project directory
cd bugbounty-mcp-server

# Check configuration and tool availability
./run.sh validate-config

# List all 92+ available tools
./run.sh list-tools

# Start the MCP server
./run.sh serve
```

### Basic Configuration

Create and customize a configuration file:

```bash
# Export default config template
./run.sh export-config --format yaml -o config.yaml

# Edit the configuration
nano config.yaml

# Copy environment template and configure API keys
cp env.example .env
nano .env

# Start with custom config
./run.sh --config config.yaml serve
```

### Quick Commands Reference

```bash
# All commands use the convenient run.sh wrapper:

./run.sh --help                              # Show all available commands
./run.sh serve                               # Start MCP server
./run.sh validate-config                     # Validate setup
./run.sh list-tools                          # List all tools
./run.sh quick-scan --target example.com     # Quick security scan
./run.sh download-wordlists --type subdomains # Download wordlists
./run.sh export-config --format yaml         # Export config template
```

## Basic Reconnaissance

### Subdomain Discovery

Natural language examples for LLM interaction:

```
"Perform comprehensive subdomain enumeration for example.com using:
- Certificate transparency logs
- DNS enumeration  
- Search engine dorking
- Third-party APIs
- Brute force with common subdomains"
```

Tool calls that would be executed:
- `subdomain_enumeration` with passive and brute force options
- `certificate_transparency` to find SSL certificate subdomains
- `dns_enumeration` for DNS records
- `google_dorking` for search engine results

### Domain Intelligence

```
"Gather intelligence on example.com including:
- WHOIS information
- DNS records and nameservers
- SSL certificate details
- Technology stack detection
- Archive.org historical data"
```

### Infrastructure Analysis

```
"Analyze the infrastructure of example.com:
- Check if it uses a CDN and identify the provider
- Find the origin server IP if behind a CDN
- Detect load balancers and their configuration
- Identify web application firewalls"
```

## Web Application Testing

### Basic Web Assessment

```
"Perform a comprehensive security assessment of https://example.com:
1. Crawl the website to discover all pages and endpoints
2. Scan for hidden directories and files
3. Analyze HTTP security headers
4. Test for common vulnerabilities (XSS, SQLi, etc.)
5. Check for security misconfigurations"
```

### Specific Vulnerability Testing

```
"Test the login form at https://example.com/login for:
- SQL injection in username and password fields
- Cross-site scripting (XSS) vulnerabilities
- Authentication bypass techniques
- Session management issues
- CSRF protection"
```

### API Security Testing

```
"Analyze the API at https://api.example.com:
- Discover all available endpoints
- Test HTTP methods (GET, POST, PUT, DELETE, OPTIONS)
- Check for rate limiting
- Verify authentication mechanisms
- Test for injection vulnerabilities in parameters"
```

## Network Security Assessment

### Port Scanning

```
"Perform network reconnaissance on 192.168.1.0/24:
- Discover live hosts
- Scan for open ports on discovered hosts
- Enumerate services running on open ports
- Identify potential security issues"
```

### Service Analysis

```
"Analyze the services running on 192.168.1.100:
- Perform comprehensive port scan
- Enumerate service versions and banners
- Check for known vulnerabilities in identified services
- Test for default credentials"
```

### Network Infrastructure

```
"Analyze the network infrastructure for example.com:
- Trace the route to the server
- Identify network devices and potential firewalls
- Check for proxy servers or load balancers
- Analyze network latency and performance"
```

## Vulnerability Assessment

### Comprehensive Vulnerability Scan

```
"Perform a complete vulnerability assessment of https://example.com:
1. Run automated vulnerability scans using Nuclei
2. Test for OWASP Top 10 vulnerabilities
3. Check for known CVEs affecting the technology stack
4. Analyze SSL/TLS configuration for weaknesses
5. Generate a prioritized remediation plan"
```

### Input Validation Testing

```
"Test input validation on https://example.com/contact:
- Test all form fields for injection vulnerabilities
- Check file upload functionality for security issues
- Verify proper input sanitization and validation
- Test for buffer overflow conditions"
```

### Session Security

```
"Analyze session management on https://example.com:
- Test session token generation and randomness
- Check for session fixation vulnerabilities
- Verify proper session expiration
- Test for concurrent session handling"
```

## OSINT Gathering

### Company Intelligence

```
"Gather comprehensive intelligence on Example Corp:
- Corporate information and registration details
- Key personnel and organizational structure
- Technology stack and infrastructure
- Recent news and security incidents
- Social media presence and employee information"
```

### Person Investigation

```
"Investigate John Doe, CEO of Example Corp:
- Search across social media platforms
- Check for data breaches containing his information
- Look for professional profiles and connections
- Search for any public records or documents"
```

### Data Breach Analysis

```
"Check if example.com or its employees have been involved in data breaches:
- Search breach databases for domain exposure
- Check common employee email patterns
- Analyze leaked credentials and their impact
- Provide recommendations for risk mitigation"
```

## Reporting and Analysis

### Vulnerability Report Generation

```
"Generate a comprehensive vulnerability report for the assessment of example.com including:
- Executive summary with business impact
- Detailed technical findings with proof of concepts
- Risk assessment and prioritization
- Remediation recommendations with timelines
- Compliance mapping to relevant frameworks"
```

### Metrics and Trends

```
"Create a security metrics dashboard showing:
- Vulnerability trends over the last quarter
- Time to remediation for different severity levels
- Scan coverage across all assets
- Compliance posture against OWASP Top 10"
```

### Risk Assessment

```
"Perform a comprehensive risk assessment considering:
- Identified vulnerabilities and their exploitability
- Business impact of potential security incidents
- Current threat landscape and attack trends
- Existing security controls and their effectiveness"
```

## Advanced Workflows

### Multi-Target Assessment

```
"Perform a comprehensive security assessment of the following targets:
- example.com (main website)
- api.example.com (API endpoints)
- admin.example.com (admin panel)
- 192.168.1.0/24 (internal network)

Include reconnaissance, vulnerability scanning, and risk analysis for each."
```

### Continuous Monitoring Setup

```
"Set up continuous security monitoring for example.com:
1. Schedule regular subdomain enumeration
2. Monitor paste sites for leaked credentials
3. Track dark web mentions of the company
4. Set up automated vulnerability scanning
5. Create alerting for new security issues"
```

### Red Team Simulation

```
"Simulate a red team attack against example.com:
1. Start with passive reconnaissance to avoid detection
2. Identify potential entry points and attack vectors
3. Develop custom exploits for identified vulnerabilities
4. Plan lateral movement within the network
5. Document the complete attack chain for blue team training"
```

## Command Line Examples

### Basic Operations

```bash
# Quick reconnaissance
bugbounty-mcp quick-scan -t example.com

# Validate configuration
bugbounty-mcp validate-config

# Download wordlists
bugbounty-mcp download-wordlists --type subdomains
bugbounty-mcp download-wordlists --type directories
```

### Configuration Management

```bash
# Export configuration template
bugbounty-mcp export-config --format yaml -o my-config.yaml

# Start with custom configuration
bugbounty-mcp --config my-config.yaml serve

# Enable verbose logging
bugbounty-mcp --verbose serve
```

## Integration Examples

### LLM Integration Configurations

#### Claude Desktop Configuration

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "bugbounty": {
      "command": "bugbounty-mcp",
      "args": ["serve"],
      "env": {
        "SHODAN_API_KEY": "your_key_here",
        "VIRUSTOTAL_API_KEY": "your_key_here"
      }
    }
  }
}
```

#### VS Code with GitHub Copilot Configuration

**For Docker Deployment (Network Socket - Recommended):**

1. Start the Docker container with MCP server on port 3001:
   ```bash
   docker-compose up --build -d
   ```

2. Configure VS Code MCP settings (`Cmd/Ctrl + ,`):
   ```json
   {
     "mcp.servers": {
       "bugbounty-docker": {
         "command": "nc",
         "args": ["localhost", "3001"],
         "description": "BugBounty MCP Server (Docker Network)",
         "capabilities": {
           "tools": true,
           "resources": true
         }
       }
     }
   }
   ```

**For Native Installation:**

```json
{
  "mcp.servers": {
    "bugbounty-native": {
      "command": "/path/to/bugbounty-mcp-server/run.sh",
      "args": ["serve"],
      "description": "BugBounty MCP Server (Native)",
      "env": {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

**Verification Steps:**

1. Restart VS Code or reload MCP extension
2. Check MCP panel for connected servers  
3. Test with GitHub Copilot: "List available security tools"

### Custom Client Integration

Example Python client:

```python
import asyncio
from mcp import ClientSession, StdioServerParameters

async def run_security_scan():
    async with ClientSession(StdioServerParameters(
        command="bugbounty-mcp",
        args=["serve"]
    )) as session:
        
        # List available tools
        tools = await session.list_tools()
        print(f"Available tools: {len(tools.tools)}")
        
        # Perform subdomain enumeration
        result = await session.call_tool(
            "subdomain_enumeration",
            {"domain": "example.com", "passive": True}
        )
        print(result.content[0].text)

if __name__ == "__main__":
    asyncio.run(run_security_scan())
```

## Best Practices

### Target Preparation

1. **Obtain explicit authorization** before testing
2. **Define scope clearly** with stakeholders
3. **Set up isolated testing environment** when possible
4. **Configure rate limiting** to avoid disruption

### Testing Methodology

1. **Start with passive reconnaissance** to gather intelligence
2. **Progress to active scanning** with appropriate caution
3. **Document all activities** for audit trails
4. **Verify findings manually** before reporting
5. **Follow responsible disclosure** for any discoveries

### Results Management

1. **Organize findings by severity** and business impact
2. **Provide clear remediation guidance** for each issue
3. **Include proof of concepts** for confirmed vulnerabilities
4. **Track remediation progress** over time
5. **Generate executive summaries** for stakeholders

---

For more detailed information on specific tools and their parameters, use the `list-tools` command or refer to the individual tool documentation within the codebase.
