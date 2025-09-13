# BugBounty MCP Server

A comprehensive Model Context Protocol (MCP) server for bug bounty hunting and web application penetration testing. This tool allows you to perform extensive security testing through natural language conversations with an LLM.

## 🚀 Features

### 🔍 Reconnaissance (13 Tools)
- **Subdomain Enumeration**: Passive and active subdomain discovery
- **DNS Enumeration**: Comprehensive DNS record analysis
- **WHOIS Lookup**: Domain registration and ownership information
- **Certificate Transparency**: SSL certificate log analysis
- **Google Dorking**: Automated search engine reconnaissance
- **Shodan/Censys Integration**: IoT and service discovery
- **GitHub Reconnaissance**: Code repository analysis
- **Archive.org Search**: Historical website analysis
- **Technology Detection**: Web stack fingerprinting
- **Social Media Search**: OSINT across platforms
- **Email Enumeration**: Email address discovery
- **Reverse DNS**: IP to hostname resolution
- **WAF Detection**: Web Application Firewall identification

### 🌐 Scanning (15 Tools)
- **Port Scanning**: Comprehensive network port analysis
- **Service Enumeration**: Detailed service fingerprinting
- **Web Directory Scanning**: Hidden file/directory discovery
- **Web Crawling**: Automated website exploration
- **Parameter Discovery**: Hidden parameter identification
- **Subdomain Takeover**: Vulnerability detection
- **SSL/TLS Analysis**: Certificate security assessment
- **CMS Scanning**: WordPress/Drupal/Joomla analysis
- **JavaScript Analysis**: Client-side security review
- **HTTP Methods Testing**: Verb tampering detection
- **CORS Analysis**: Cross-origin policy testing
- **Security Headers**: HTTP header security analysis
- **Nuclei Integration**: Vulnerability template scanning
- **Fuzzing**: Input validation testing
- **API Endpoint Discovery**: REST/GraphQL/SOAP analysis

### 🛡️ Vulnerability Assessment (15 Tools)
- **SQL Injection Testing**: Automated SQLi detection
- **XSS Testing**: Cross-site scripting analysis
- **Command Injection**: OS command execution testing
- **File Inclusion (LFI/RFI)**: Path traversal analysis
- **XXE Testing**: XML external entity detection
- **SSRF Testing**: Server-side request forgery
- **IDOR Testing**: Insecure direct object reference
- **CSRF Testing**: Cross-site request forgery
- **Authentication Bypass**: Login mechanism testing
- **Privilege Escalation**: Permission boundary testing
- **JWT Security**: JSON Web Token analysis
- **Session Management**: Session security assessment
- **Race Condition**: Concurrency vulnerability testing
- **Business Logic**: Workflow security analysis
- **Deserialization**: Unsafe object handling detection

### 🌍 Web Application (10 Tools)
- **Access Control Testing**: Authorization boundary testing
- **Security Misconfiguration**: Configuration weakness detection
- **Sensitive Data Exposure**: Information leakage analysis
- **API Security Testing**: REST/GraphQL security assessment
- **File Upload Security**: Upload mechanism testing
- **Input Validation**: Data sanitization analysis
- **Cookie Security**: Session cookie analysis
- **WebSocket Security**: Real-time communication testing
- **GraphQL Security**: Query language vulnerability testing
- **Error Handling Analysis**: Information disclosure via errors

### 🔧 Network Security (10 Tools)
- **Network Discovery**: Live host identification
- **Firewall Detection**: Security device identification
- **Load Balancer Detection**: Traffic distribution analysis
- **CDN Detection**: Content delivery network analysis
- **Proxy Detection**: Intermediary service identification
- **Routing Analysis**: Network path examination
- **Bandwidth Testing**: Network performance analysis
- **Wireless Security**: WiFi network assessment
- **Network Sniffing**: Packet capture and analysis
- **Lateral Movement**: Internal network exploration

### 🕵️ OSINT (10 Tools)
- **Person Investigation**: Individual background research
- **Company Investigation**: Corporate intelligence gathering
- **Dark Web Monitoring**: Hidden service surveillance
- **Data Breach Checking**: Credential exposure analysis
- **Social Media Investigation**: Profile analysis across platforms
- **Paste Site Monitoring**: Leaked information detection
- **Code Repository Search**: Source code intelligence
- **Geolocation Investigation**: Physical presence analysis
- **Threat Intelligence**: IoC analysis and attribution
- **Metadata Extraction**: Document forensics

### ⚔️ Exploitation (10 Tools)
- **Exploit Search**: Vulnerability database queries
- **Payload Generation**: Custom exploit creation
- **Privilege Escalation**: System access expansion
- **Lateral Movement**: Network propagation techniques
- **Persistence Mechanisms**: Backdoor installation methods
- **Data Exfiltration**: Information extraction techniques
- **Credential Dumping**: Password harvesting methods
- **Anti-Forensics**: Evidence elimination techniques
- **Evasion Techniques**: Security control bypass
- **Social Engineering**: Human factor exploitation

### 📊 Reporting (10 Tools)
- **Vulnerability Reports**: Comprehensive security assessments
- **Executive Summaries**: Business-focused reporting
- **Finding Tracking**: Vulnerability lifecycle management
- **Metrics Dashboard**: Security KPI visualization
- **Data Export**: Multi-format result export
- **Remediation Planning**: Prioritized fix roadmaps
- **Compliance Mapping**: Framework alignment analysis
- **Risk Assessment**: Business impact evaluation
- **Scan Comparison**: Historical trend analysis
- **Proof of Concept**: Exploit documentation

## 📋 Total: 92+ Security Testing Tools

## 🛠️ Installation

### Prerequisites

- **Python 3.10 or higher** (Python 3.11+ recommended)
- **Git**
- **macOS, Linux, or Windows with WSL**

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/bugbounty-mcp-server.git
   cd bugbounty-mcp-server
   ```

2. **Run the automated installation:**
   ```bash
   # Make the run script executable
   chmod +x run.sh
   
   # Install everything automatically
   ./install.sh
   ```

   **OR for manual installation:**

3. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

5. **Install external security tools** (optional but recommended):
   ```bash
   # On Ubuntu/Debian
   sudo apt update
   sudo apt install nmap masscan nikto dirb sqlmap
   
   # On macOS with Homebrew
   brew install nmap masscan nikto dirb sqlmap
   
   # Install Go-based tools
   go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/OJ/gobuster/v3@latest
   go install github.com/ffuf/ffuf@latest
   ```

6. **Configure API keys** (optional):
   ```bash
   # Copy environment template
   cp env.example .env
   
   # Edit .env file with your API keys
   nano .env
   ```

7. **Download wordlists:**
   ```bash
   ./run.sh download-wordlists --type subdomains
   ./run.sh download-wordlists --type directories
   ./run.sh download-wordlists --type parameters
   ```

8. **Validate configuration:**
   ```bash
   ./run.sh validate-config
   ```

## 🎯 Usage

### Starting the MCP Server

#### 🚀 Quick Start with run.sh

The easiest way to start the server is using the provided `run.sh` script:

```bash
# Navigate to the project directory
cd bugbounty-mcp-server

# Start the MCP server
./run.sh serve
```

The script will:
- ✅ Automatically activate the virtual environment
- ✅ Load environment variables from `.env` file
- ✅ Display server status and available tools
- ✅ Start the MCP server for LLM integration

#### 📋 Command Line Interface

```bash
# List all available commands
./run.sh --help

# Start the MCP server
./run.sh serve

# List all 92+ available tools
./run.sh list-tools

# Validate configuration and tool availability
./run.sh validate-config

# Perform a quick security scan
./run.sh quick-scan --target example.com

# Download security wordlists
./run.sh download-wordlists --type subdomains

# Export configuration template
./run.sh export-config --format yaml
bugbounty-mcp export-config --format yaml -o config.yaml
```

### 🤖 MCP Server Integration with LLMs

The BugBounty MCP Server implements the **Model Context Protocol (MCP)**, enabling seamless integration with various LLM applications for natural language penetration testing.

#### 🔗 Supported LLM Clients

##### 1. **Claude Desktop** (Recommended)

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "bugbounty-mcp": {
      "command": "/Users/your-username/Documents/bugbounty-mcp-server/run.sh",
      "args": ["serve"],
      "env": {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

##### 2. **Custom MCP Clients**

```python
import asyncio
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

async def use_bugbounty_mcp():
    async with stdio_client(["./run.sh", "serve"]) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print(f"Available tools: {len(tools)}")
            
            # Call a tool
            result = await session.call_tool(
                "subdomain_enumeration",
                {"domain": "example.com", "passive_only": True}
            )
            print(result)

# Run the client
asyncio.run(use_bugbounty_mcp())
```

##### 3. **Integration Examples**

**Start the server and test:**
```bash
# Terminal 1: Start the MCP server
./run.sh serve

# Terminal 2: Test with any MCP client
# The server will be listening on stdio for MCP protocol messages
```

**Example LLM conversation:**
```
User: "Please perform a comprehensive security assessment of example.com"

LLM: I'll help you conduct a comprehensive security assessment using the BugBounty MCP tools. Let me start by gathering information about the target.

[The LLM will automatically use tools like:]
- subdomain_enumeration to find subdomains
- port_scanning to identify open services  
- vulnerability_scanning to detect security issues
- web_directory_scanning to find hidden files
- And 90+ other security tools as needed
```

#### 🔧 Troubleshooting MCP Integration

**If the server doesn't start in Claude Desktop:**

1. **Check the path in your config:**
   ```bash
   # Get the absolute path
   pwd
   # Use this full path in claude_desktop_config.json
   ```

2. **Verify the run.sh script is executable:**
   ```bash
   chmod +x run.sh
   ```

3. **Test the server manually:**
   ```bash
   ./run.sh serve
   # Should show "BugBounty MCP Server started successfully"
   ```

4. **Check Claude Desktop logs:**
   - **macOS**: `~/Library/Logs/Claude/`
   - **Windows**: `%LOCALAPPDATA%\Claude\logs\`

### Example Configuration

```yaml
# bugbounty_mcp_config.yaml
api_keys:
  shodan: "your_shodan_api_key"
  virustotal: "your_virustotal_api_key"
  github: "your_github_token"

tools:
  nmap_path: "nmap"
  nuclei_path: "nuclei"
  max_concurrent_scans: 10
  default_timeout: 30

scanning:
  default_ports: ["21", "22", "23", "25", "53", "80", "443", "8080", "8443"]
  max_crawl_depth: 3
  max_pages_to_crawl: 100

output:
  output_dir: "output"
  report_format: "json"
  create_html_report: true

safety:
  safe_mode: true
  allowed_targets: ["*.example.com", "192.168.1.0/24"]
  blocked_targets: ["*.gov", "*.mil"]
```

## 🗣️ Natural Language Examples

Once integrated with an LLM, you can perform security testing through conversation:

### Reconnaissance
```
"Perform subdomain enumeration for example.com using both passive and active methods"

"Check if example.com uses a CDN and try to find the origin server"

"Search GitHub for any repositories mentioning example.com that might contain sensitive information"
```

### Vulnerability Testing
```
"Test the login form at https://example.com/login for SQL injection vulnerabilities"

"Scan https://example.com for XSS vulnerabilities in all input parameters"

"Check if https://example.com has any CORS misconfigurations"
```

### Comprehensive Testing
```
"Perform a complete security assessment of example.com including:
- Subdomain discovery
- Port scanning
- Web application testing
- SSL/TLS analysis
- Generate a detailed report"
```

### OSINT Gathering
```
"Investigate the company Example Corp for:
- Employee information
- Technology stack
- Recent data breaches
- Social media presence"
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SHODAN_API_KEY` | Shodan API key for device discovery | No |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for threat intelligence | No |
| `CENSYS_API_ID` | Censys API ID for certificate/host search | No |
| `CENSYS_API_SECRET` | Censys API secret | No |
| `GITHUB_TOKEN` | GitHub token for repository search | No |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API for DNS history | No |
| `HUNTER_IO_API_KEY` | Hunter.io API for email discovery | No |
| `BINARYEDGE_API_KEY` | BinaryEdge API for internet scanning | No |

### Tool Paths

The server automatically detects tools in your PATH, but you can specify custom paths:

```yaml
tools:
  nmap_path: "/usr/local/bin/nmap"
  masscan_path: "/opt/masscan/bin/masscan"
  nuclei_path: "/home/user/go/bin/nuclei"
  # ... other tools
```

### Safety Features

```yaml
safety:
  safe_mode: true                    # Enable safety checks
  allowed_targets:                   # Whitelist of allowed targets
    - "*.example.com"
    - "192.168.1.0/24"
    - "10.0.0.0/8"
  blocked_targets:                   # Blacklist of forbidden targets
    - "*.gov"
    - "*.mil"
    - "*.edu"
  rate_limit_enabled: true          # Enable rate limiting
  requests_per_second: 10.0         # Request rate limit
```

## 📁 Project Structure

```
bugbounty-mcp-server/
├── bugbounty_mcp_server/
│   ├── __init__.py
│   ├── server.py              # Main MCP server
│   ├── config.py              # Configuration management
│   ├── utils.py               # Utility functions
│   ├── cli.py                 # Command-line interface
│   └── tools/
│       ├── __init__.py
│       ├── base.py            # Base tool class
│       ├── recon.py           # Reconnaissance tools
│       ├── scanning.py        # Scanning tools
│       ├── vulnerability.py   # Vulnerability assessment
│       ├── webapp.py          # Web application tools
│       ├── network.py         # Network security tools
│       ├── osint.py           # OSINT tools
│       ├── exploitation.py    # Exploitation tools
│       └── reporting.py       # Reporting tools
├── wordlists/                 # Wordlists for scanning
├── output/                    # Scan results and reports
├── data/                      # Persistent data storage
├── pyproject.toml             # Project configuration
├── README.md                  # This file
├── LICENSE                    # MIT License
└── SECURITY.md               # Security guidelines
```

## 🔒 Security Considerations

### Responsible Usage

This tool is designed for **authorized security testing only**. Users must:

1. **Obtain explicit permission** before testing any systems
2. **Comply with local laws** and regulations
3. **Respect rate limits** and avoid DoS conditions
4. **Follow responsible disclosure** for any vulnerabilities found

### Safety Features

- **Target Whitelisting**: Configure allowed targets
- **Rate Limiting**: Prevent overwhelming target systems
- **Safe Mode**: Enable additional safety checks
- **Logging**: Comprehensive audit trails

### Legal Disclaimer

Users are solely responsible for ensuring their use of this tool complies with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this software.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. **Clone and install in development mode:**
   ```bash
   git clone https://github.com/yourusername/bugbounty-mcp-server.git
   cd bugbounty-mcp-server
   pip install -e ".[dev]"
   ```

2. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

3. **Run tests:**
   ```bash
   pytest
   ```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security testing methodologies
- [ProjectDiscovery](https://projectdiscovery.io/) for excellent security tools
- [SecLists](https://github.com/danielmiessler/SecLists) for comprehensive wordlists
- The bug bounty and security research community

## 📚 Documentation

- **[RUN_SCRIPT.md](RUN_SCRIPT.md)** - Detailed `run.sh` script documentation
- **[USAGE.md](USAGE.md)** - Comprehensive usage examples and workflows
- **[SECURITY.md](SECURITY.md)** - Security guidelines and best practices
- **[env.example](env.example)** - Environment configuration template

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/bugbounty-mcp-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/bugbounty-mcp-server/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting security issues

## 🚀 Roadmap

- [ ] Web-based dashboard
- [ ] Integration with popular bug bounty platforms
- [ ] Machine learning-powered vulnerability detection
- [ ] Collaborative testing features
- [ ] Advanced evasion techniques
- [ ] Mobile application testing tools
- [ ] Cloud security assessment tools
- [ ] Blockchain security testing

---

**⚠️ Warning**: This tool is for authorized security testing only. Unauthorized use against systems you don't own or have explicit permission to test is illegal and unethical.
