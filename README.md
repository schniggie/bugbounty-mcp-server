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

- Python 3.9 or higher
- pip (Python package installer)
- Git

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/bugbounty-mcp-server.git
   cd bugbounty-mcp-server
   ```

2. **Install dependencies:**
   ```bash
   pip install -e .
   ```

3. **Install external tools** (optional but recommended):
   ```bash
   # On Ubuntu/Debian
   sudo apt update
   sudo apt install nmap masscan nikto dirb
   
   # On macOS with Homebrew
   brew install nmap masscan nikto dirb
   
   # Install Go-based tools
   go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/OJ/gobuster/v3@latest
   go install github.com/ffuf/ffuf@latest
   ```

4. **Configure API keys** (optional):
   ```bash
   # Export environment variables
   export SHODAN_API_KEY="your_shodan_key"
   export VIRUSTOTAL_API_KEY="your_vt_key"
   export CENSYS_API_ID="your_censys_id"
   export CENSYS_API_SECRET="your_censys_secret"
   export GITHUB_TOKEN="your_github_token"
   export SECURITYTRAILS_API_KEY="your_st_key"
   export HUNTER_IO_API_KEY="your_hunter_key"
   export BINARYEDGE_API_KEY="your_be_key"
   ```

5. **Download wordlists:**
   ```bash
   bugbounty-mcp download-wordlists --type subdomains
   bugbounty-mcp download-wordlists --type directories
   bugbounty-mcp download-wordlists --type parameters
   ```

6. **Validate configuration:**
   ```bash
   bugbounty-mcp validate-config
   ```

7. **Start the MCP server:**
   ```bash
   bugbounty-mcp serve
   ```

## 🎯 Usage

### Command Line Interface

```bash
# Start the MCP server
bugbounty-mcp serve

# List all available tools
bugbounty-mcp list-tools

# Validate configuration
bugbounty-mcp validate-config

# Quick scan (demonstration)
bugbounty-mcp quick-scan -t example.com

# Export default configuration
bugbounty-mcp export-config --format yaml -o config.yaml
```

### MCP Client Integration

The server implements the Model Context Protocol, allowing integration with various LLM clients:

1. **Claude Desktop**: Add to your configuration
2. **OpenAI ChatGPT**: Use with custom GPT
3. **Local LLM**: Integrate with Ollama, LM Studio, etc.

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
