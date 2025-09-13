# run.sh Script Documentation

The `run.sh` script is a convenient wrapper that simplifies running the BugBounty MCP Server. It handles virtual environment activation, environment variables, and provides an easy interface to all server functionality.

## 🚀 Features

- ✅ **Automatic Virtual Environment**: Activates the `venv` automatically
- ✅ **Environment Loading**: Loads variables from `.env` file
- ✅ **Status Display**: Shows Python version and tool count
- ✅ **Error Handling**: Provides clear error messages
- ✅ **Cross-Platform**: Works on macOS, Linux, and Windows (WSL)

## 📋 Usage

### Basic Syntax

```bash
./run.sh [COMMAND] [OPTIONS]
```

### Available Commands

#### Server Operations
```bash
# Start the MCP server for LLM integration
./run.sh serve

# Start server with verbose logging
./run.sh --verbose serve

# Start server with custom config
./run.sh --config custom-config.yaml serve
```

#### Configuration Management
```bash
# Validate configuration and check tool availability
./run.sh validate-config

# Export configuration template
./run.sh export-config --format yaml
./run.sh export-config --format json --output my-config.json

# List all available tools (92+ tools)
./run.sh list-tools
```

#### Security Operations
```bash
# Perform quick security scan
./run.sh quick-scan --target example.com
./run.sh quick-scan --target example.com --output results.json

# Download security wordlists
./run.sh download-wordlists --type subdomains
./run.sh download-wordlists --type directories
./run.sh download-wordlists --type parameters
./run.sh download-wordlists --type files
```

#### Help and Information
```bash
# Show help message
./run.sh --help
./run.sh -h

# Show version information
./run.sh --version
```

## 🔧 Configuration

### Environment Variables

The script automatically loads environment variables from `.env` file:

```bash
# Copy the template
cp env.example .env

# Edit with your API keys
nano .env
```

Example `.env` file:
```bash
# API Keys for enhanced functionality
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
CENSYS_API_ID=your_censys_id_here
CENSYS_API_SECRET=your_censys_secret_here
GITHUB_TOKEN=your_github_token_here
SECURITYTRAILS_API_KEY=your_securitytrails_key_here
HUNTER_IO_API_KEY=your_hunter_io_key_here
BINARYEDGE_API_KEY=your_binaryedge_key_here

# Server Configuration
LOG_LEVEL=INFO
SAFE_MODE=true
RATE_LIMIT_ENABLED=true
REQUESTS_PER_SECOND=10
```

### Virtual Environment

The script expects a virtual environment in the `venv` directory:

```bash
# Create virtual environment (if not exists)
python3 -m venv venv

# The run.sh script will automatically activate it
./run.sh serve
```

## 🎯 Examples

### Starting the MCP Server

```bash
# Basic startup
./run.sh serve

# Output:
# 🚀 Starting BugBounty MCP Server...
# 📍 Tools available: 92+ security testing tools
# 🔧 Virtual environment: Python 3.13.2
# 📁 Working directory: /path/to/bugbounty-mcp-server
#
# Starting BugBounty MCP Server...
# [Server logs...]
# BugBounty MCP Server started successfully
```

### Validating Configuration

```bash
./run.sh validate-config

# Output:
# Validating configuration...
# 
# API Keys Status:
#   Shodan: ✓ Configured
#   Censys ID: ✓ Configured
#   VirusTotal: ✗ Not configured
#   [...]
# 
# Tool Availability:
#   nmap: ✓ Found at /opt/homebrew/bin/nmap
#   nuclei: ✓ Found at /Users/user/go/bin/nuclei
#   [...]
# 
# Configuration validation complete.
```

### Listing Available Tools

```bash
./run.sh list-tools

# Output:
# Available Tools:
# 
# 🔧 Reconnaissance
#    • subdomain_enumeration
#      Comprehensive subdomain enumeration using multiple techniques
#    • dns_enumeration
#      Comprehensive DNS record enumeration and analysis
#    [... 90+ more tools]
```

### Quick Security Scan

```bash
./run.sh quick-scan --target example.com

# Output:
# Starting quick scan of example.com...
# 
# Scan components:
#   • Port scan (top 1000 ports)
#   • Service enumeration
#   • Web directory scan
#   • SSL/TLS analysis
#   • Basic vulnerability checks
# 
# [Scan results...]
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Fix: Make the script executable
chmod +x run.sh
```

#### 2. Virtual Environment Not Found
```bash
# Fix: Create the virtual environment
python3 -m venv venv
pip install -r requirements.txt
```

#### 3. Python Version Issues
```bash
# Fix: Check Python version (requires 3.10+)
python3 --version

# Use specific Python version
/opt/homebrew/bin/python3 -m venv venv
```

#### 4. Missing Dependencies
```bash
# Fix: Install dependencies
source venv/bin/activate
pip install -r requirements.txt
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
./run.sh --verbose serve
```

## 🔧 Customization

### Custom Python Path

If you need to use a specific Python version:

```bash
# Edit the run.sh script
nano run.sh

# Modify the python path in the script
```

### Custom Environment File

```bash
# Use different environment file
export ENV_FILE=.env.production
./run.sh serve
```

### Adding Custom Commands

The `run.sh` script passes all arguments to the `bugbounty-mcp` CLI tool, so any new commands added to the CLI will automatically work:

```bash
# Any new CLI commands will work
./run.sh new-command --with-options
```

## 🚀 Advanced Usage

### Background Execution

```bash
# Run in background
./run.sh serve &

# Check if running
ps aux | grep bugbounty-mcp

# Stop background process
kill $(ps aux | grep "bugbounty-mcp serve" | grep -v grep | awk '{print $2}')
```

### Integration with Systemd (Linux)

Create a systemd service:

```bash
# Create service file
sudo nano /etc/systemd/system/bugbounty-mcp.service
```

```ini
[Unit]
Description=BugBounty MCP Server
After=network.target

[Service]
Type=simple
User=your-username
WorkingDirectory=/path/to/bugbounty-mcp-server
ExecStart=/path/to/bugbounty-mcp-server/run.sh serve
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable bugbounty-mcp
sudo systemctl start bugbounty-mcp
```

### Integration with Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "bugbounty-mcp": {
      "command": "/full/path/to/bugbounty-mcp-server/run.sh",
      "args": ["serve"],
      "env": {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

## 📚 See Also

- [README.md](README.md) - Main project documentation
- [USAGE.md](USAGE.md) - Detailed usage examples
- [SECURITY.md](SECURITY.md) - Security guidelines
- [env.example](env.example) - Environment configuration template
