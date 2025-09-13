#!/bin/bash

# BugBounty MCP Server Run Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

cd "$(dirname "$0")"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Activate virtual environment if it exists
if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    PYTHON_CMD="python"
    log_success "Virtual environment activated"
else
    log_warning "Virtual environment not found. Using system Python."
    log_info "💡 Run './install.sh' to set up the virtual environment."
    PYTHON_CMD="python3"
fi

# Set environment variables if .env file exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs) 2>/dev/null || true
    log_info ".env file loaded"
fi

# Check if this is a download-wordlists command
if [ "$1" = "download-wordlists" ]; then
    shift  # Remove 'download-wordlists' from arguments
    
    log_info "🚀 BugBounty MCP Server - Wordlist Downloader"
    log_info "📍 Tools available: 92+ security testing tools"
    log_info "🔧 Virtual environment: $($PYTHON_CMD --version 2>/dev/null || echo 'Not available')"
    log_info "📁 Working directory: $(pwd)"
    echo ""
    
    # Handle different wordlist types
    if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        log_info "Available wordlist types:"
        echo "  • all         - Download all wordlists (recommended)"
        echo "  • subdomains  - Subdomain enumeration wordlists"
        echo "  • directories - Directory/file discovery wordlists"
        echo "  • parameters  - Parameter discovery wordlists"
        echo "  • files       - Common file wordlists"
        echo ""
        echo "Usage examples:"
        echo "  ./run.sh download-wordlists                    # Download all wordlists"
        echo "  ./run.sh download-wordlists --type all         # Download all wordlists"
        echo "  ./run.sh download-wordlists --type subdomains  # Download only subdomain wordlists"
        echo "  ./run.sh download-wordlists --type directories # Download only directory wordlists"
        exit 0
    fi
    
    # If no type specified, default to all
    if [ $# -eq 0 ]; then
        log_info "No type specified, downloading all wordlists..."
        bugbounty-mcp download-wordlists --type all
    else
        # Pass all arguments to the CLI command
        bugbounty-mcp download-wordlists "$@"
    fi
    
elif [ "$1" = "serve" ]; then
    log_info "🚀 Starting BugBounty MCP Server..."
    log_info "📍 Tools available: 92+ security testing tools"
    log_info "🔧 Virtual environment: $($PYTHON_CMD --version 2>/dev/null || echo 'Not available')"
    log_info "� Working directory: $(pwd)"
    echo ""
    
    bugbounty-mcp "$@"
    
elif [ "$1" = "validate-config" ]; then
    log_info "🔍 Validating BugBounty MCP Server configuration..."
    log_info "�🔧 Virtual environment: $($PYTHON_CMD --version 2>/dev/null || echo 'Not available')"
    echo ""
    
    bugbounty-mcp "$@"
    
elif [ "$1" = "list-tools" ]; then
    log_info "� Listing all available BugBounty MCP Server tools..."
    log_info "🔧 Virtual environment: $($PYTHON_CMD --version 2>/dev/null || echo 'Not available')"
    echo ""
    
    bugbounty-mcp "$@"
    
elif [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ $# -eq 0 ]; then
    log_info "🚀 BugBounty MCP Server Management Script"
    echo ""
    echo "Available commands:"
    echo "  serve                     - Start the MCP server"
    echo "  validate-config           - Check configuration and tool availability"
    echo "  list-tools               - Show all 92+ available security tools"
    echo "  download-wordlists        - Download security wordlists"
    echo "  quick-scan -t <target>    - Perform a quick security scan"
    echo "  export-config             - Export configuration template"
    echo ""
    echo "Wordlist management:"
    echo "  download-wordlists                    - Download all wordlists"
    echo "  download-wordlists --type subdomains  - Download subdomain wordlists"
    echo "  download-wordlists --type directories - Download directory wordlists"
    echo "  download-wordlists --type parameters  - Download parameter wordlists"
    echo "  download-wordlists --type files       - Download file wordlists"
    echo ""
    echo "Examples:"
    echo "  ./run.sh serve"
    echo "  ./run.sh validate-config"
    echo "  ./run.sh download-wordlists"
    echo "  ./run.sh quick-scan -t example.com"
    echo ""
    echo "For more options, run: bugbounty-mcp --help"
    
else
    # For all other commands, pass directly to bugbounty-mcp
    log_info "🚀 BugBounty MCP Server"
    log_info "📍 Tools available: 92+ security testing tools"
    log_info "🔧 Virtual environment: $($PYTHON_CMD --version 2>/dev/null || echo 'Not available')"
    echo ""
    
    bugbounty-mcp "$@"
fi
