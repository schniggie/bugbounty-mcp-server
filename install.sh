#!/bin/bash

# BugBounty MCP Server Installation Script
# This script installs the MCP server and its dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

check_command() {
    if command -v "$1" &> /dev/null; then
        log_success "$1 is installed"
        return 0
    else
        log_warning "$1 is not installed"
        return 1
    fi
}

install_python_package() {
    log_info "Installing BugBounty MCP Server..."
    
    # Install in development mode if we're in the source directory
    if [ -f "pyproject.toml" ]; then
        pip install -e .
    else
        pip install bugbounty-mcp-server
    fi
    
    log_success "BugBounty MCP Server installed"
}

install_go_tools() {
    log_info "Installing Go-based security tools..."
    
    # Check if Go is installed
    if ! check_command go; then
        log_error "Go is not installed. Please install Go first: https://golang.org/doc/install"
        return 1
    fi
    
    # Install tools
    local tools=(
        "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/OJ/gobuster/v3@latest"
        "github.com/ffuf/ffuf@latest"
    )
    
    for tool in "${tools[@]}"; do
        log_info "Installing ${tool}..."
        go install "${tool}" || log_warning "Failed to install ${tool}"
    done
    
    log_success "Go tools installation completed"
}

install_system_tools() {
    log_info "Installing system security tools..."
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            log_info "Detected Debian/Ubuntu system"
            sudo apt-get update
            sudo apt-get install -y nmap masscan nikto dirb sqlmap whatweb dnsutils git curl wget
        elif command -v yum &> /dev/null; then
            # RHEL/CentOS
            log_info "Detected RHEL/CentOS system"
            sudo yum install -y nmap masscan nikto dirb sqlmap git curl wget
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            log_info "Detected Arch Linux system"
            sudo pacman -S nmap masscan nikto dirb sqlmap git curl wget
        else
            log_warning "Unknown Linux distribution. Please install tools manually."
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        log_info "Detected macOS system"
        if command -v brew &> /dev/null; then
            brew install nmap masscan nikto dirb sqlmap git curl wget
        else
            log_error "Homebrew not found. Please install Homebrew first: https://brew.sh/"
            return 1
        fi
    else
        log_warning "Unsupported operating system: $OSTYPE"
        return 1
    fi
    
    log_success "System tools installation completed"
}

setup_directories() {
    log_info "Setting up directories..."
    
    # Create necessary directories
    mkdir -p wordlists
    mkdir -p output
    mkdir -p data
    mkdir -p logs
    mkdir -p cache
    
    # Set appropriate permissions
    chmod 755 wordlists output data logs cache
    
    log_success "Directories created"
}

download_wordlists() {
    log_info "Downloading wordlists..."
    
    # SecLists wordlists
    local wordlist_urls=(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt:wordlists/subdomains.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt:wordlists/directories.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt:wordlists/parameters.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt:wordlists/common_files.txt"
    )
    
    for url_path in "${wordlist_urls[@]}"; do
        IFS=':' read -r url path <<< "$url_path"
        log_info "Downloading $(basename "$path")..."
        
        if curl -s -L "$url" -o "$path"; then
            log_success "Downloaded $(basename "$path")"
        else
            log_warning "Failed to download $(basename "$path")"
        fi
    done
    
    log_success "Wordlists download completed"
}

setup_environment() {
    log_info "Setting up environment..."
    
    # Copy environment template if it doesn't exist
    if [ ! -f ".env" ] && [ -f "env.example" ]; then
        cp env.example .env
        log_success "Created .env file from template"
        log_info "Please edit .env file to add your API keys"
    fi
    
    # Add Go bin to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:$HOME/go/bin
        log_success "Added Go bin directory to PATH"
    fi
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Check if the main command works
    if bugbounty-mcp --help &> /dev/null; then
        log_success "BugBounty MCP Server is working"
    else
        log_error "BugBounty MCP Server installation failed"
        return 1
    fi
    
    # Check tool availability
    local tools=("nmap" "nuclei" "subfinder" "httpx" "gobuster" "ffuf")
    for tool in "${tools[@]}"; do
        check_command "$tool"
    done
    
    # Validate configuration
    log_info "Validating configuration..."
    bugbounty-mcp validate-config || log_warning "Configuration validation failed"
    
    log_success "Installation verification completed"
}

show_usage() {
    cat << EOF
BugBounty MCP Server Installation Script

Usage: $0 [options]

Options:
    --help, -h          Show this help message
    --minimal          Install only the Python package (no external tools)
    --no-wordlists     Skip wordlist downloads
    --no-system-tools  Skip system tool installation
    --go-tools-only    Install only Go-based tools
    
Examples:
    $0                 # Full installation
    $0 --minimal       # Minimal installation
    $0 --go-tools-only # Install only Go tools

EOF
}

main() {
    log_info "BugBounty MCP Server Installation Script"
    log_info "========================================"
    
    # Parse arguments
    INSTALL_SYSTEM_TOOLS=true
    INSTALL_GO_TOOLS=true
    DOWNLOAD_WORDLISTS=true
    MINIMAL_INSTALL=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_usage
                exit 0
                ;;
            --minimal)
                MINIMAL_INSTALL=true
                INSTALL_SYSTEM_TOOLS=false
                INSTALL_GO_TOOLS=false
                DOWNLOAD_WORDLISTS=false
                shift
                ;;
            --no-wordlists)
                DOWNLOAD_WORDLISTS=false
                shift
                ;;
            --no-system-tools)
                INSTALL_SYSTEM_TOOLS=false
                shift
                ;;
            --go-tools-only)
                INSTALL_SYSTEM_TOOLS=false
                DOWNLOAD_WORDLISTS=false
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check prerequisites
    log_info "Checking prerequisites..."
    
    if ! check_command python3; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    if ! check_command pip; then
        log_error "pip is required but not installed"
        exit 1
    fi
    
    # Install components based on options
    install_python_package
    setup_directories
    setup_environment
    
    if [ "$INSTALL_SYSTEM_TOOLS" = true ]; then
        install_system_tools
    fi
    
    if [ "$INSTALL_GO_TOOLS" = true ]; then
        install_go_tools
    fi
    
    if [ "$DOWNLOAD_WORDLISTS" = true ]; then
        download_wordlists
    fi
    
    verify_installation
    
    # Final instructions
    log_success "Installation completed successfully!"
    echo
    log_info "Next steps:"
    echo "1. Edit .env file to add your API keys (optional but recommended)"
    echo "2. Run 'bugbounty-mcp validate-config' to check your setup"
    echo "3. Run 'bugbounty-mcp serve' to start the server"
    echo "4. Integrate with your LLM client (Claude Desktop, etc.)"
    echo
    log_info "For usage examples, see USAGE.md"
    log_info "For security guidelines, see SECURITY.md"
    echo
    log_warning "Remember: Only use this tool on systems you own or have explicit permission to test!"
}

# Run main function
main "$@"
