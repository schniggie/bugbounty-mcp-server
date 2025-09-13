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

check_python_version() {
    log_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        return 1
    fi
    
    local python_version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local major_version
    major_version=$(echo "$python_version" | cut -d. -f1)
    local minor_version
    minor_version=$(echo "$python_version" | cut -d. -f2)
    
    if [ "$major_version" -eq 3 ] && [ "$minor_version" -ge 10 ]; then
        log_success "Python $python_version is compatible (>=3.10 required)"
        return 0
    else
        log_error "Python $python_version is not compatible. MCP requires Python 3.10 or higher"
        log_info "Please upgrade Python:"
        log_info "  macOS: brew install python@3.11"
        log_info "  Ubuntu/Debian: sudo apt install python3.11 python3.11-venv"
        log_info "  CentOS/RHEL: sudo yum install python311 python311-pip"
        return 1
    fi
}

setup_virtual_environment() {
    log_info "Setting up Python virtual environment..."
    
    # Check if venv already exists
    if [ -d "venv" ]; then
        log_info "Virtual environment already exists"
        return 0
    fi
    
    # Create virtual environment
    if python3 -m venv venv; then
        log_success "Virtual environment created successfully"
        
        # Activate and upgrade pip
        source venv/bin/activate
        pip install --upgrade pip
        
        log_success "Virtual environment activated and pip upgraded"
        return 0
    else
        log_error "Failed to create virtual environment"
        return 1
    fi
}

install_python_package() {
    log_info "Installing BugBounty MCP Server..."
    
    # Ensure virtual environment is activated
    if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
        log_info "Using virtual environment: $(python --version)"
    else
        log_warning "No virtual environment found, using system Python"
    fi
    
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
            sudo apt-get install -y nmap masscan nikto dirb sqlmap whatweb dnsutils git curl wget python3-venv python3-pip
        elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
            # RHEL/CentOS/Fedora
            local package_manager
            if command -v dnf &> /dev/null; then
                package_manager="dnf"
                log_info "Detected Fedora system"
            else
                package_manager="yum"
                log_info "Detected RHEL/CentOS system"
            fi
            sudo $package_manager install -y nmap masscan nikto dirb sqlmap git curl wget python3 python3-pip
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            log_info "Detected Arch Linux system"
            sudo pacman -S --noconfirm nmap masscan nikto dirb sqlmap git curl wget python python-pip
        elif command -v zypper &> /dev/null; then
            # openSUSE
            log_info "Detected openSUSE system"
            sudo zypper install -y nmap masscan nikto dirb sqlmap git curl wget python3 python3-pip
        else
            log_warning "Unknown Linux distribution. Please install tools manually."
            log_info "Required tools: nmap, masscan, nikto, dirb, sqlmap, git, curl, wget"
            return 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        log_info "Detected macOS system"
        if command -v brew &> /dev/null; then
            # Install essential tools (some may not be available)
            brew install nmap nikto sqlmap git curl wget python@3.11 || log_warning "Some tools may not be available via Homebrew"
            
            # Try to install additional tools
            brew install masscan 2>/dev/null || log_info "masscan not available via Homebrew (install manually if needed)"
            brew install dirb 2>/dev/null || log_info "dirb not available via Homebrew (install manually if needed)"
        else
            log_error "Homebrew not found. Please install Homebrew first: https://brew.sh/"
            log_info "Then run: brew install nmap nikto sqlmap git curl wget python@3.11"
            return 1
        fi
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        # Windows (Git Bash/WSL)
        log_info "Detected Windows environment"
        log_warning "Windows support is limited. Please install tools manually:"
        log_info "1. Install Python 3.11+ from python.org"
        log_info "2. Install Git from git-scm.com"
        log_info "3. Install WSL2 for Linux tools (recommended)"
        log_info "4. Or use Windows ports: nmap, nikto, sqlmap"
        return 1
    else
        log_warning "Unsupported operating system: $OSTYPE"
        log_info "Please install the following tools manually:"
        log_info "- Python 3.10+ with pip and venv"
        log_info "- Git, curl, wget"
        log_info "- Security tools: nmap, nikto, sqlmap (optional)"
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
    log_info "Downloading security wordlists..."
    
    # Ensure wordlists directory exists
    mkdir -p wordlists
    
    # Define wordlists to download (URL|FILENAME)
    local wordlists=(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt|subdomains-top1million-110000.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt|directory-list-quickhits.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt|parameters.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt|common_files.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt|big.txt"
    )
    
    local total_files=${#wordlists[@]}
    local downloaded=0
    local failed=0
    
    for wordlist_entry in "${wordlists[@]}"; do
        IFS='|' read -r url filename <<< "$wordlist_entry"
        local path="wordlists/$filename"
        
        log_info "Downloading $filename..."
        
        if curl -s -L --max-time 30 "$url" -o "$path"; then
            # Verify the download was successful (file size > 1KB)
            local file_size
            if command -v stat >/dev/null 2>&1; then
                file_size=$(stat -f%z "$path" 2>/dev/null || stat -c%s "$path" 2>/dev/null || echo 0)
            else
                file_size=$(wc -c < "$path" 2>/dev/null || echo 0)
            fi
            
            if [ -f "$path" ] && [ "$file_size" -gt 1024 ]; then
                local file_size_human
                if command -v du >/dev/null 2>&1; then
                    file_size_human=$(du -h "$path" | cut -f1)
                else
                    file_size_human="${file_size} bytes"
                fi
                log_success "✓ Downloaded $filename ($file_size_human)"
                downloaded=$((downloaded + 1))
            else
                log_warning "✗ Downloaded $filename but file seems too small"
                rm -f "$path"
                failed=$((failed + 1))
            fi
        else
            log_warning "✗ Failed to download $filename"
            failed=$((failed + 1))
        fi
    done
    
    # Create symlinks for common names
    if [ -f "wordlists/subdomains-top1million-110000.txt" ]; then
        ln -sf "subdomains-top1million-110000.txt" "wordlists/subdomains.txt"
    fi
    if [ -f "wordlists/directory-list-quickhits.txt" ]; then
        ln -sf "directory-list-quickhits.txt" "wordlists/directories.txt"
    fi
    
    log_info "Wordlist download summary: $downloaded successful, $failed failed"
    
    if [ "$downloaded" -gt 0 ]; then
        log_success "Wordlists download completed successfully"
        log_info "Downloaded wordlists:"
        ls -lh wordlists/*.txt 2>/dev/null | grep -v "total" || true
    else
        log_warning "No wordlists were downloaded successfully"
        log_info "You can download them manually later with:"
        log_info "  curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -o wordlists/subdomains.txt"
        log_info "  curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt -o wordlists/directories.txt"
        log_info "  curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt -o wordlists/parameters.txt"
    fi
}

setup_environment() {
    log_info "Setting up environment..."
    
    # Copy environment template if it doesn't exist
    if [ ! -f ".env" ] && [ -f "env.example" ]; then
        cp env.example .env
        log_success "Created .env file from template"
        log_info "Please edit .env file to add your API keys"
    fi
    
    # Add Go bin to PATH if Go is installed and not already in PATH
    if command -v go &> /dev/null && [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        local go_bin_path="$HOME/go/bin"
        
        # Detect shell and add to appropriate config file
        local shell_config=""
        case "$SHELL" in
            */zsh)
                shell_config="$HOME/.zshrc"
                ;;
            */bash)
                shell_config="$HOME/.bashrc"
                ;;
            */fish)
                shell_config="$HOME/.config/fish/config.fish"
                ;;
            */tcsh)
                shell_config="$HOME/.tcshrc"
                ;;
            */csh)
                shell_config="$HOME/.cshrc"
                ;;
            *)
                shell_config="$HOME/.bashrc"
                ;;
        esac
        
        # Add to shell config
        if [ -f "$shell_config" ]; then
            if ! grep -q "export PATH=\$PATH:$go_bin_path" "$shell_config"; then
                echo "" >> "$shell_config"
                echo "# Added by BugBounty MCP Server installer" >> "$shell_config"
                echo "export PATH=\$PATH:$go_bin_path" >> "$shell_config"
                log_success "Added Go bin directory to PATH in $shell_config"
            else
                log_info "Go bin directory already in PATH"
            fi
        else
            log_warning "Shell config file not found: $shell_config"
            log_info "Please add this to your shell configuration:"
            log_info "export PATH=\$PATH:$go_bin_path"
        fi
        
        # Add to current session
        export PATH=$PATH:$go_bin_path
        log_info "Go tools will be available after restarting your shell"
    fi
}

verify_installation() {
    log_info "Verifying installation..."
    
    # Activate virtual environment if available
    if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
        log_info "Using virtual environment for verification"
    fi
    
    # Check if the main command works
    if bugbounty-mcp --help &> /dev/null; then
        log_success "BugBounty MCP Server is working"
    else
        log_error "BugBounty MCP Server installation failed"
        log_info "Trying to diagnose the issue..."
        
        # Check if we're in the right directory
        if [ ! -f "pyproject.toml" ]; then
            log_error "Not in the correct directory. Please run from the project root."
        fi
        
        # Check virtual environment
        if [ -d "venv" ]; then
            log_info "Virtual environment exists"
            if [ -f "venv/bin/activate" ]; then
                log_info "Virtual environment activation script exists"
            else
                log_error "Virtual environment activation script missing"
            fi
        else
            log_error "Virtual environment not found"
        fi
        
        # Check Python packages
        if command -v python &> /dev/null; then
            log_info "Python version: $(python --version)"
            log_info "Pip version: $(pip --version)"
        fi
        
        return 1
    fi
    
    # Check tool availability
    log_info "Checking security tools availability..."
    local tools=("nmap" "nuclei" "subfinder" "httpx" "gobuster" "ffuf")
    local available_tools=()
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            available_tools+=("$tool")
            log_success "✓ $tool is available"
        else
            missing_tools+=("$tool")
            log_warning "✗ $tool is not available"
        fi
    done
    
    log_info "Available tools: ${available_tools[*]}"
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warning "Missing tools: ${missing_tools[*]}"
        log_info "You can install them later or use alternative tools"
    fi
    
    # Check wordlists
    log_info "Checking wordlists..."
    if [ -d "wordlists" ] && [ "$(ls -A wordlists/*.txt 2>/dev/null | wc -l)" -gt 0 ]; then
        log_success "Wordlists are available"
        ls -lh wordlists/*.txt 2>/dev/null | grep -v "total" | head -5
    else
        log_warning "No wordlists found"
        log_info "Run './run.sh download-wordlists' to download them"
    fi
    
    # Validate configuration
    log_info "Validating configuration..."
    if bugbounty-mcp validate-config 2>/dev/null; then
        log_success "Configuration validation passed"
    else
        log_warning "Configuration validation failed (this may be normal for first setup)"
    fi
    
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
    
    # Essential tools
    local missing_tools=()
    
    # Python and pip
    if ! check_command python3; then
        missing_tools+=("python3")
    else
        check_python_version || exit 1
    fi
    
    if ! check_command pip; then
        missing_tools+=("pip")
    fi
    
    # Git (for cloning and Go tools)
    if ! check_command git; then
        missing_tools+=("git")
    fi
    
    # Curl (for downloads)
    if ! check_command curl; then
        missing_tools+=("curl")
    fi
    
    # Report missing tools
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and try again:"
        
        case "$OSTYPE" in
            "darwin"*)
                log_info "macOS: brew install ${missing_tools[*]}"
                ;;
            "linux-gnu"*)
                if command -v apt-get &> /dev/null; then
                    log_info "Debian/Ubuntu: sudo apt install ${missing_tools[*]}"
                elif command -v yum &> /dev/null; then
                    log_info "RHEL/CentOS: sudo yum install ${missing_tools[*]}"
                elif command -v pacman &> /dev/null; then
                    log_info "Arch: sudo pacman -S ${missing_tools[*]}"
                fi
                ;;
        esac
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
    
    # Install components based on options
    setup_virtual_environment || exit 1
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
    log_info "🎉 BugBounty MCP Server is ready to use!"
    echo
    log_info "Next steps:"
    echo "1. Edit .env file to add your API keys (optional but recommended)"
    echo "2. Test the installation: ./run.sh validate-config"
    echo "3. Start the server: ./run.sh serve"
    echo "4. Integrate with your LLM client (Claude Desktop, etc.)"
    echo
    log_info "Quick commands:"
    echo "  ./run.sh serve                    # Start the MCP server"
    echo "  ./run.sh validate-config          # Check your setup"
    echo "  ./run.sh download-wordlists       # Download additional wordlists"
    echo "  ./run.sh --help                   # Show all available commands"
    echo
    log_info "Documentation:"
    echo "  📖 README.md         - Main documentation"
    echo "  📖 USAGE.md          - Usage examples"
    echo "  📖 RUN_SCRIPT.md     - Run script guide"
    echo "  📖 SECURITY.md       - Security guidelines"
    echo "  📄 env.example       - Environment configuration template"
    echo
    log_info "Virtual Environment:"
    echo "  📁 venv/             - Python virtual environment (created)"
    echo "  🔧 Auto-activated    - run.sh automatically activates venv"
    echo
    log_warning "⚠️  IMPORTANT: Only use this tool on systems you own or have explicit permission to test!"
    log_warning "⚠️  This tool is for authorized security testing only!"
    echo
    log_success "Happy bug hunting! 🐛🔍"
}

# Run main function
main "$@"
