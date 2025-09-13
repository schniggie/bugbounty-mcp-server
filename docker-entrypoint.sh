#!/bin/bash

# Docker entrypoint script for BugBounty MCP Server
# This script handles different modes of operation

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to validate environment
validate_environment() {
    print_info "Validating BugBounty MCP Server environment..."
    
    # Check if tools are available
    if bugbounty-mcp validate-config > /dev/null 2>&1; then
        print_success "Configuration validation passed"
    else
        print_warning "Configuration validation failed, but continuing..."
    fi
    
    # Check data directories
    if [ -d "/app/output" ] && [ -d "/app/data" ]; then
        print_success "Data directories are ready"
    else
        print_warning "Some data directories are missing"
    fi
}

# Function to start MCP server in background with named pipe
start_mcp_server() {
    print_info "Starting BugBounty MCP Server..."
    
    # Create named pipes for stdin/stdout communication
    FIFO_IN="/tmp/mcp_in"
    FIFO_OUT="/tmp/mcp_out"
    
    # Clean up any existing pipes
    rm -f $FIFO_IN $FIFO_OUT
    
    # Create named pipes
    mkfifo $FIFO_IN $FIFO_OUT
    
    # Start MCP server with named pipes
    bugbounty-mcp serve < $FIFO_IN > $FIFO_OUT 2>&1 &
    MCP_PID=$!
    
    print_success "MCP Server started with PID: $MCP_PID"
    
    # Keep pipes open and log output
    exec 3<>$FIFO_IN
    exec 4<>$FIFO_OUT
    
    # Store PID for cleanup
    echo $MCP_PID > /tmp/mcp.pid
    
    return 0
}

# Function to start MCP server in stdio mode (for direct use)
start_mcp_stdio() {
    print_info "Starting MCP Server in stdio mode..."
    exec bugbounty-mcp serve
}

# Function to start MCP server with network socket
start_mcp_network() {
    print_info "Starting MCP Server with network socket on port 3001..."
    
    # Use socat to bridge stdio MCP server to network socket
    socat TCP-LISTEN:3001,fork,reuseaddr EXEC:"bugbounty-mcp serve",pty,ctty
}

# Function to run validation and exit
run_validation() {
    validate_environment
    print_info "Running configuration validation..."
    bugbounty-mcp validate-config
    exit 0
}

# Function to list tools and exit
list_tools() {
    print_info "Listing available tools..."
    bugbounty-mcp list-tools
    exit 0
}

# Function to run daemon mode
run_daemon() {
    print_info "Starting in daemon mode..."
    validate_environment
    
    # Create a simple HTTP health endpoint
    while true; do
        # Simple health check server on port 8080
        {
            echo -e "HTTP/1.1 200 OK\r"
            echo -e "Content-Type: application/json\r"
            echo -e "Content-Length: 60\r"
            echo -e "\r"
            echo -e '{"status":"healthy","service":"bugbounty-mcp-server"}\r'
        } | nc -l -p 8080 -q 1 > /dev/null 2>&1 || true
        
        sleep 1
    done
}

# Function to handle shutdown
cleanup() {
    print_info "Shutting down BugBounty MCP Server..."
    
    # Kill MCP server if running
    if [ -f "/tmp/mcp.pid" ]; then
        MCP_PID=$(cat /tmp/mcp.pid)
        if kill -0 $MCP_PID > /dev/null 2>&1; then
            print_info "Stopping MCP server (PID: $MCP_PID)"
            kill -TERM $MCP_PID
            wait $MCP_PID 2>/dev/null || true
        fi
        rm -f /tmp/mcp.pid
    fi
    
    # Clean up named pipes
    rm -f /tmp/mcp_in /tmp/mcp_out
    
    print_success "Cleanup complete"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Main execution logic
case "${1:-serve}" in
    "serve")
        # MCP server mode with network socket (default for docker-compose)
        validate_environment
        start_mcp_network
        ;;
    "stdio")
        # Direct MCP server mode (for interactive use)
        start_mcp_stdio
        ;;
    "validate-config")
        run_validation
        ;;
    "list-tools")
        list_tools
        ;;
    "daemon")
        # Daemon mode (for manual testing)
        run_daemon
        ;;
    "help"|"--help"|"-h")
        echo "BugBounty MCP Server Docker Entrypoint"
        echo ""
        echo "Usage: $0 [COMMAND]"
        echo ""
        echo "Commands:"
        echo "  serve              Start MCP server with network socket (default)"
        echo "  stdio              Start MCP server in stdio mode (interactive)"
        echo "  daemon             Start in daemon mode with health endpoint"
        echo "  validate-config    Validate configuration and exit"
        echo "  list-tools         List available tools and exit"
        echo "  help               Show this help message"
        echo ""
        echo "Examples:"
        echo "  docker-compose up                                  # Start MCP server on port 3001"
        echo "  docker run -it bugbounty-mcp:latest stdio         # Interactive MCP"
        echo "  docker exec container_name validate-config        # Validate configuration"
        ;;
    *)
        # Pass through to bugbounty-mcp command
        print_info "Passing command to bugbounty-mcp: $@"
        exec bugbounty-mcp "$@"
        ;;
esac