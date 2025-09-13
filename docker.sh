#!/bin/bash

# BugBounty MCP Server Docker Management Script
# This script helps build, run, and manage the Docker container

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

show_usage() {
    cat << EOF
BugBounty MCP Server Docker Management Script

Usage: $0 [command] [options]

Commands:
    build           Build the Docker image
    run             Run the container
    stop            Stop the container
    restart         Restart the container
    logs            Show container logs
    shell           Access container shell
    validate        Validate container setup
    clean           Clean up containers and images
    backup          Backup container data
    restore         Restore container data

Options:
    --dev           Use development configuration
    --force         Force rebuild/restart
    --follow        Follow logs in real-time
    --api-keys      Set API keys from environment

Examples:
    $0 build                    # Build the image
    $0 run --api-keys          # Run with API keys from .env
    $0 logs --follow           # Follow logs in real-time
    $0 shell                   # Access container shell
    $0 clean --force           # Clean all containers and images

EOF
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        log_info "Please install Docker: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        log_info "Please start Docker daemon"
        exit 1
    fi
    
    log_success "Docker is available"
}

check_docker_compose() {
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    else
        log_warning "Docker Compose not found, using docker commands only"
        return 1
    fi
    
    log_success "Docker Compose is available: $COMPOSE_CMD"
    return 0
}

build_image() {
    local force="$1"
    local dev_mode="$2"
    
    log_info "Building BugBounty MCP Docker image..."
    
    # Build arguments
    local build_args=""
    if [ "$dev_mode" = "true" ]; then
        build_args="--target builder"
        log_info "Building development image"
    fi
    
    if [ "$force" = "true" ]; then
        build_args="$build_args --no-cache"
        log_info "Force rebuilding (no cache)"
    fi
    
    # Build the image
    if docker build $build_args -t bugbounty-mcp:latest .; then
        log_success "Docker image built successfully"
        
        # Show image size
        local image_size
        image_size=$(docker images bugbounty-mcp:latest --format "table {{.Size}}" | tail -n 1)
        log_info "Image size: $image_size"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

run_container() {
    local api_keys="$1"
    local dev_mode="$2"
    
    # Stop existing container if running
    if docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
        log_warning "Stopping existing container..."
        docker stop bugbounty-mcp-server >/dev/null 2>&1 || true
        docker rm bugbounty-mcp-server >/dev/null 2>&1 || true
    fi
    
    log_info "Starting BugBounty MCP Server container..."
    
    # Prepare run command
    local run_cmd="docker run -d --name bugbounty-mcp-server"
    
    # Add volumes
    run_cmd="$run_cmd -v $(pwd)/output:/app/output"
    run_cmd="$run_cmd -v $(pwd)/data:/app/data"
    run_cmd="$run_cmd -v $(pwd)/logs:/app/logs"
    run_cmd="$run_cmd -v $(pwd)/cache:/app/cache"
    
    # Add .env file if it exists
    if [ -f ".env" ]; then
        run_cmd="$run_cmd -v $(pwd)/.env:/app/.env:ro"
        log_info "Mounting .env file"
    fi
    
    # Add API keys from environment
    if [ "$api_keys" = "true" ] && [ -f ".env" ]; then
        source .env 2>/dev/null || true
        
        [ -n "$SHODAN_API_KEY" ] && run_cmd="$run_cmd -e SHODAN_API_KEY=$SHODAN_API_KEY"
        [ -n "$CENSYS_API_ID" ] && run_cmd="$run_cmd -e CENSYS_API_ID=$CENSYS_API_ID"
        [ -n "$CENSYS_API_SECRET" ] && run_cmd="$run_cmd -e CENSYS_API_SECRET=$CENSYS_API_SECRET"
        [ -n "$VIRUSTOTAL_API_KEY" ] && run_cmd="$run_cmd -e VIRUSTOTAL_API_KEY=$VIRUSTOTAL_API_KEY"
        [ -n "$GITHUB_TOKEN" ] && run_cmd="$run_cmd -e GITHUB_TOKEN=$GITHUB_TOKEN"
        [ -n "$SECURITYTRAILS_API_KEY" ] && run_cmd="$run_cmd -e SECURITYTRAILS_API_KEY=$SECURITYTRAILS_API_KEY"
        [ -n "$HUNTER_IO_API_KEY" ] && run_cmd="$run_cmd -e HUNTER_IO_API_KEY=$HUNTER_IO_API_KEY"
        [ -n "$BINARYEDGE_API_KEY" ] && run_cmd="$run_cmd -e BINARYEDGE_API_KEY=$BINARYEDGE_API_KEY"
        
        log_info "API keys loaded from environment"
    fi
    
    # Development mode
    if [ "$dev_mode" = "true" ]; then
        run_cmd="$run_cmd -v $(pwd):/app"
        log_info "Development mode: mounting source code"
    fi
    
    # Add image name
    run_cmd="$run_cmd bugbounty-mcp:latest"
    
    # Create necessary directories
    mkdir -p output data logs cache
    
    # Run the container
    if eval $run_cmd; then
        log_success "Container started successfully"
        
        # Wait a moment for container to initialize
        sleep 3
        
        # Check if container is still running
        if docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
            log_success "Container is running (ID: $(docker ps -q -f name=bugbounty-mcp-server))"
            log_info "View logs with: $0 logs"
            log_info "Access shell with: $0 shell"
        else
            log_error "Container stopped unexpectedly"
            log_info "Check logs with: docker logs bugbounty-mcp-server"
            exit 1
        fi
    else
        log_error "Failed to start container"
        exit 1
    fi
}

stop_container() {
    log_info "Stopping BugBounty MCP Server container..."
    
    if docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
        docker stop bugbounty-mcp-server
        docker rm bugbounty-mcp-server
        log_success "Container stopped and removed"
    else
        log_warning "Container is not running"
    fi
}

restart_container() {
    local api_keys="$1"
    local dev_mode="$2"
    
    log_info "Restarting BugBounty MCP Server container..."
    stop_container
    run_container "$api_keys" "$dev_mode"
}

show_logs() {
    local follow="$1"
    
    if ! docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
        log_error "Container is not running"
        exit 1
    fi
    
    if [ "$follow" = "true" ]; then
        log_info "Following container logs (Ctrl+C to exit)..."
        docker logs -f bugbounty-mcp-server
    else
        log_info "Showing recent container logs..."
        docker logs --tail 50 bugbounty-mcp-server
    fi
}

access_shell() {
    if ! docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
        log_error "Container is not running"
        exit 1
    fi
    
    log_info "Accessing container shell..."
    docker exec -it bugbounty-mcp-server /bin/bash
}

validate_container() {
    log_info "Validating BugBounty MCP Server container..."
    
    if ! docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
        log_error "Container is not running"
        exit 1
    fi
    
    log_info "Running configuration validation..."
    if docker exec bugbounty-mcp-server bugbounty-mcp validate-config; then
        log_success "Container validation passed"
    else
        log_warning "Container validation failed"
    fi
    
    log_info "Checking available tools..."
    docker exec bugbounty-mcp-server bugbounty-mcp list-tools | head -20
    
    log_info "Container status:"
    docker ps -f name=bugbounty-mcp-server --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
}

clean_docker() {
    local force="$1"
    
    log_info "Cleaning up Docker resources..."
    
    if [ "$force" = "true" ]; then
        log_warning "Force cleaning - this will remove all bugbounty-mcp containers and images"
        
        # Stop and remove containers
        docker ps -a -q -f name=bugbounty-mcp | xargs -r docker stop
        docker ps -a -q -f name=bugbounty-mcp | xargs -r docker rm
        
        # Remove images
        docker images -q bugbounty-mcp | xargs -r docker rmi -f
        
        # Clean up orphaned volumes
        docker volume ls -q -f dangling=true | xargs -r docker volume rm
        
        log_success "Force cleanup completed"
    else
        # Stop and remove running containers only
        if docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
            docker stop bugbounty-mcp-server
            docker rm bugbounty-mcp-server
            log_success "Stopped and removed running container"
        else
            log_info "No running containers to clean"
        fi
    fi
}

backup_data() {
    local backup_dir="backup"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$backup_dir/bugbounty-data-backup-$timestamp.tar.gz"
    
    log_info "Creating data backup..."
    
    mkdir -p "$backup_dir"
    
    # Create backup of persistent data
    if docker run --rm \
        -v $(pwd)/output:/source/output:ro \
        -v $(pwd)/data:/source/data:ro \
        -v $(pwd)/logs:/source/logs:ro \
        -v $(pwd)/$backup_dir:/backup \
        alpine \
        tar czf /backup/bugbounty-data-backup-$timestamp.tar.gz \
        -C /source .; then
        
        log_success "Backup created: $backup_file"
        
        # Show backup size
        local backup_size
        backup_size=$(du -h "$backup_file" | cut -f1)
        log_info "Backup size: $backup_size"
    else
        log_error "Backup failed"
        exit 1
    fi
}

restore_data() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        log_error "Please specify backup file path"
        log_info "Usage: $0 restore /path/to/backup.tar.gz"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    log_info "Restoring data from: $backup_file"
    log_warning "This will overwrite existing data. Continue? (y/N)"
    
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log_info "Restore cancelled"
        exit 0
    fi
    
    # Stop container if running
    if docker ps -q -f name=bugbounty-mcp-server | grep -q .; then
        log_info "Stopping container for restore..."
        docker stop bugbounty-mcp-server
    fi
    
    # Restore data
    if docker run --rm \
        -v $(pwd)/output:/target/output \
        -v $(pwd)/data:/target/data \
        -v $(pwd)/logs:/target/logs \
        -v "$(dirname "$(realpath "$backup_file")"):/backup" \
        alpine \
        tar xzf "/backup/$(basename "$backup_file")" -C /target; then
        
        log_success "Data restored successfully"
        log_info "You may want to restart the container: $0 restart"
    else
        log_error "Restore failed"
        exit 1
    fi
}

main() {
    # Check prerequisites
    check_docker
    
    # Parse command
    local command="$1"
    shift || true
    
    # Parse options
    local force=false
    local dev_mode=false
    local follow=false
    local api_keys=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force)
                force=true
                shift
                ;;
            --dev)
                dev_mode=true
                shift
                ;;
            --follow)
                follow=true
                shift
                ;;
            --api-keys)
                api_keys=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Execute command
    case "$command" in
        build)
            build_image "$force" "$dev_mode"
            ;;
        run)
            run_container "$api_keys" "$dev_mode"
            ;;
        stop)
            stop_container
            ;;
        restart)
            restart_container "$api_keys" "$dev_mode"
            ;;
        logs)
            show_logs "$follow"
            ;;
        shell)
            access_shell
            ;;
        validate)
            validate_container
            ;;
        clean)
            clean_docker "$force"
            ;;
        backup)
            backup_data
            ;;
        restore)
            restore_data "$1"
            ;;
        ""|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"