# BugBounty MCP Server Docker Image
# Multi-stage build for optimized image size

# Stage 1: Builder stage with all build dependencies
FROM python:3.11-slim-bookworm as builder

# Set environment variables for build
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go for Go-based security tools
ENV GO_VERSION=1.21.5
RUN curl -fsSL https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Create Go workspace
RUN mkdir -p ${GOPATH}/{src,bin,pkg}

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/OJ/gobuster/v3@latest && \
    go install -v github.com/ffuf/ffuf@latest

# Create Python virtual environment and install dependencies
WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime stage with minimal dependencies
FROM python:3.11-slim-bookworm

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/venv/bin:$PATH"
ENV PATH="/go/bin:$PATH"

# Create non-root user for security
RUN groupadd -r bugbounty && useradd -r -g bugbounty -d /app -s /bin/bash bugbounty

# Install runtime system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential tools
    curl \
    wget \
    git \
    ca-certificates \
    dnsutils \
    netcat-traditional \
    # Network scanning tools
    nmap \
    masscan \
    # Web security tools
    nikto \
    dirb \
    sqlmap \
    # Additional utilities
    whatweb \
    whois \
    # SSL tools
    openssl \
    # Browser automation (for Selenium/Playwright)
    chromium \
    # Python runtime deps
    python3-distutils \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder stage
COPY --from=builder /go/bin/* /usr/local/bin/

# Copy Python virtual environment from builder stage
COPY --from=builder /app/venv /app/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Install the application in the virtual environment
RUN pip install --no-cache-dir -e .

# Create necessary directories and set permissions
RUN mkdir -p wordlists output data logs cache && \
    chown -R bugbounty:bugbounty /app && \
    chmod +x run.sh

# Set up default environment file
RUN cp env.example .env

# Download wordlists using our enhanced download script
# This uses the proper CLI command with error handling and progress feedback
RUN ./run.sh download-wordlists --type all || true

# Set correct permissions
RUN chown -R bugbounty:bugbounty /app

# Switch to non-root user
USER bugbounty

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD bugbounty-mcp validate-config || exit 1

# Expose port (for future web interface)
EXPOSE 8080

# Set default command to start the MCP server
CMD ["bugbounty-mcp", "serve"]

# Labels for metadata
LABEL org.opencontainers.image.title="BugBounty MCP Server"
LABEL org.opencontainers.image.description="Comprehensive Model Context Protocol server for bug bounty hunting and penetration testing"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="Gokul <apgokul008@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/gokulapap/bugbounty-mcp-server"
LABEL org.opencontainers.image.licenses="MIT"