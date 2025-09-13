#!/bin/bash

# BugBounty MCP Server Run Script

cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Set environment variables if .env file exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Start the server
echo "🚀 Starting BugBounty MCP Server..."
echo "📍 Tools available: 92+ security testing tools"
echo "🔧 Virtual environment: $(python --version)"
echo "📁 Working directory: $(pwd)"
echo ""

bugbounty-mcp "$@"
