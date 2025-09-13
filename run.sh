#!/bin/bash

# BugBounty MCP Server Run Script

cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    PYTHON_CMD="python"
else
    echo "⚠️  Virtual environment not found. Using system Python."
    echo "💡 Run './install.sh' to set up the virtual environment."
    PYTHON_CMD="python3"
fi

# Set environment variables if .env file exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Start the server
echo "🚀 Starting BugBounty MCP Server..."
echo "📍 Tools available: 92+ security testing tools"
echo "🔧 Virtual environment: $($PYTHON_CMD --version 2>/dev/null || echo 'Not available')"
echo "📁 Working directory: $(pwd)"
echo ""

bugbounty-mcp "$@"
