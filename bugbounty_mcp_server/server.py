"""
Main MCP Server implementation for Bug Bounty hunting.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Sequence

from mcp import ClientSession, StdioServerParameters
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

from .tools import (
    ReconTools,
    ScanningTools,
    VulnerabilityTools,
    WebApplicationTools,
    NetworkTools,
    OSINTTools,
    ExploitationTools,
    ReportingTools,
)
from .config import BugBountyConfig
from .utils import setup_logging

logger = logging.getLogger(__name__)


class BugBountyMCPServer:
    """Main MCP Server for Bug Bounty operations."""

    def __init__(self, config: Optional[BugBountyConfig] = None):
        self.config = config or BugBountyConfig()
        self.server = Server("bugbounty-mcp-server")
        
        # Initialize tool categories
        self.recon_tools = ReconTools(self.config)
        self.scanning_tools = ScanningTools(self.config)
        self.vuln_tools = VulnerabilityTools(self.config)
        self.webapp_tools = WebApplicationTools(self.config)
        self.network_tools = NetworkTools(self.config)
        self.osint_tools = OSINTTools(self.config)
        self.exploit_tools = ExploitationTools(self.config)
        self.reporting_tools = ReportingTools(self.config)
        
        # Store all tool instances
        self.tool_categories = [
            self.recon_tools,
            self.scanning_tools,
            self.vuln_tools,
            self.webapp_tools,
            self.network_tools,
            self.osint_tools,
            self.exploit_tools,
            self.reporting_tools,
        ]
        
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Setup MCP server handlers."""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List all available tools."""
            tools = []
            for tool_category in self.tool_categories:
                tools.extend(tool_category.get_tools())
            return tools

        @self.server.call_tool()
        async def handle_call_tool(
            name: str, arguments: Optional[Dict[str, Any]] = None
        ) -> List[TextContent | ImageContent | EmbeddedResource]:
            """Execute a tool."""
            if arguments is None:
                arguments = {}

            logger.info(f"Executing tool: {name} with args: {arguments}")

            # Find the tool in one of our categories
            for tool_category in self.tool_categories:
                if hasattr(tool_category, name):
                    tool_method = getattr(tool_category, name)
                    try:
                        result = await tool_method(**arguments)
                        return [TextContent(type="text", text=str(result))]
                    except Exception as e:
                        error_msg = f"Error executing {name}: {str(e)}"
                        logger.error(error_msg)
                        return [TextContent(type="text", text=error_msg)]

            return [TextContent(type="text", text=f"Tool '{name}' not found")]

    async def start(self) -> None:
        """Start the MCP server."""
        setup_logging(self.config.log_level)
        logger.info("Starting BugBounty MCP Server...")
        
        # Initialize all tool categories
        for tool_category in self.tool_categories:
            await tool_category.initialize()
        
        logger.info("BugBounty MCP Server started successfully")

    async def run_stdio(self) -> None:
        """Run server with stdio transport."""
        from mcp.server.stdio import stdio_server
        
        await self.start()
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="bugbounty-mcp-server",
                    server_version="1.0.0",
                    capabilities={
                        "tools": {
                            "listChanged": False
                        },
                        "resources": {
                            "subscribe": False,
                            "listChanged": False
                        },
                        "prompts": {
                            "listChanged": False
                        }
                    },
                ),
            )
