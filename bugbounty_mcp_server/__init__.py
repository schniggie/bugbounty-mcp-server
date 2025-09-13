"""
BugBounty MCP Server

A comprehensive Model Context Protocol server for bug bounty hunting 
and web application penetration testing.
"""

__version__ = "1.0.0"
__author__ = "Gokul"
__email__ = "apgokul008@gmail.com"

from .server import BugBountyMCPServer
from .tools import *

__all__ = ["BugBountyMCPServer"]
