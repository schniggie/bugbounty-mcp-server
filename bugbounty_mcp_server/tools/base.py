"""
Base class for all tool categories.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from mcp.types import Tool
from ..config import BugBountyConfig
from ..utils import RateLimiter, Cache

logger = logging.getLogger(__name__)


class BaseTools(ABC):
    """Base class for all tool categories."""
    
    def __init__(self, config: BugBountyConfig):
        self.config = config
        self.rate_limiter = RateLimiter(config.requests_per_second)
        self.cache = Cache(config.cache_ttl) if config.cache_enabled else None
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def get_tools(self) -> List[Tool]:
        """Return list of tools provided by this category."""
        pass
    
    async def initialize(self) -> None:
        """Initialize the tool category. Override if needed."""
        self.logger.info(f"Initializing {self.__class__.__name__}")
    
    def get_cached(self, key: str) -> Optional[Any]:
        """Get value from cache if caching is enabled."""
        if self.cache:
            return self.cache.get(key)
        return None
    
    def set_cached(self, key: str, value: Any) -> None:
        """Set value in cache if caching is enabled."""
        if self.cache:
            self.cache.set(key, value)
    
    async def rate_limit(self) -> None:
        """Apply rate limiting."""
        if self.config.rate_limit_enabled:
            await self.rate_limiter.wait()
    
    def check_target_allowed(self, target: str) -> bool:
        """Check if target is allowed for scanning."""
        return self.config.is_target_allowed(target)
    
    def format_result(self, data: Any, title: str = "") -> str:
        """Format result data for display."""
        if isinstance(data, dict):
            result = f"=== {title} ===\n" if title else ""
            for key, value in data.items():
                if isinstance(value, (list, dict)):
                    result += f"{key}:\n"
                    if isinstance(value, list):
                        for item in value:
                            result += f"  - {item}\n"
                    else:
                        for k, v in value.items():
                            result += f"  {k}: {v}\n"
                else:
                    result += f"{key}: {value}\n"
            return result
        elif isinstance(data, list):
            result = f"=== {title} ===\n" if title else ""
            for item in data:
                result += f"- {item}\n"
            return result
        else:
            return str(data)
