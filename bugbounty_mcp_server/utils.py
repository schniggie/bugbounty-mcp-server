"""
Utility functions for the BugBounty MCP Server.
"""

import asyncio
import logging
import json
import hashlib
import time
import re
import socket
import ipaddress
from typing import Any, Dict, List, Optional, Union, Callable, Awaitable
from pathlib import Path
from urllib.parse import urlparse, urljoin
import aiohttp
import dns.resolver
from datetime import datetime


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """Setup logging configuration."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Get root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


class RateLimiter:
    """Simple rate limiter for API calls."""
    
    def __init__(self, calls_per_second: float = 1.0):
        self.calls_per_second = calls_per_second
        self.last_call = 0.0
    
    async def wait(self) -> None:
        """Wait for rate limit if necessary."""
        now = time.time()
        elapsed = now - self.last_call
        min_interval = 1.0 / self.calls_per_second
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self.last_call = time.time()


class Cache:
    """Simple in-memory cache with TTL."""
    
    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self.data: Dict[str, tuple] = {}  # key -> (value, timestamp)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key not in self.data:
            return None
        
        value, timestamp = self.data[key]
        if time.time() - timestamp > self.ttl:
            del self.data[key]
            return None
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        self.data[key] = (value, time.time())
    
    def clear(self) -> None:
        """Clear all cached data."""
        self.data.clear()


def validate_target(target: str) -> Dict[str, Any]:
    """
    Validate and parse a target (URL, domain, IP address, or CIDR range).
    
    Supports:
    - URLs: http://example.com, https://api.example.com:8080/path
    - Domains: example.com, subdomain.example.com
    - IPv4 addresses: 192.168.1.1
    - IPv6 addresses: ::1, 2001:db8::1
    - CIDR ranges: 192.168.1.0/24, 2001:db8::/32
    - Domain:port: example.com:8080
    
    Returns:
        Dict with keys: valid, type, original, parsed, domain, host, port, 
        scheme, path, ip, network, ip_range, error
    """
    result = {
        "valid": False,
        "type": None,
        "original": target,
        "parsed": None,
        "domain": None,
        "host": None,
        "ip": None,
        "port": None,
        "scheme": None,
        "path": None,
        "network": None,
        "ip_range": None,
        "error": None
    }
    
    if not target or not isinstance(target, str):
        result["error"] = "Target must be a non-empty string"
        return result
    
    target = target.strip()
    
    try:
        # Step 1: Try to parse as URL (must have scheme)
        if "://" in target:
            parsed = urlparse(target)
            if parsed.scheme and parsed.netloc:
                result["valid"] = True
                result["type"] = "url"
                result["parsed"] = parsed
                result["scheme"] = parsed.scheme
                result["domain"] = parsed.hostname
                result["host"] = parsed.hostname
                result["path"] = parsed.path if parsed.path else None
                
                # Set port (use explicit port or defaults)
                if parsed.port:
                    result["port"] = parsed.port
                else:
                    result["port"] = 443 if parsed.scheme == "https" else 80
                
                # Try to resolve IP (optional, non-blocking if fails)
                if parsed.hostname:
                    try:
                        result["ip"] = socket.gethostbyname(parsed.hostname)
                    except:
                        pass
                
                return result
            else:
                result["error"] = "Invalid URL format: missing scheme or netloc"
                return result
        
        # Step 2: Try to parse as CIDR range
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                result["valid"] = True
                result["type"] = "cidr"
                result["network"] = network
                result["ip_range"] = f"{network.network_address} - {network.broadcast_address}"
                result["host"] = str(network.network_address)
                return result
            except ValueError as e:
                result["error"] = f"Invalid CIDR range: {str(e)}"
                return result
        
        # Step 3: Try to parse as IP address (IPv4 or IPv6)
        try:
            ip_obj = ipaddress.ip_address(target)
            result["valid"] = True
            result["type"] = "ipv4" if ip_obj.version == 4 else "ipv6"
            result["ip"] = str(ip_obj)
            result["host"] = str(ip_obj)
            return result
        except ValueError:
            pass
        
        # Step 4: Try to parse as domain:port
        if ":" in target and not target.startswith("["):
            # Avoid treating IPv6 addresses as domain:port
            # Simple heuristic: if there's more than one colon, it's likely IPv6
            if target.count(":") == 1:
                parts = target.rsplit(":", 1)
                if len(parts) == 2:
                    potential_domain, port_str = parts
                    try:
                        port = int(port_str)
                        if 1 <= port <= 65535:
                            # Validate the domain part
                            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', potential_domain):
                                result["valid"] = True
                                result["type"] = "domain"
                                result["domain"] = potential_domain
                                result["host"] = potential_domain
                                result["port"] = port
                                
                                # Try to resolve IP
                                try:
                                    result["ip"] = socket.gethostbyname(potential_domain)
                                except:
                                    pass
                                
                                return result
                    except ValueError:
                        pass
        
        # Step 5: Try to parse as plain domain
        # Domain validation regex: alphanumeric, hyphens, dots
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', target):
            result["valid"] = True
            result["type"] = "domain"
            result["domain"] = target
            result["host"] = target
            
            # Try to resolve IP (optional)
            try:
                result["ip"] = socket.gethostbyname(target)
            except:
                pass
            
            return result
        
        # If we get here, target is invalid
        result["error"] = "Invalid target format: must be URL, domain, IP address, or CIDR range"
        return result
    
    except Exception as e:
        result["error"] = f"Unexpected error during validation: {str(e)}"
        return result


async def resolve_domain(domain: str) -> Dict[str, List[str]]:
    """Resolve domain to various record types."""
    results = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SOA": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    
    for record_type in results.keys():
        try:
            answers = resolver.resolve(domain, record_type)
            for answer in answers:
                results[record_type].append(str(answer))
        except Exception:
            continue
    
    return results


async def check_port_open(host: str, port: int, timeout: int = 5) -> bool:
    """Check if a port is open on a host."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def extract_urls_from_text(text: str, base_url: Optional[str] = None) -> List[str]:
    """Extract URLs from text content."""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    
    urls = url_pattern.findall(text)
    
    # Also look for relative URLs if base_url is provided
    if base_url:
        relative_pattern = re.compile(r'(?:href|src)=["\']([^"\']+)["\']')
        relative_urls = relative_pattern.findall(text)
        
        for rel_url in relative_urls:
            if not rel_url.startswith(('http://', 'https://', 'javascript:', 'mailto:')):
                full_url = urljoin(base_url, rel_url)
                urls.append(full_url)
    
    return list(set(urls))


def extract_subdomains_from_text(text: str, domain: str) -> List[str]:
    """Extract subdomains for a specific domain from text."""
    # Pattern to match subdomains
    pattern = rf'\b[\w\.-]*\.{re.escape(domain)}\b'
    matches = re.findall(pattern, text, re.IGNORECASE)
    
    # Filter out false positives and clean up
    subdomains = []
    for match in matches:
        if match.endswith(f'.{domain}'):
            subdomains.append(match.lower())
    
    return list(set(subdomains))


def hash_content(content: str) -> str:
    """Generate hash of content for caching/deduplication."""
    return hashlib.md5(content.encode()).hexdigest()


def format_bytes(bytes_count: int) -> str:
    """Format bytes into human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable format."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


async def run_command_async(command: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run a command asynchronously and return results."""
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )
        
        return {
            "returncode": process.returncode,
            "stdout": stdout.decode('utf-8', errors='ignore'),
            "stderr": stderr.decode('utf-8', errors='ignore'),
            "success": process.returncode == 0
        }
    
    except asyncio.TimeoutError:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out",
            "success": False
        }
    except Exception as e:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "success": False
        }


def safe_filename(filename: str) -> str:
    """Make a filename safe for the filesystem."""
    # Remove or replace unsafe characters
    filename = re.sub(r'[^\w\-_.]', '_', filename)
    # Remove consecutive underscores
    filename = re.sub(r'_+', '_', filename)
    # Limit length
    return filename[:200]


def load_wordlist(file_path: str) -> List[str]:
    """Load wordlist from file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []


def save_json_report(data: Dict[str, Any], file_path: str) -> bool:
    """Save data as JSON report."""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception:
        return False


def get_timestamp() -> str:
    """Get current timestamp as string."""
    return datetime.now().isoformat()


async def batch_process(
    items: List[Any], 
    func: Callable[[Any], Awaitable[Any]], 
    max_concurrent: int = 10
) -> List[Any]:
    """Process items in batches with concurrency limit."""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_item(item):
        async with semaphore:
            return await func(item)
    
    tasks = [process_item(item) for item in items]
    return await asyncio.gather(*tasks, return_exceptions=True)
