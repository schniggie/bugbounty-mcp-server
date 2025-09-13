"""
Configuration management for BugBounty MCP Server.
"""

import os
from typing import Dict, Any, Optional, List
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class APIKeys(BaseModel):
    """API keys for various services."""
    shodan: Optional[str] = Field(default=None, description="Shodan API key")
    censys_id: Optional[str] = Field(default=None, description="Censys API ID")
    censys_secret: Optional[str] = Field(default=None, description="Censys API Secret")
    virustotal: Optional[str] = Field(default=None, description="VirusTotal API key")
    github: Optional[str] = Field(default=None, description="GitHub API token")
    securitytrails: Optional[str] = Field(default=None, description="SecurityTrails API key")
    hunter_io: Optional[str] = Field(default=None, description="Hunter.io API key")
    binaryedge: Optional[str] = Field(default=None, description="BinaryEdge API key")
    whoisxml: Optional[str] = Field(default=None, description="WhoisXML API key")
    fofa: Optional[str] = Field(default=None, description="FOFA API key")


class ToolConfig(BaseModel):
    """Tool-specific configurations."""
    nmap_path: str = Field(default="nmap", description="Path to nmap binary")
    masscan_path: str = Field(default="masscan", description="Path to masscan binary")
    nuclei_path: str = Field(default="nuclei", description="Path to nuclei binary")
    subfinder_path: str = Field(default="subfinder", description="Path to subfinder binary")
    httpx_path: str = Field(default="httpx", description="Path to httpx binary")
    gobuster_path: str = Field(default="gobuster", description="Path to gobuster binary")
    ffuf_path: str = Field(default="ffuf", description="Path to ffuf binary")
    sqlmap_path: str = Field(default="sqlmap", description="Path to sqlmap binary")
    nikto_path: str = Field(default="nikto", description="Path to nikto binary")
    dirb_path: str = Field(default="dirb", description="Path to dirb binary")
    wpscan_path: str = Field(default="wpscan", description="Path to wpscan binary")
    
    # Browser settings for Selenium
    chrome_driver_path: Optional[str] = Field(default=None, description="Path to Chrome WebDriver")
    firefox_driver_path: Optional[str] = Field(default=None, description="Path to Firefox WebDriver")
    headless_browser: bool = Field(default=True, description="Run browsers in headless mode")
    
    # Threading and performance
    max_concurrent_scans: int = Field(default=10, description="Maximum concurrent scans")
    default_timeout: int = Field(default=30, description="Default timeout for operations")
    max_retries: int = Field(default=3, description="Maximum retries for failed operations")


class ScanConfig(BaseModel):
    """Scanning configuration."""
    default_ports: List[str] = Field(
        default=[
            "21", "22", "23", "25", "53", "80", "110", "111", "135", "139", "143", 
            "443", "993", "995", "1723", "3306", "3389", "5432", "5900", "8080", 
            "8443", "8888", "9090", "27017", "6379", "11211", "50070"
        ],
        description="Default ports to scan"
    )
    
    top_ports: int = Field(default=1000, description="Number of top ports to scan")
    scan_rate: int = Field(default=1000, description="Scan rate for masscan")
    
    # Web application scanning
    max_crawl_depth: int = Field(default=3, description="Maximum crawl depth")
    max_pages_to_crawl: int = Field(default=100, description="Maximum pages to crawl")
    
    # Wordlists
    subdomain_wordlist: str = Field(
        default="wordlists/subdomains.txt", 
        description="Path to subdomain wordlist"
    )
    directory_wordlist: str = Field(
        default="wordlists/directories.txt", 
        description="Path to directory wordlist"
    )
    common_files_wordlist: str = Field(
        default="wordlists/common_files.txt", 
        description="Path to common files wordlist"
    )


class OutputConfig(BaseModel):
    """Output and reporting configuration."""
    output_dir: str = Field(default="output", description="Output directory")
    report_format: str = Field(default="json", description="Default report format")
    save_raw_output: bool = Field(default=True, description="Save raw tool output")
    create_html_report: bool = Field(default=True, description="Create HTML reports")
    create_pdf_report: bool = Field(default=False, description="Create PDF reports")


class BugBountyConfig(BaseModel):
    """Main configuration class."""
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[str] = Field(default=None, description="Log file path")
    
    # Data storage
    data_dir: str = Field(default="data", description="Data storage directory")
    cache_enabled: bool = Field(default=True, description="Enable caching")
    cache_ttl: int = Field(default=3600, description="Cache TTL in seconds")
    
    # API Keys
    api_keys: APIKeys = Field(default_factory=APIKeys)
    
    # Tool configurations
    tools: ToolConfig = Field(default_factory=ToolConfig)
    
    # Scan configurations
    scanning: ScanConfig = Field(default_factory=ScanConfig)
    
    # Output configurations
    output: OutputConfig = Field(default_factory=OutputConfig)
    
    # Rate limiting
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting")
    requests_per_second: float = Field(default=10.0, description="Requests per second limit")
    
    # Safety features
    safe_mode: bool = Field(default=True, description="Enable safe mode (no destructive operations)")
    allowed_targets: List[str] = Field(default=[], description="Allowed target domains/IPs")
    blocked_targets: List[str] = Field(default=[], description="Blocked target domains/IPs")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._load_from_env()
        self._create_directories()

    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # API Keys from environment
        if shodan_key := os.getenv("SHODAN_API_KEY"):
            self.api_keys.shodan = shodan_key
        if censys_id := os.getenv("CENSYS_API_ID"):
            self.api_keys.censys_id = censys_id
        if censys_secret := os.getenv("CENSYS_API_SECRET"):
            self.api_keys.censys_secret = censys_secret
        if vt_key := os.getenv("VIRUSTOTAL_API_KEY"):
            self.api_keys.virustotal = vt_key
        if github_token := os.getenv("GITHUB_TOKEN"):
            self.api_keys.github = github_token
        if st_key := os.getenv("SECURITYTRAILS_API_KEY"):
            self.api_keys.securitytrails = st_key
        if hunter_key := os.getenv("HUNTER_IO_API_KEY"):
            self.api_keys.hunter_io = hunter_key
        if be_key := os.getenv("BINARYEDGE_API_KEY"):
            self.api_keys.binaryedge = be_key

        # Other configurations
        if log_level := os.getenv("LOG_LEVEL"):
            self.log_level = log_level
        if output_dir := os.getenv("OUTPUT_DIR"):
            self.output.output_dir = output_dir

    def _create_directories(self) -> None:
        """Create necessary directories."""
        dirs_to_create = [
            self.data_dir,
            self.output.output_dir,
            "wordlists",
            "logs",
            "cache"
        ]
        
        for dir_path in dirs_to_create:
            Path(dir_path).mkdir(parents=True, exist_ok=True)

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service."""
        return getattr(self.api_keys, service, None)

    def is_target_allowed(self, target: str) -> bool:
        """Check if a target is allowed for scanning."""
        if self.safe_mode and self.allowed_targets:
            return any(target.endswith(allowed) for allowed in self.allowed_targets)
        
        if self.blocked_targets:
            return not any(target.endswith(blocked) for blocked in self.blocked_targets)
        
        return True
