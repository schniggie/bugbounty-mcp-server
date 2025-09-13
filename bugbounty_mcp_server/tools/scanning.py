"""
Network and web scanning tools for vulnerability discovery and enumeration.
"""

import asyncio
import json
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse, urljoin
import aiohttp
from mcp.types import Tool
from .base import BaseTools
from ..utils import (
    validate_target, run_command_async, check_port_open,
    get_timestamp, batch_process
)


class ScanningTools(BaseTools):
    """Network and web scanning tools."""
    
    def get_tools(self) -> List[Tool]:
        """Return list of scanning tools."""
        return [
            Tool(
                name="port_scan",
                description="Comprehensive port scanning using nmap and masscan",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target IP/domain/CIDR"},
                        "ports": {"type": "string", "description": "Port range (e.g., '1-1000', 'top1000', or specific ports)"},
                        "scan_type": {"type": "string", "enum": ["tcp", "udp", "syn", "connect", "stealth"], "default": "syn"},
                        "timing": {"type": "string", "enum": ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"], "default": "normal"},
                        "service_detection": {"type": "boolean", "default": True},
                        "os_detection": {"type": "boolean", "default": False}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="service_enumeration",
                description="Enumerate services running on discovered ports",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target IP/domain"},
                        "ports": {"type": "array", "items": {"type": "integer"}, "description": "Specific ports to enumerate"},
                        "aggressive": {"type": "boolean", "default": False, "description": "Use aggressive enumeration"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="web_directory_scan",
                description="Scan for hidden directories and files using multiple tools",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "wordlist": {"type": "string", "description": "Custom wordlist path"},
                        "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions to search"},
                        "recursive": {"type": "boolean", "default": False, "description": "Recursive scanning"},
                        "depth": {"type": "integer", "default": 2, "description": "Maximum recursion depth"},
                        "threads": {"type": "integer", "default": 10, "description": "Number of threads"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="web_crawler",
                description="Crawl website to discover all accessible pages and endpoints",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Starting URL"},
                        "max_depth": {"type": "integer", "default": 3, "description": "Maximum crawl depth"},
                        "max_pages": {"type": "integer", "default": 100, "description": "Maximum pages to crawl"},
                        "follow_external": {"type": "boolean", "default": False, "description": "Follow external links"},
                        "extract_forms": {"type": "boolean", "default": True, "description": "Extract forms and parameters"},
                        "extract_apis": {"type": "boolean", "default": True, "description": "Extract API endpoints"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="parameter_discovery",
                description="Discover hidden parameters in web applications",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                        "wordlist": {"type": "string", "description": "Parameter wordlist"},
                        "placeholder": {"type": "string", "default": "FUZZ", "description": "Parameter placeholder value"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="subdomain_takeover_check",
                description="Check for subdomain takeover vulnerabilities",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "subdomains": {"type": "array", "items": {"type": "string"}, "description": "List of subdomains to check"},
                        "domain": {"type": "string", "description": "Primary domain (will enumerate subdomains if subdomains not provided)"}
                    }
                }
            ),
            Tool(
                name="ssl_scan",
                description="Comprehensive SSL/TLS security scan",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target domain or IP"},
                        "port": {"type": "integer", "default": 443, "description": "SSL port"},
                        "check_vulnerabilities": {"type": "boolean", "default": True, "description": "Check for SSL vulnerabilities"},
                        "check_ciphers": {"type": "boolean", "default": True, "description": "Check cipher suites"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="cms_scan",
                description="Scan and enumerate CMS (WordPress, Drupal, Joomla) vulnerabilities",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "cms_type": {"type": "string", "enum": ["auto", "wordpress", "drupal", "joomla"], "default": "auto"},
                        "enumerate_users": {"type": "boolean", "default": True, "description": "Enumerate users"},
                        "enumerate_plugins": {"type": "boolean", "default": True, "description": "Enumerate plugins/modules"},
                        "enumerate_themes": {"type": "boolean", "default": True, "description": "Enumerate themes"},
                        "check_vulnerabilities": {"type": "boolean", "default": True, "description": "Check for known vulnerabilities"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="javascript_analysis",
                description="Analyze JavaScript files for sensitive information and endpoints",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL or direct JS file URL"},
                        "extract_endpoints": {"type": "boolean", "default": True, "description": "Extract API endpoints"},
                        "extract_secrets": {"type": "boolean", "default": True, "description": "Extract potential secrets"},
                        "extract_domains": {"type": "boolean", "default": True, "description": "Extract domain names"},
                        "beautify": {"type": "boolean", "default": False, "description": "Beautify minified JavaScript"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="http_methods_scan",
                description="Test HTTP methods and verb tampering",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "methods": {"type": "array", "items": {"type": "string"}, "description": "HTTP methods to test"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="cors_scan",
                description="Test Cross-Origin Resource Sharing (CORS) configuration",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "test_origins": {"type": "array", "items": {"type": "string"}, "description": "Origins to test"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="headers_analysis",
                description="Analyze HTTP security headers",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "check_all": {"type": "boolean", "default": True, "description": "Check all security headers"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="nuclei_scan",
                description="Run Nuclei vulnerability scanner with custom templates",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL or IP"},
                        "templates": {"type": "array", "items": {"type": "string"}, "description": "Specific templates to use"},
                        "severity": {"type": "array", "items": {"type": "string"}, "description": "Severity levels to include"},
                        "tags": {"type": "array", "items": {"type": "string"}, "description": "Template tags to include"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="fuzzing_scan",
                description="Fuzz web application inputs for vulnerabilities",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL with FUZZ placeholder"},
                        "wordlist": {"type": "string", "description": "Fuzzing wordlist"},
                        "filter_codes": {"type": "array", "items": {"type": "integer"}, "description": "HTTP status codes to filter out"},
                        "filter_size": {"type": "integer", "description": "Response size to filter out"},
                        "match_regex": {"type": "string", "description": "Regex pattern to match responses"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="api_endpoint_discovery",
                description="Discover API endpoints and analyze their structure",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "description": "Base API URL"},
                        "api_type": {"type": "string", "enum": ["rest", "graphql", "soap", "auto"], "default": "auto"},
                        "common_paths": {"type": "boolean", "default": True, "description": "Check common API paths"},
                        "version_enumeration": {"type": "boolean", "default": True, "description": "Enumerate API versions"}
                    },
                    "required": ["base_url"]
                }
            )
        ]
    
    async def port_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_type: str = "syn",
        timing: str = "normal",
        service_detection: bool = True,
        os_detection: bool = False
    ) -> str:
        """Comprehensive port scanning."""
        target_info = validate_target(target)
        if not target_info["valid"]:
            return f"Invalid target: {target}"
        
        if not self.check_target_allowed(target):
            return f"Target {target} is not allowed for scanning"
        
        results = {
            "target": target,
            "timestamp": get_timestamp(),
            "scan_type": scan_type,
            "ports_scanned": ports or "default",
            "open_ports": [],
            "services": {},
            "os_info": {},
            "scan_stats": {}
        }
        
        # Determine port range
        if not ports:
            port_args = ["-F"]  # Fast scan (top 100 ports)
        elif ports == "top1000":
            port_args = ["--top-ports", "1000"]
        elif ports == "all":
            port_args = ["-p-"]
        else:
            port_args = ["-p", ports]
        
        # Build nmap command
        nmap_cmd = ["nmap"]
        
        # Scan type
        if scan_type == "syn":
            nmap_cmd.append("-sS")
        elif scan_type == "connect":
            nmap_cmd.append("-sT")
        elif scan_type == "udp":
            nmap_cmd.append("-sU")
        elif scan_type == "stealth":
            nmap_cmd.extend(["-sS", "-f"])  # Fragment packets
        
        # Timing
        timing_map = {
            "paranoid": "-T0",
            "sneaky": "-T1", 
            "polite": "-T2",
            "normal": "-T3",
            "aggressive": "-T4",
            "insane": "-T5"
        }
        nmap_cmd.append(timing_map.get(timing, "-T3"))
        
        # Service detection
        if service_detection:
            nmap_cmd.extend(["-sV", "-sC"])
        
        # OS detection
        if os_detection:
            nmap_cmd.append("-O")
        
        # Output format
        nmap_cmd.extend(["-oX", "-"])  # XML output to stdout
        
        # Add port arguments and target
        nmap_cmd.extend(port_args)
        nmap_cmd.append(target)
        
        try:
            result = await run_command_async(nmap_cmd, timeout=300)  # 5 minute timeout
            
            if result["success"]:
                # Parse nmap XML output
                results.update(self._parse_nmap_output(result["stdout"]))
            else:
                results["error"] = result["stderr"]
        
        except Exception as e:
            results["error"] = str(e)
        
        return self.format_result(results, f"Port Scan Results for {target}")
    
    async def service_enumeration(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        aggressive: bool = False
    ) -> str:
        """Enumerate services on specific ports."""
        if not self.check_target_allowed(target):
            return f"Target {target} is not allowed for scanning"
        
        results = {
            "target": target,
            "timestamp": get_timestamp(),
            "services": {},
            "banner_grabs": {},
            "vulnerabilities": []
        }
        
        # If no ports specified, do a quick scan first
        if not ports:
            quick_scan = await self._quick_port_scan(target)
            ports = quick_scan.get("open_ports", [])
        
        if not ports:
            return f"No open ports found on {target}"
        
        # Enumerate each service
        for port in ports:
            service_info = await self._enumerate_service(target, port, aggressive)
            if service_info:
                results["services"][port] = service_info
        
        return self.format_result(results, f"Service Enumeration for {target}")
    
    async def web_directory_scan(
        self,
        url: str,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
        depth: int = 2,
        threads: int = 10
    ) -> str:
        """Scan for hidden directories and files."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "found_paths": [],
            "interesting_files": [],
            "status_codes": {},
            "total_requests": 0
        }
        
        # Use multiple tools for directory scanning
        tools_results = await asyncio.gather(
            self._gobuster_scan(url, wordlist, extensions, threads),
            self._ffuf_scan(url, wordlist, extensions),
            self._dirb_scan(url, wordlist),
            return_exceptions=True
        )
        
        # Combine results from all tools
        for tool_result in tools_results:
            if isinstance(tool_result, dict):
                results["found_paths"].extend(tool_result.get("paths", []))
                results["interesting_files"].extend(tool_result.get("files", []))
        
        # Remove duplicates and sort
        results["found_paths"] = sorted(list(set(results["found_paths"])))
        results["interesting_files"] = sorted(list(set(results["interesting_files"])))
        
        # If recursive scanning enabled
        if recursive and depth > 1:
            recursive_results = await self._recursive_directory_scan(
                results["found_paths"], depth - 1, wordlist, extensions
            )
            results["recursive_findings"] = recursive_results
        
        return self.format_result(results, f"Directory Scan Results for {url}")
    
    async def web_crawler(
        self,
        url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        follow_external: bool = False,
        extract_forms: bool = True,
        extract_apis: bool = True
    ) -> str:
        """Crawl website to discover pages and endpoints."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "start_url": url,
            "timestamp": get_timestamp(),
            "pages_found": [],
            "forms": [],
            "api_endpoints": [],
            "external_links": [],
            "parameters": set(),
            "js_files": [],
            "css_files": [],
            "images": [],
            "crawl_stats": {
                "pages_crawled": 0,
                "depth_reached": 0,
                "errors": 0
            }
        }
        
        visited = set()
        to_visit = [(url, 0)]  # (url, depth)
        
        async with aiohttp.ClientSession() as session:
            while to_visit and len(visited) < max_pages:
                current_url, depth = to_visit.pop(0)
                
                if current_url in visited or depth > max_depth:
                    continue
                
                visited.add(current_url)
                results["crawl_stats"]["pages_crawled"] += 1
                results["crawl_stats"]["depth_reached"] = max(results["crawl_stats"]["depth_reached"], depth)
                
                try:
                    await self.rate_limit()
                    async with session.get(current_url, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Extract links
                            new_links = self._extract_links(content, current_url)
                            
                            for link in new_links:
                                parsed_link = urlparse(link)
                                
                                if follow_external or parsed_link.netloc == domain:
                                    if link not in visited and (link, depth + 1) not in to_visit:
                                        to_visit.append((link, depth + 1))
                                        
                                        if parsed_link.netloc == domain:
                                            results["pages_found"].append(link)
                                        else:
                                            results["external_links"].append(link)
                            
                            # Extract forms
                            if extract_forms:
                                forms = self._extract_forms(content, current_url)
                                results["forms"].extend(forms)
                            
                            # Extract API endpoints
                            if extract_apis:
                                apis = self._extract_api_endpoints(content)
                                results["api_endpoints"].extend(apis)
                            
                            # Extract resources
                            results["js_files"].extend(self._extract_js_files(content, current_url))
                            results["css_files"].extend(self._extract_css_files(content, current_url))
                            results["images"].extend(self._extract_images(content, current_url))
                            
                            # Extract parameters
                            params = self._extract_parameters(current_url, content)
                            results["parameters"].update(params)
                        
                        else:
                            results["crawl_stats"]["errors"] += 1
                
                except Exception:
                    results["crawl_stats"]["errors"] += 1
        
        # Convert sets to lists for JSON serialization
        results["parameters"] = sorted(list(results["parameters"]))
        
        # Remove duplicates
        for key in ["pages_found", "forms", "api_endpoints", "external_links", "js_files", "css_files", "images"]:
            if isinstance(results[key], list):
                results[key] = list(set(results[key]))
        
        return self.format_result(results, f"Web Crawl Results for {url}")
    
    async def parameter_discovery(
        self,
        url: str,
        method: str = "GET",
        wordlist: Optional[str] = None,
        placeholder: str = "FUZZ"
    ) -> str:
        """Discover hidden parameters."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "method": method,
            "timestamp": get_timestamp(),
            "found_parameters": [],
            "interesting_responses": []
        }
        
        # Load parameter wordlist
        if not wordlist:
            wordlist = "wordlists/parameters.txt"
        
        try:
            with open(wordlist, 'r') as f:
                parameters = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Use default parameter list
            parameters = [
                "id", "user", "admin", "test", "debug", "page", "file", "path",
                "url", "query", "search", "q", "s", "keyword", "key", "token",
                "session", "sid", "uid", "pid", "action", "cmd", "command",
                "exec", "execute", "run", "do", "function", "func", "method",
                "callback", "jsonp", "format", "type", "mode", "view", "show"
            ]
        
        # Test parameters
        baseline_response = await self._make_request(url, method, {})
        
        async def test_parameter(param):
            test_params = {param: placeholder}
            response = await self._make_request(url, method, test_params)
            
            if response and self._is_response_different(baseline_response, response):
                return {
                    "parameter": param,
                    "status_code": response.get("status_code"),
                    "content_length": len(response.get("content", "")),
                    "response_time": response.get("response_time")
                }
            return None
        
        # Process parameters in batches
        found_params = await batch_process(
            parameters[:500],  # Limit to 500 parameters
            test_parameter,
            self.config.tools.max_concurrent_scans
        )
        
        results["found_parameters"] = [p for p in found_params if p]
        
        return self.format_result(results, f"Parameter Discovery for {url}")
    
    async def subdomain_takeover_check(
        self,
        subdomains: Optional[List[str]] = None,
        domain: Optional[str] = None
    ) -> str:
        """Check for subdomain takeover vulnerabilities."""
        if not subdomains and not domain:
            return "Either subdomains list or domain must be provided"
        
        if domain and not subdomains:
            if not self.check_target_allowed(domain):
                return f"Target {domain} is not allowed for scanning"
            # Would need to enumerate subdomains first
            subdomains = [f"www.{domain}", f"mail.{domain}", f"ftp.{domain}"]
        
        results = {
            "timestamp": get_timestamp(),
            "checked_subdomains": len(subdomains) if subdomains else 0,
            "vulnerable": [],
            "potentially_vulnerable": [],
            "safe": []
        }
        
        # Takeover signatures
        takeover_signatures = {
            "github": ["There isn't a GitHub Pages site here."],
            "heroku": ["No such app"],
            "shopify": ["Sorry, this shop is currently unavailable"],
            "tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
            "wordpress": ["Do you want to register"],
            "ghost": ["The thing you were looking for is no longer here"],
            "aws": ["NoSuchBucket", "The specified bucket does not exist"],
            "bitbucket": ["Repository not found"],
            "cargo": ["404 Not Found"],
            "fastly": ["Fastly error: unknown domain"],
            "feedpress": ["The feed has not been found"],
            "freshdesk": ["May be this is still fresh!"],
            "pantheon": ["The gods are wise"],
            "surge": ["project not found"],
            "zendesk": ["Help Center Closed"]
        }
        
        async def check_subdomain(subdomain):
            try:
                async with aiohttp.ClientSession() as session:
                    await self.rate_limit()
                    async with session.get(f"http://{subdomain}", timeout=10) as response:
                        content = await response.text()
                        
                        for service, signatures in takeover_signatures.items():
                            for signature in signatures:
                                if signature.lower() in content.lower():
                                    return {
                                        "subdomain": subdomain,
                                        "service": service,
                                        "signature": signature,
                                        "status": "vulnerable"
                                    }
                        
                        # Check CNAME records
                        try:
                            import dns.resolver
                            answers = dns.resolver.resolve(subdomain, 'CNAME')
                            cname = str(answers[0])
                            
                            dangerous_cnames = [
                                "github.io", "herokuapp.com", "wordpress.com",
                                "tumblr.com", "bitbucket.io", "ghost.io"
                            ]
                            
                            for dangerous in dangerous_cnames:
                                if dangerous in cname:
                                    return {
                                        "subdomain": subdomain,
                                        "cname": cname,
                                        "status": "potentially_vulnerable"
                                    }
                        except:
                            pass
                        
                        return {"subdomain": subdomain, "status": "safe"}
            
            except Exception:
                return {"subdomain": subdomain, "status": "error"}
        
        if subdomains:
            check_results = await batch_process(
                subdomains,
                check_subdomain,
                self.config.tools.max_concurrent_scans
            )
            
            for result in check_results:
                if isinstance(result, dict):
                    status = result.get("status")
                    if status == "vulnerable":
                        results["vulnerable"].append(result)
                    elif status == "potentially_vulnerable":
                        results["potentially_vulnerable"].append(result)
                    elif status == "safe":
                        results["safe"].append(result["subdomain"])
        
        return self.format_result(results, "Subdomain Takeover Check Results")
    
    async def ssl_scan(
        self,
        target: str,
        port: int = 443,
        check_vulnerabilities: bool = True,
        check_ciphers: bool = True
    ) -> str:
        """Comprehensive SSL/TLS security scan."""
        if not self.check_target_allowed(target):
            return f"Target {target} is not allowed for scanning"
        
        results = {
            "target": target,
            "port": port,
            "timestamp": get_timestamp(),
            "certificate_info": {},
            "vulnerabilities": [],
            "cipher_suites": [],
            "protocols": [],
            "security_score": 0
        }
        
        # Use testssl.sh if available, otherwise use built-in checks
        testssl_result = await run_command_async([
            "testssl.sh", "--quiet", "--jsonfile-pretty", "/dev/stdout", f"{target}:{port}"
        ], timeout=120)
        
        if testssl_result["success"]:
            try:
                ssl_data = json.loads(testssl_result["stdout"])
                results.update(self._parse_testssl_output(ssl_data))
            except:
                # Fallback to manual SSL checks
                results.update(await self._manual_ssl_check(target, port))
        else:
            results.update(await self._manual_ssl_check(target, port))
        
        return self.format_result(results, f"SSL/TLS Scan for {target}:{port}")
    
    async def cms_scan(
        self,
        url: str,
        cms_type: str = "auto",
        enumerate_users: bool = True,
        enumerate_plugins: bool = True,
        enumerate_themes: bool = True,
        check_vulnerabilities: bool = True
    ) -> str:
        """Scan and enumerate CMS vulnerabilities."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "detected_cms": None,
            "version": None,
            "users": [],
            "plugins": [],
            "themes": [],
            "vulnerabilities": []
        }
        
        # Detect CMS type if auto
        if cms_type == "auto":
            cms_type = await self._detect_cms(url)
            results["detected_cms"] = cms_type
        
        if cms_type == "wordpress":
            wp_results = await self._wordpress_scan(
                url, enumerate_users, enumerate_plugins, 
                enumerate_themes, check_vulnerabilities
            )
            results.update(wp_results)
        
        elif cms_type == "drupal":
            drupal_results = await self._drupal_scan(url, check_vulnerabilities)
            results.update(drupal_results)
        
        elif cms_type == "joomla":
            joomla_results = await self._joomla_scan(url, check_vulnerabilities)
            results.update(joomla_results)
        
        else:
            results["error"] = f"CMS type '{cms_type}' not supported or not detected"
        
        return self.format_result(results, f"CMS Scan Results for {url}")
    
    async def javascript_analysis(
        self,
        url: str,
        extract_endpoints: bool = True,
        extract_secrets: bool = True,
        extract_domains: bool = True,
        beautify: bool = False
    ) -> str:
        """Analyze JavaScript files for sensitive information."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "endpoints": [],
            "secrets": [],
            "domains": [],
            "api_keys": [],
            "comments": [],
            "functions": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                await self.rate_limit()
                async with session.get(url) as response:
                    if response.status == 200:
                        js_content = await response.text()
                        
                        # If it's not a direct JS file, extract JS from HTML
                        if not url.endswith('.js'):
                            js_files = self._extract_js_files(js_content, url)
                            
                            # Analyze each JS file
                            for js_file in js_files[:10]:  # Limit to 10 files
                                js_analysis = await self._analyze_single_js_file(js_file)
                                if js_analysis:
                                    for key in results:
                                        if key in js_analysis:
                                            results[key].extend(js_analysis[key])
                        else:
                            # Direct JS file analysis
                            results.update(self._analyze_js_content(js_content))
                    
                    else:
                        results["error"] = f"HTTP {response.status}"
        
        except Exception as e:
            results["error"] = str(e)
        
        # Remove duplicates
        for key in ["endpoints", "secrets", "domains", "api_keys"]:
            results[key] = list(set(results[key]))
        
        return self.format_result(results, f"JavaScript Analysis for {url}")
    
    async def http_methods_scan(
        self,
        url: str,
        methods: Optional[List[str]] = None
    ) -> str:
        """Test HTTP methods and verb tampering."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        if methods is None:
            methods = [
                "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
                "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
                "COPY", "MOVE", "LOCK", "UNLOCK"
            ]
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "allowed_methods": [],
            "dangerous_methods": [],
            "method_responses": {}
        }
        
        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PATCH"]
        
        async with aiohttp.ClientSession() as session:
            for method in methods:
                try:
                    await self.rate_limit()
                    async with session.request(method, url, timeout=10) as response:
                        results["method_responses"][method] = {
                            "status_code": response.status,
                            "allowed": response.status not in [405, 501]
                        }
                        
                        if response.status not in [405, 501]:
                            results["allowed_methods"].append(method)
                            
                            if method in dangerous:
                                results["dangerous_methods"].append(method)
                
                except Exception as e:
                    results["method_responses"][method] = {"error": str(e)}
        
        return self.format_result(results, f"HTTP Methods Scan for {url}")
    
    async def cors_scan(
        self,
        url: str,
        test_origins: Optional[List[str]] = None
    ) -> str:
        """Test CORS configuration."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        if test_origins is None:
            test_origins = [
                "https://evil.com",
                "http://evil.com",
                "null",
                f"https://evil.{domain}",
                f"https://{domain}.evil.com",
                "https://localhost:3000"
            ]
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "cors_enabled": False,
            "vulnerabilities": [],
            "origin_tests": {}
        }
        
        async with aiohttp.ClientSession() as session:
            for origin in test_origins:
                try:
                    headers = {"Origin": origin}
                    await self.rate_limit()
                    
                    async with session.get(url, headers=headers, timeout=10) as response:
                        cors_headers = {
                            k: v for k, v in response.headers.items() 
                            if k.lower().startswith('access-control-')
                        }
                        
                        results["origin_tests"][origin] = {
                            "cors_headers": cors_headers,
                            "status_code": response.status
                        }
                        
                        # Check for vulnerabilities
                        if "access-control-allow-origin" in cors_headers:
                            results["cors_enabled"] = True
                            allowed_origin = cors_headers["access-control-allow-origin"]
                            
                            if allowed_origin == "*":
                                results["vulnerabilities"].append({
                                    "type": "Wildcard CORS",
                                    "description": "Access-Control-Allow-Origin: * allows any origin"
                                })
                            
                            elif allowed_origin == origin:
                                results["vulnerabilities"].append({
                                    "type": "Reflected Origin",
                                    "description": f"Origin {origin} is reflected in CORS headers",
                                    "origin": origin
                                })
                
                except Exception as e:
                    results["origin_tests"][origin] = {"error": str(e)}
        
        return self.format_result(results, f"CORS Scan for {url}")
    
    async def headers_analysis(self, url: str, check_all: bool = True) -> str:
        """Analyze HTTP security headers."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "security_headers": {},
            "missing_headers": [],
            "security_score": 0,
            "recommendations": []
        }
        
        required_headers = {
            "strict-transport-security": "Prevents protocol downgrade attacks",
            "content-security-policy": "Prevents XSS and injection attacks",
            "x-frame-options": "Prevents clickjacking attacks",
            "x-content-type-options": "Prevents MIME type sniffing",
            "referrer-policy": "Controls referrer information",
            "permissions-policy": "Controls browser features and APIs"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                await self.rate_limit()
                async with session.get(url, timeout=10) as response:
                    headers = dict(response.headers)
                    
                    for header, description in required_headers.items():
                        if header in headers:
                            results["security_headers"][header] = {
                                "value": headers[header],
                                "present": True,
                                "description": description
                            }
                            results["security_score"] += 1
                        else:
                            results["missing_headers"].append({
                                "header": header,
                                "description": description
                            })
                    
                    # Check for potentially dangerous headers
                    dangerous_headers = {
                        "server": "Server information disclosure",
                        "x-powered-by": "Technology stack disclosure"
                    }
                    
                    for header, risk in dangerous_headers.items():
                        if header in headers:
                            results["recommendations"].append({
                                "type": "Remove Header",
                                "header": header,
                                "value": headers[header],
                                "risk": risk
                            })
                    
                    # Calculate security score percentage
                    results["security_score"] = (results["security_score"] / len(required_headers)) * 100
        
        except Exception as e:
            results["error"] = str(e)
        
        return self.format_result(results, f"Security Headers Analysis for {url}")
    
    async def nuclei_scan(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> str:
        """Run Nuclei vulnerability scanner."""
        if not self.check_target_allowed(target):
            return f"Target {target} is not allowed for scanning"
        
        nuclei_cmd = [self.config.tools.nuclei_path, "-u", target, "-json"]
        
        if templates:
            nuclei_cmd.extend(["-t", ",".join(templates)])
        
        if severity:
            nuclei_cmd.extend(["-severity", ",".join(severity)])
        
        if tags:
            nuclei_cmd.extend(["-tags", ",".join(tags)])
        
        results = {
            "target": target,
            "timestamp": get_timestamp(),
            "vulnerabilities": [],
            "scan_stats": {}
        }
        
        try:
            result = await run_command_async(nuclei_cmd, timeout=300)
            
            if result["success"]:
                # Parse JSON output line by line
                for line in result["stdout"].strip().split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            results["vulnerabilities"].append({
                                "template_id": vuln_data.get("template-id"),
                                "name": vuln_data.get("info", {}).get("name"),
                                "severity": vuln_data.get("info", {}).get("severity"),
                                "description": vuln_data.get("info", {}).get("description"),
                                "matched_at": vuln_data.get("matched-at"),
                                "extracted_results": vuln_data.get("extracted-results", [])
                            })
                        except json.JSONDecodeError:
                            continue
                
                results["scan_stats"]["total_vulnerabilities"] = len(results["vulnerabilities"])
                
                # Count by severity
                severity_counts = {}
                for vuln in results["vulnerabilities"]:
                    sev = vuln.get("severity", "unknown")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                results["scan_stats"]["by_severity"] = severity_counts
            
            else:
                results["error"] = result["stderr"]
        
        except Exception as e:
            results["error"] = str(e)
        
        return self.format_result(results, f"Nuclei Scan Results for {target}")
    
    async def fuzzing_scan(
        self,
        url: str,
        wordlist: Optional[str] = None,
        filter_codes: Optional[List[int]] = None,
        filter_size: Optional[int] = None,
        match_regex: Optional[str] = None
    ) -> str:
        """Fuzz web application inputs."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        if "FUZZ" not in url:
            return "URL must contain FUZZ placeholder"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "interesting_responses": [],
            "total_requests": 0,
            "filtered_out": 0
        }
        
        # Use ffuf for fuzzing
        ffuf_cmd = [self.config.tools.ffuf_path, "-u", url, "-o", "/dev/stdout", "-of", "json"]
        
        if wordlist:
            ffuf_cmd.extend(["-w", wordlist])
        else:
            # Use default wordlist
            ffuf_cmd.extend(["-w", self.config.scanning.directory_wordlist])
        
        if filter_codes:
            ffuf_cmd.extend(["-fc", ",".join(map(str, filter_codes))])
        
        if filter_size:
            ffuf_cmd.extend(["-fs", str(filter_size)])
        
        if match_regex:
            ffuf_cmd.extend(["-mr", match_regex])
        
        try:
            result = await run_command_async(ffuf_cmd, timeout=300)
            
            if result["success"]:
                try:
                    ffuf_data = json.loads(result["stdout"])
                    
                    for finding in ffuf_data.get("results", []):
                        results["interesting_responses"].append({
                            "url": finding.get("url"),
                            "status_code": finding.get("status"),
                            "length": finding.get("length"),
                            "words": finding.get("words"),
                            "lines": finding.get("lines"),
                            "response_time": finding.get("duration")
                        })
                    
                    results["total_requests"] = len(ffuf_data.get("results", []))
                
                except json.JSONDecodeError:
                    results["error"] = "Failed to parse ffuf output"
            
            else:
                results["error"] = result["stderr"]
        
        except Exception as e:
            results["error"] = str(e)
        
        return self.format_result(results, f"Fuzzing Results for {url}")
    
    async def api_endpoint_discovery(
        self,
        base_url: str,
        api_type: str = "auto",
        common_paths: bool = True,
        version_enumeration: bool = True
    ) -> str:
        """Discover API endpoints and analyze structure."""
        parsed_url = urlparse(base_url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "base_url": base_url,
            "timestamp": get_timestamp(),
            "api_type": api_type,
            "endpoints": [],
            "versions": [],
            "documentation": [],
            "schema": {}
        }
        
        # Common API paths to check
        if common_paths:
            api_paths = [
                "/api", "/api/v1", "/api/v2", "/api/v3",
                "/rest", "/graphql", "/soap",
                "/swagger.json", "/openapi.json", "/api-docs",
                "/docs", "/documentation", "/spec",
                "/.well-known/openapi_spec"
            ]
            
            for path in api_paths:
                endpoint_url = urljoin(base_url, path)
                endpoint_info = await self._check_api_endpoint(endpoint_url)
                
                if endpoint_info:
                    results["endpoints"].append(endpoint_info)
        
        # Version enumeration
        if version_enumeration:
            versions = await self._enumerate_api_versions(base_url)
            results["versions"] = versions
        
        # Try to detect API type if auto
        if api_type == "auto":
            detected_type = await self._detect_api_type(base_url)
            results["api_type"] = detected_type
        
        return self.format_result(results, f"API Discovery Results for {base_url}")
    
    # Helper methods continue in next part due to length...
    
    async def _parse_nmap_output(self, xml_output: str) -> Dict[str, Any]:
        """Parse nmap XML output."""
        # This would implement XML parsing for nmap results
        # For brevity, returning a simplified structure
        return {
            "open_ports": [],
            "services": {},
            "os_info": {},
            "scan_stats": {"ports_scanned": 0, "hosts_up": 1}
        }
    
    async def _quick_port_scan(self, target: str) -> Dict[str, Any]:
        """Quick port scan to find open ports."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 3306]
        open_ports = []
        
        async def check_port(port):
            if await check_port_open(target, port, timeout=3):
                return port
            return None
        
        results = await batch_process(common_ports, check_port, 20)
        open_ports = [port for port in results if port is not None]
        
        return {"open_ports": open_ports}
    
    async def _enumerate_service(self, target: str, port: int, aggressive: bool) -> Optional[Dict[str, Any]]:
        """Enumerate a specific service."""
        # This would implement service-specific enumeration
        return {
            "port": port,
            "service": "unknown",
            "version": "unknown",
            "banner": ""
        }
    
    # Additional helper methods would continue here...
    # Due to length constraints, I'm providing the core structure
    
    async def _gobuster_scan(self, url: str, wordlist: Optional[str], extensions: Optional[List[str]], threads: int) -> Dict[str, Any]:
        """Run gobuster directory scan."""
        return {"paths": [], "files": []}
    
    async def _ffuf_scan(self, url: str, wordlist: Optional[str], extensions: Optional[List[str]]) -> Dict[str, Any]:
        """Run ffuf directory scan.""" 
        return {"paths": [], "files": []}
    
    async def _dirb_scan(self, url: str, wordlist: Optional[str]) -> Dict[str, Any]:
        """Run dirb directory scan."""
        return {"paths": [], "files": []}
    
    # Additional helper methods would be implemented here...
    def _extract_links(self, content: str, base_url: str) -> List[str]:
        """Extract links from HTML content."""
        return []
    
    def _extract_forms(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content."""
        return []
    
    def _extract_api_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints from content."""
        return []
    
    def _extract_js_files(self, content: str, base_url: str) -> List[str]:
        """Extract JavaScript file URLs."""
        return []
    
    def _extract_css_files(self, content: str, base_url: str) -> List[str]:
        """Extract CSS file URLs."""
        return []
    
    def _extract_images(self, content: str, base_url: str) -> List[str]:
        """Extract image URLs."""
        return []
    
    def _extract_parameters(self, url: str, content: str) -> Set[str]:
        """Extract parameters from URL and content."""
        return set()
    
    async def _make_request(self, url: str, method: str, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Make HTTP request and return response info."""
        return None
    
    def _is_response_different(self, baseline: Optional[Dict[str, Any]], response: Optional[Dict[str, Any]]) -> bool:
        """Check if responses are significantly different."""
        return False
