"""
Reconnaissance tools for domain enumeration, subdomain discovery, and asset gathering.
"""

import asyncio
import json
import re
import socket
import ssl
import subprocess
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse
import aiohttp
import dns.resolver
from mcp.types import Tool
from .base import BaseTools
from ..utils import (
    validate_target, resolve_domain, run_command_async, 
    extract_subdomains_from_text, get_timestamp
)


class ReconTools(BaseTools):
    """Reconnaissance and information gathering tools."""
    
    def get_tools(self) -> List[Tool]:
        """Return list of reconnaissance tools."""
        return [
            Tool(
                name="subdomain_enumeration",
                description="Comprehensive subdomain enumeration using multiple techniques",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "passive": {"type": "boolean", "default": True, "description": "Use passive enumeration"},
                        "brute_force": {"type": "boolean", "default": False, "description": "Use brute force enumeration"},
                        "wordlist": {"type": "string", "description": "Custom wordlist path"}
                    },
                    "required": ["domain"]
                }
            ),
            Tool(
                name="dns_enumeration",
                description="Comprehensive DNS record enumeration and analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "record_types": {"type": "array", "items": {"type": "string"}, "description": "DNS record types to query"}
                    },
                    "required": ["domain"]
                }
            ),
            Tool(
                name="whois_lookup",
                description="WHOIS information gathering for domains and IPs",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Domain or IP address"},
                        "detailed": {"type": "boolean", "default": False, "description": "Include detailed historical data"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="certificate_transparency",
                description="Search certificate transparency logs for subdomains",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "include_expired": {"type": "boolean", "default": False, "description": "Include expired certificates"}
                    },
                    "required": ["domain"]
                }
            ),
            Tool(
                name="reverse_dns_lookup",
                description="Reverse DNS lookup for IP ranges and individual IPs",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP address or CIDR range"},
                        "timeout": {"type": "integer", "default": 5, "description": "Timeout in seconds"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="google_dorking",
                description="Automated Google dorking for information gathering",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "dork_type": {"type": "string", "enum": ["files", "subdomains", "directories", "parameters", "all"], "default": "all"},
                        "custom_dorks": {"type": "array", "items": {"type": "string"}, "description": "Custom Google dorks"}
                    },
                    "required": ["domain"]
                }
            ),
            Tool(
                name="shodan_search",
                description="Search Shodan for exposed services and devices",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Shodan search query"},
                        "domain": {"type": "string", "description": "Target domain (alternative to query)"},
                        "limit": {"type": "integer", "default": 100, "description": "Maximum results"}
                    }
                }
            ),
            Tool(
                name="censys_search",
                description="Search Censys for certificates and hosts",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Censys search query"},
                        "domain": {"type": "string", "description": "Target domain"},
                        "search_type": {"type": "string", "enum": ["hosts", "certificates"], "default": "hosts"}
                    }
                }
            ),
            Tool(
                name="github_reconnaissance",
                description="Search GitHub for sensitive information and repositories",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "keywords": {"type": "array", "items": {"type": "string"}, "description": "Additional keywords"},
                        "search_type": {"type": "string", "enum": ["repositories", "code", "commits", "all"], "default": "all"}
                    },
                    "required": ["domain"]
                }
            ),
            Tool(
                name="archive_org_search",
                description="Search Wayback Machine for historical data",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "limit": {"type": "integer", "default": 100, "description": "Maximum snapshots"},
                        "year": {"type": "integer", "description": "Specific year to search"}
                    },
                    "required": ["domain"]
                }
            ),
            Tool(
                name="technology_detection",
                description="Detect technologies used by target websites",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "deep_scan": {"type": "boolean", "default": False, "description": "Perform deep technology detection"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="social_media_search",
                description="Search social media platforms for information",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain or company name"},
                        "platforms": {"type": "array", "items": {"type": "string"}, "description": "Platforms to search"}
                    },
                    "required": ["domain"]
                }
            ),
            Tool(
                name="email_enumeration",
                description="Enumerate email addresses for a domain",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Target domain"},
                        "source": {"type": "string", "enum": ["hunter", "clearbit", "all"], "default": "all"}
                    },
                    "required": ["domain"]
                }
            )
        ]
    
    async def subdomain_enumeration(
        self, 
        domain: str, 
        passive: bool = True, 
        brute_force: bool = False,
        wordlist: Optional[str] = None
    ) -> str:
        """Comprehensive subdomain enumeration."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        cache_key = f"subdomains_{domain}_{passive}_{brute_force}"
        cached_result = self.get_cached(cache_key)
        if cached_result:
            return cached_result
        
        results = {
            "domain": domain,
            "timestamp": get_timestamp(),
            "subdomains": set(),
            "methods": {}
        }
        
        # Passive enumeration methods
        if passive:
            # Certificate Transparency
            ct_subs = await self._cert_transparency_search(domain)
            results["subdomains"].update(ct_subs)
            results["methods"]["certificate_transparency"] = len(ct_subs)
            
            # DNS enumeration
            dns_subs = await self._dns_passive_enum(domain)
            results["subdomains"].update(dns_subs)
            results["methods"]["dns_passive"] = len(dns_subs)
            
            # Search engines
            search_subs = await self._search_engine_subdomains(domain)
            results["subdomains"].update(search_subs)
            results["methods"]["search_engines"] = len(search_subs)
            
            # Third-party APIs
            api_subs = await self._api_subdomain_search(domain)
            results["subdomains"].update(api_subs)
            results["methods"]["third_party_apis"] = len(api_subs)
        
        # Brute force enumeration
        if brute_force:
            bf_subs = await self._brute_force_subdomains(domain, wordlist)
            results["subdomains"].update(bf_subs)
            results["methods"]["brute_force"] = len(bf_subs)
        
        # Convert set to sorted list
        results["subdomains"] = sorted(list(results["subdomains"]))
        results["total_found"] = len(results["subdomains"])
        
        result_str = self.format_result(results, f"Subdomain Enumeration for {domain}")
        self.set_cached(cache_key, result_str)
        
        return result_str
    
    async def dns_enumeration(self, domain: str, record_types: Optional[List[str]] = None) -> str:
        """Comprehensive DNS record enumeration."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        if record_types is None:
            record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "PTR"]
        
        results = {
            "domain": domain,
            "timestamp": get_timestamp(),
            "records": {}
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        
        for record_type in record_types:
            try:
                await self.rate_limit()
                answers = resolver.resolve(domain, record_type)
                results["records"][record_type] = [str(answer) for answer in answers]
            except Exception as e:
                results["records"][record_type] = f"Error: {str(e)}"
        
        # Additional DNS queries
        try:
            # Zone transfer attempt
            results["zone_transfer"] = await self._attempt_zone_transfer(domain)
        except Exception as e:
            results["zone_transfer"] = f"Failed: {str(e)}"
        
        return self.format_result(results, f"DNS Enumeration for {domain}")
    
    async def whois_lookup(self, target: str, detailed: bool = False) -> str:
        """WHOIS information gathering."""
        if not self.check_target_allowed(target):
            return f"Target {target} is not allowed for scanning"
        
        cache_key = f"whois_{target}_{detailed}"
        cached_result = self.get_cached(cache_key)
        if cached_result:
            return cached_result
        
        results = {
            "target": target,
            "timestamp": get_timestamp(),
            "whois_data": {},
            "registrar_info": {},
            "nameservers": [],
            "creation_date": None,
            "expiration_date": None
        }
        
        try:
            # Use whois command
            cmd_result = await run_command_async(["whois", target])
            if cmd_result["success"]:
                whois_text = cmd_result["stdout"]
                results["whois_data"]["raw"] = whois_text
                
                # Parse important fields
                results.update(self._parse_whois_data(whois_text))
            
        except Exception as e:
            results["error"] = str(e)
        
        result_str = self.format_result(results, f"WHOIS Lookup for {target}")
        self.set_cached(cache_key, result_str)
        
        return result_str
    
    async def certificate_transparency(
        self, 
        domain: str, 
        include_expired: bool = False
    ) -> str:
        """Search certificate transparency logs."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        subdomains = await self._cert_transparency_search(domain, include_expired)
        
        results = {
            "domain": domain,
            "timestamp": get_timestamp(),
            "subdomains_found": len(subdomains),
            "subdomains": sorted(list(subdomains)),
            "include_expired": include_expired
        }
        
        return self.format_result(results, f"Certificate Transparency Search for {domain}")
    
    async def reverse_dns_lookup(self, target: str, timeout: int = 5) -> str:
        """Reverse DNS lookup for IPs."""
        results = {
            "target": target,
            "timestamp": get_timestamp(),
            "reverse_records": []
        }
        
        # Handle CIDR ranges
        if "/" in target:
            try:
                import ipaddress
                network = ipaddress.ip_network(target, strict=False)
                
                # Limit to reasonable size
                if network.num_addresses > 256:
                    return "CIDR range too large (max 256 addresses)"
                
                tasks = []
                for ip in network.hosts():
                    tasks.append(self._reverse_dns_single(str(ip), timeout))
                
                # Process in batches
                batch_size = 50
                for i in range(0, len(tasks), batch_size):
                    batch = tasks[i:i+batch_size]
                    batch_results = await asyncio.gather(*batch, return_exceptions=True)
                    
                    for ip_str, result in zip([str(ip) for ip in list(network.hosts())[i:i+batch_size]], batch_results):
                        if isinstance(result, str) and result != ip_str:
                            results["reverse_records"].append({
                                "ip": ip_str,
                                "hostname": result
                            })
            
            except Exception as e:
                results["error"] = str(e)
        
        else:
            # Single IP
            hostname = await self._reverse_dns_single(target, timeout)
            if hostname and hostname != target:
                results["reverse_records"].append({
                    "ip": target,
                    "hostname": hostname
                })
        
        return self.format_result(results, f"Reverse DNS Lookup for {target}")
    
    async def google_dorking(
        self, 
        domain: str, 
        dork_type: str = "all",
        custom_dorks: Optional[List[str]] = None
    ) -> str:
        """Automated Google dorking."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        dorks = []
        
        if dork_type in ["files", "all"]:
            dorks.extend([
                f'site:{domain} filetype:pdf',
                f'site:{domain} filetype:doc',
                f'site:{domain} filetype:xls',
                f'site:{domain} filetype:ppt',
                f'site:{domain} filetype:sql',
                f'site:{domain} filetype:xml',
                f'site:{domain} filetype:conf',
                f'site:{domain} filetype:cnf',
                f'site:{domain} filetype:reg',
                f'site:{domain} filetype:inf',
                f'site:{domain} filetype:rdp',
                f'site:{domain} filetype:cfg',
                f'site:{domain} filetype:txt',
                f'site:{domain} filetype:ora',
                f'site:{domain} filetype:ini',
            ])
        
        if dork_type in ["subdomains", "all"]:
            dorks.extend([
                f'site:*.{domain}',
                f'site:{domain} -site:www.{domain}',
                f'inurl:{domain}',
            ])
        
        if dork_type in ["directories", "all"]:
            dorks.extend([
                f'site:{domain} intitle:"index of"',
                f'site:{domain} intitle:"directory listing"',
                f'site:{domain} "parent directory"',
                f'site:{domain} inurl:"/admin"',
                f'site:{domain} inurl:"/backup"',
                f'site:{domain} inurl:"/config"',
                f'site:{domain} inurl:"/test"',
                f'site:{domain} inurl:"/dev"',
                f'site:{domain} inurl:"/staging"',
            ])
        
        if dork_type in ["parameters", "all"]:
            dorks.extend([
                f'site:{domain} inurl:"id="',
                f'site:{domain} inurl:"user="',
                f'site:{domain} inurl:"query="',
                f'site:{domain} inurl:"search="',
                f'site:{domain} inurl:"page="',
                f'site:{domain} inurl:"file="',
                f'site:{domain} inurl:"path="',
                f'site:{domain} inurl:"debug="',
            ])
        
        if custom_dorks:
            dorks.extend([dork.replace("{domain}", domain) for dork in custom_dorks])
        
        results = {
            "domain": domain,
            "timestamp": get_timestamp(),
            "dork_type": dork_type,
            "total_dorks": len(dorks),
            "dorks": dorks
        }
        
        return self.format_result(results, f"Google Dorking for {domain}")
    
    async def shodan_search(
        self, 
        query: Optional[str] = None, 
        domain: Optional[str] = None,
        limit: int = 100
    ) -> str:
        """Search Shodan for exposed services."""
        api_key = self.config.get_api_key("shodan")
        if not api_key:
            return "Shodan API key not configured"
        
        if not query and not domain:
            return "Either query or domain must be provided"
        
        if domain and not query:
            if not self.check_target_allowed(domain):
                return f"Target {domain} is not allowed for scanning"
            query = f"hostname:{domain}"
        
        try:
            import shodan
            api = shodan.Shodan(api_key)
            
            results = {
                "query": query,
                "timestamp": get_timestamp(),
                "total": 0,
                "results": []
            }
            
            # Search Shodan
            search_results = api.search(query, limit=limit)
            results["total"] = search_results["total"]
            
            for result in search_results["matches"]:
                results["results"].append({
                    "ip": result.get("ip_str"),
                    "port": result.get("port"),
                    "hostnames": result.get("hostnames", []),
                    "organization": result.get("org"),
                    "country": result.get("location", {}).get("country_name"),
                    "city": result.get("location", {}).get("city"),
                    "product": result.get("product"),
                    "version": result.get("version"),
                    "banner": result.get("data", "")[:200] + "..." if len(result.get("data", "")) > 200 else result.get("data", "")
                })
            
            return self.format_result(results, f"Shodan Search Results for '{query}'")
            
        except Exception as e:
            return f"Shodan search failed: {str(e)}"
    
    async def censys_search(
        self, 
        query: Optional[str] = None,
        domain: Optional[str] = None,
        search_type: str = "hosts"
    ) -> str:
        """Search Censys for certificates and hosts."""
        api_id = self.config.get_api_key("censys_id")
        api_secret = self.config.get_api_key("censys_secret")
        
        if not api_id or not api_secret:
            return "Censys API credentials not configured"
        
        if not query and not domain:
            return "Either query or domain must be provided"
        
        if domain and not query:
            if not self.check_target_allowed(domain):
                return f"Target {domain} is not allowed for scanning"
            query = domain
        
        try:
            from censys.search import CensysHosts, CensysCertificates
            
            results = {
                "query": query,
                "search_type": search_type,
                "timestamp": get_timestamp(),
                "results": []
            }
            
            if search_type == "hosts":
                h = CensysHosts(api_id, api_secret)
                for page in h.search(query, per_page=100, pages=5):
                    for host in page:
                        results["results"].append({
                            "ip": host.get("ip"),
                            "services": host.get("services", []),
                            "location": host.get("location"),
                            "autonomous_system": host.get("autonomous_system"),
                            "last_updated": host.get("last_updated_at")
                        })
            
            elif search_type == "certificates":
                c = CensysCertificates(api_id, api_secret)
                for page in c.search(query, per_page=100, pages=5):
                    for cert in page:
                        results["results"].append({
                            "fingerprint": cert.get("fingerprint_sha256"),
                            "names": cert.get("names", []),
                            "issuer": cert.get("parsed", {}).get("issuer_dn"),
                            "validity": cert.get("parsed", {}).get("validity"),
                            "subject": cert.get("parsed", {}).get("subject_dn")
                        })
            
            return self.format_result(results, f"Censys {search_type.title()} Search for '{query}'")
            
        except Exception as e:
            return f"Censys search failed: {str(e)}"
    
    async def github_reconnaissance(
        self, 
        domain: str,
        keywords: Optional[List[str]] = None,
        search_type: str = "all"
    ) -> str:
        """Search GitHub for sensitive information."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        api_token = self.config.get_api_key("github")
        if not api_token:
            return "GitHub API token not configured"
        
        if keywords is None:
            keywords = ["password", "api_key", "secret", "token", "config"]
        
        search_queries = []
        
        if search_type in ["repositories", "all"]:
            search_queries.extend([
                f'"{domain}" in:name',
                f'"{domain}" in:description',
                f'"{domain}" in:readme',
            ])
        
        if search_type in ["code", "all"]:
            for keyword in keywords:
                search_queries.extend([
                    f'"{domain}" "{keyword}"',
                    f'"{domain}" {keyword} extension:json',
                    f'"{domain}" {keyword} extension:yml',
                    f'"{domain}" {keyword} extension:yaml',
                    f'"{domain}" {keyword} extension:conf',
                    f'"{domain}" {keyword} extension:cfg',
                    f'"{domain}" {keyword} extension:env',
                ])
        
        results = {
            "domain": domain,
            "search_type": search_type,
            "timestamp": get_timestamp(),
            "total_queries": len(search_queries),
            "queries": search_queries,
            "note": "Execute these queries manually on GitHub or use GitHub API"
        }
        
        return self.format_result(results, f"GitHub Reconnaissance for {domain}")
    
    async def archive_org_search(
        self, 
        domain: str, 
        limit: int = 100,
        year: Optional[int] = None
    ) -> str:
        """Search Wayback Machine for historical data."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "json",
            "limit": limit
        }
        
        if year:
            params["from"] = str(year)
            params["to"] = str(year)
        
        try:
            async with aiohttp.ClientSession() as session:
                await self.rate_limit()
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        results = {
                            "domain": domain,
                            "timestamp": get_timestamp(),
                            "total_snapshots": len(data) - 1 if data else 0,  # -1 for header
                            "snapshots": [],
                            "unique_urls": set()
                        }
                        
                        if data and len(data) > 1:
                            headers = data[0]
                            for snapshot in data[1:]:
                                snapshot_data = dict(zip(headers, snapshot))
                                results["snapshots"].append({
                                    "timestamp": snapshot_data.get("timestamp"),
                                    "url": snapshot_data.get("original"),
                                    "status": snapshot_data.get("statuscode"),
                                    "mimetype": snapshot_data.get("mimetype"),
                                    "length": snapshot_data.get("length")
                                })
                                results["unique_urls"].add(snapshot_data.get("original"))
                        
                        results["unique_urls"] = sorted(list(results["unique_urls"]))
                        results["unique_url_count"] = len(results["unique_urls"])
                        
                        return self.format_result(results, f"Wayback Machine Search for {domain}")
                    else:
                        return f"Archive.org search failed with status {response.status}"
        
        except Exception as e:
            return f"Archive.org search failed: {str(e)}"
    
    async def technology_detection(self, url: str, deep_scan: bool = False) -> str:
        """Detect technologies used by target websites."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "technologies": {},
            "headers": {},
            "ssl_info": {},
            "meta_tags": {},
            "scripts": [],
            "stylesheets": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                await self.rate_limit()
                async with session.get(url, timeout=10) as response:
                    results["status_code"] = response.status
                    results["headers"] = dict(response.headers)
                    
                    content = await response.text()
                    
                    # Basic technology detection
                    results["technologies"] = self._detect_technologies(content, results["headers"])
                    
                    if deep_scan:
                        # Deep scan for more technologies
                        results["meta_tags"] = self._extract_meta_tags(content)
                        results["scripts"] = self._extract_scripts(content)
                        results["stylesheets"] = self._extract_stylesheets(content)
                        
                        # SSL/TLS information
                        if url.startswith("https://"):
                            results["ssl_info"] = await self._get_ssl_info(domain)
        
        except Exception as e:
            results["error"] = str(e)
        
        return self.format_result(results, f"Technology Detection for {url}")
    
    async def social_media_search(
        self, 
        domain: str,
        platforms: Optional[List[str]] = None
    ) -> str:
        """Search social media platforms for information."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        if platforms is None:
            platforms = ["linkedin", "twitter", "facebook", "instagram", "youtube"]
        
        # Extract company name from domain
        company_name = domain.split('.')[0].replace('-', ' ').replace('_', ' ').title()
        
        search_urls = {}
        
        for platform in platforms:
            if platform.lower() == "linkedin":
                search_urls["LinkedIn"] = [
                    f"https://www.linkedin.com/search/results/companies/?keywords={company_name}",
                    f"https://www.linkedin.com/search/results/people/?keywords={company_name}"
                ]
            elif platform.lower() == "twitter":
                search_urls["Twitter"] = [
                    f"https://twitter.com/search?q={company_name}",
                    f"https://twitter.com/search?q={domain}"
                ]
            elif platform.lower() == "facebook":
                search_urls["Facebook"] = [
                    f"https://www.facebook.com/search/top?q={company_name}"
                ]
            elif platform.lower() == "instagram":
                search_urls["Instagram"] = [
                    f"https://www.instagram.com/explore/tags/{company_name.replace(' ', '')}"
                ]
            elif platform.lower() == "youtube":
                search_urls["YouTube"] = [
                    f"https://www.youtube.com/results?search_query={company_name}"
                ]
        
        results = {
            "domain": domain,
            "company_name": company_name,
            "timestamp": get_timestamp(),
            "platforms": platforms,
            "search_urls": search_urls,
            "note": "Visit these URLs manually to gather social media intelligence"
        }
        
        return self.format_result(results, f"Social Media Search for {domain}")
    
    async def email_enumeration(
        self, 
        domain: str,
        source: str = "all"
    ) -> str:
        """Enumerate email addresses for a domain."""
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "domain": domain,
            "timestamp": get_timestamp(),
            "emails": [],
            "sources": {}
        }
        
        # Hunter.io API
        if source in ["hunter", "all"]:
            hunter_emails = await self._hunter_io_search(domain)
            results["sources"]["hunter_io"] = len(hunter_emails)
            results["emails"].extend(hunter_emails)
        
        # Common email patterns
        if source in ["pattern", "all"]:
            pattern_emails = self._generate_email_patterns(domain)
            results["sources"]["patterns"] = len(pattern_emails)
            results["emails"].extend(pattern_emails)
        
        # Remove duplicates
        results["emails"] = list(set(results["emails"]))
        results["total_found"] = len(results["emails"])
        
        return self.format_result(results, f"Email Enumeration for {domain}")
    
    # Helper methods
    
    async def _cert_transparency_search(self, domain: str, include_expired: bool = False) -> Set[str]:
        """Search certificate transparency logs."""
        subdomains = set()
        
        # crt.sh API
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with aiohttp.ClientSession() as session:
                await self.rate_limit()
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            if "name_value" in cert:
                                names = cert["name_value"].split("\n")
                                for name in names:
                                    name = name.strip()
                                    # Remove wildcard prefix
                                    if name.startswith('*.'):
                                        name = name[2:]
                                    
                                    # Validate it's a subdomain or the domain itself
                                    if name and (name.endswith(f".{domain}") or name == domain):
                                        subdomains.add(name.lower())
        except aiohttp.ClientError as e:
            self.logger.warning(f"CT log API request failed: {e}")
        except asyncio.TimeoutError:
            self.logger.warning(f"CT log search timed out for {domain}")
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON response from crt.sh for {domain}")
        except Exception as e:
            self.logger.error(f"Unexpected error in CT search: {e}")
        
        return subdomains
    
    async def _dns_passive_enum(self, domain: str) -> Set[str]:
        """Passive DNS enumeration with common subdomain checking."""
        subdomains = set()
        
        # Common subdomains to check
        common_subs = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging", "api", 
            "blog", "shop", "store", "support", "help", "docs", "cdn",
            "img", "images", "static", "assets", "m", "mobile", "app",
            "portal", "vpn", "remote", "secure", "cloud", "app1", "app2",
            "beta", "demo", "old", "new", "backup", "git", "svn"
        ]
        
        # Use asyncio.gather for parallel DNS resolution
        async def check_subdomain(sub: str) -> Optional[str]:
            """Check if a subdomain resolves."""
            full_domain = f"{sub}.{domain}"
            try:
                # Run DNS resolution in executor to avoid blocking
                await asyncio.get_event_loop().run_in_executor(
                    None, socket.gethostbyname, full_domain
                )
                return full_domain
            except socket.gaierror:
                # Subdomain doesn't resolve
                return None
            except Exception as e:
                self.logger.debug(f"Error checking {full_domain}: {e}")
                return None
        
        # Check all subdomains in parallel with rate limiting
        tasks = []
        for sub in common_subs:
            await self.rate_limit()  # Respect rate limits
            tasks.append(check_subdomain(sub))
        
        try:
            # Execute with timeout to prevent hanging
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=30.0  # 30 second total timeout
            )
            
            # Collect successful resolutions
            for result in results:
                if result and isinstance(result, str):
                    subdomains.add(result)
                    
        except asyncio.TimeoutError:
            self.logger.warning(f"DNS enumeration timed out for {domain}")
        except Exception as e:
            self.logger.error(f"Error in DNS passive enumeration: {e}")
        
        return subdomains
    
    async def _search_engine_subdomains(self, domain: str) -> Set[str]:
        """Extract subdomains from search engines."""
        # This would typically use search engine APIs or scraping
        # For now, return empty set as this requires careful implementation
        # to avoid being blocked
        return set()
    
    async def _api_subdomain_search(self, domain: str) -> Set[str]:
        """Search subdomains using third-party APIs."""
        subdomains = set()
        
        # SecurityTrails API
        api_key = self.config.get_api_key("securitytrails")
        if api_key:
            try:
                url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                headers = {"APIKEY": api_key}
                
                async with aiohttp.ClientSession() as session:
                    await self.rate_limit()
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            for sub in data.get("subdomains", []):
                                subdomains.add(f"{sub}.{domain}")
                        elif response.status == 401:
                            self.logger.error("SecurityTrails API key is invalid or expired")
                        elif response.status == 429:
                            self.logger.warning("SecurityTrails rate limit exceeded")
                        else:
                            self.logger.warning(f"SecurityTrails API error: {response.status}")
            except aiohttp.ClientError as e:
                self.logger.warning(f"SecurityTrails API request failed: {e}")
            except asyncio.TimeoutError:
                self.logger.warning(f"SecurityTrails API timed out for {domain}")
            except Exception as e:
                self.logger.error(f"Unexpected error in SecurityTrails search: {e}")
        
        # VirusTotal API
        vt_key = self.config.get_api_key("virustotal")
        if vt_key:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
                headers = {"x-apikey": vt_key}
                
                async with aiohttp.ClientSession() as session:
                    await self.rate_limit()
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            for item in data.get('data', []):
                                subdomain = item.get('id', '')
                                if subdomain and (subdomain.endswith(f".{domain}") or subdomain == domain):
                                    subdomains.add(subdomain.lower())
                        elif response.status == 401:
                            self.logger.error("VirusTotal API key is invalid or expired")
                        elif response.status == 429:
                            self.logger.warning("VirusTotal rate limit exceeded")
                        else:
                            self.logger.warning(f"VirusTotal API error: {response.status}")
            except aiohttp.ClientError as e:
                self.logger.warning(f"VirusTotal API request failed: {e}")
            except asyncio.TimeoutError:
                self.logger.warning(f"VirusTotal API timed out for {domain}")
            except Exception as e:
                self.logger.error(f"Unexpected error in VirusTotal search: {e}")
        
        # Shodan API (optional)
        shodan_key = self.config.get_api_key("shodan")
        if shodan_key:
            try:
                url = f"https://api.shodan.io/dns/domain/{domain}"
                params = {"key": shodan_key}
                
                async with aiohttp.ClientSession() as session:
                    await self.rate_limit()
                    async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            for subdomain in data.get('subdomains', []):
                                full_subdomain = f"{subdomain}.{domain}"
                                subdomains.add(full_subdomain.lower())
                        elif response.status == 401:
                            self.logger.error("Shodan API key is invalid or expired")
                        elif response.status == 429:
                            self.logger.warning("Shodan rate limit exceeded")
                        else:
                            self.logger.warning(f"Shodan API error: {response.status}")
            except aiohttp.ClientError as e:
                self.logger.warning(f"Shodan API request failed: {e}")
            except asyncio.TimeoutError:
                self.logger.warning(f"Shodan API timed out for {domain}")
            except Exception as e:
                self.logger.error(f"Unexpected error in Shodan search: {e}")
        
        return subdomains
    
    async def _brute_force_subdomains(self, domain: str, wordlist: Optional[str] = None) -> Set[str]:
        """Brute force subdomain enumeration."""
        subdomains = set()
        
        if not wordlist:
            wordlist = self.config.scanning.subdomain_wordlist
        
        try:
            with open(wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Use basic wordlist if file not found
            words = [
                "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
                "blog", "shop", "store", "support", "help", "docs", "cdn"
            ]
        
        # Limit wordlist size for performance
        words = words[:1000]
        
        async def check_subdomain(word):
            try:
                full_domain = f"{word}.{domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        # Process in batches
        batch_size = 50
        for i in range(0, len(words), batch_size):
            batch = words[i:i+batch_size]
            tasks = [check_subdomain(word) for word in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and isinstance(result, str):
                    subdomains.add(result)
        
        return subdomains
    
    async def _attempt_zone_transfer(self, domain: str) -> str:
        """Attempt DNS zone transfer."""
        try:
            # Get nameservers
            ns_records = dns.resolver.resolve(domain, 'NS')
            nameservers = [str(ns) for ns in ns_records]
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    return f"Zone transfer successful from {ns}"
                except:
                    continue
            
            return "Zone transfer not allowed"
        
        except Exception as e:
            return f"Zone transfer failed: {str(e)}"
    
    def _parse_whois_data(self, whois_text: str) -> Dict[str, Any]:
        """Parse WHOIS data from text."""
        data = {}
        
        # Extract common fields using regex
        patterns = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creation Date:\s*(.+)",
            "expiration_date": r"Registry Expiry Date:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)"
        }
        
        for field, pattern in patterns.items():
            matches = re.findall(pattern, whois_text, re.IGNORECASE)
            if matches:
                if field == "name_servers":
                    data[field] = matches
                else:
                    data[field] = matches[0].strip()
        
        return data
    
    async def _reverse_dns_single(self, ip: str, timeout: int) -> str:
        """Perform reverse DNS lookup for single IP."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ip
    
    def _detect_technologies(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Detect web technologies from content and headers."""
        technologies = {}
        
        # Server header
        if "server" in headers:
            technologies["web_server"] = headers["server"]
        
        # Framework detection
        frameworks = {
            "Laravel": r"laravel",
            "Django": r"django",
            "Flask": r"flask",
            "Express": r"express",
            "React": r"react",
            "Angular": r"angular",
            "Vue": r"vue\.js",
            "jQuery": r"jquery",
            "Bootstrap": r"bootstrap"
        }
        
        for framework, pattern in frameworks.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.setdefault("frameworks", []).append(framework)
        
        # CMS detection
        cms_patterns = {
            "WordPress": r"wp-content|wordpress",
            "Drupal": r"drupal",
            "Joomla": r"joomla",
            "Magento": r"magento"
        }
        
        for cms, pattern in cms_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies["cms"] = cms
                break
        
        return technologies
    
    def _extract_meta_tags(self, content: str) -> Dict[str, str]:
        """Extract meta tags from HTML content."""
        meta_tags = {}
        meta_pattern = r'<meta\s+([^>]+)>'
        
        for match in re.finditer(meta_pattern, content, re.IGNORECASE):
            meta_content = match.group(1)
            name_match = re.search(r'name=["\']([^"\']+)["\']', meta_content, re.IGNORECASE)
            content_match = re.search(r'content=["\']([^"\']+)["\']', meta_content, re.IGNORECASE)
            
            if name_match and content_match:
                meta_tags[name_match.group(1)] = content_match.group(1)
        
        return meta_tags
    
    def _extract_scripts(self, content: str) -> List[str]:
        """Extract script sources from HTML content."""
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        return re.findall(script_pattern, content, re.IGNORECASE)
    
    def _extract_stylesheets(self, content: str) -> List[str]:
        """Extract stylesheet links from HTML content."""
        css_pattern = r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']'
        return re.findall(css_pattern, content, re.IGNORECASE)
    
    async def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL/TLS certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "subject_alt_names": [x[1] for x in cert.get("subjectAltName", [])]
                    }
        except Exception as e:
            return {"error": str(e)}
    
    async def _hunter_io_search(self, domain: str) -> List[Dict[str, Any]]:
        """Search emails using Hunter.io API with detailed metadata."""
        api_key = self.config.get_api_key("hunter_io")
        if not api_key:
            return []
        
        try:
            url = f"https://api.hunter.io/v2/domain-search"
            params = {
                "domain": domain,
                "api_key": api_key,
                "limit": 100  # Max results per request
            }
            
            async with aiohttp.ClientSession() as session:
                await self.rate_limit()
                async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=20)) as response:
                    if response.status == 200:
                        data = await response.json()
                        emails = []
                        
                        # Extract detailed email information
                        email_data = data.get("data", {})
                        for email_info in email_data.get("emails", []):
                            email_entry = {
                                'email': email_info.get('value'),
                                'first_name': email_info.get('first_name'),
                                'last_name': email_info.get('last_name'),
                                'position': email_info.get('position'),
                                'type': email_info.get('type'),  # personal or generic
                                'confidence': email_info.get('confidence'),
                                'department': email_info.get('department'),
                                'seniority': email_info.get('seniority'),
                                'sources': [
                                    {
                                        'domain': src.get('domain'),
                                        'uri': src.get('uri'),
                                        'extracted_on': src.get('extracted_on'),
                                        'still_on_page': src.get('still_on_page')
                                    }
                                    for src in email_info.get('sources', [])[:3]  # Limit to first 3 sources
                                ]
                            }
                            emails.append(email_entry)
                        
                        # Extract email pattern if available
                        pattern = email_data.get('pattern')
                        if pattern:
                            emails.append({
                                'type': 'pattern',
                                'pattern': pattern,
                                'description': f"Email format pattern: {pattern}",
                                'confidence': 100
                            })
                        
                        return emails
                    
                    elif response.status == 401:
                        self.logger.error("Hunter.io API key is invalid or expired")
                        return []
                    
                    elif response.status == 429:
                        self.logger.warning("Hunter.io rate limit exceeded")
                        return []
                    
                    elif response.status == 400:
                        error_data = await response.json()
                        error_msg = error_data.get('errors', [{}])[0].get('details', 'Bad request')
                        self.logger.error(f"Hunter.io API error: {error_msg}")
                        return []
                    
                    else:
                        self.logger.error(f"Hunter.io API error: HTTP {response.status}")
                        return []
                        
        except aiohttp.ClientError as e:
            self.logger.warning(f"Hunter.io API request failed: {e}")
        except asyncio.TimeoutError:
            self.logger.warning(f"Hunter.io API timed out for {domain}")
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON response from Hunter.io for {domain}")
        except Exception as e:
            self.logger.error(f"Unexpected error in Hunter.io search: {e}")
        
        return []
    
    def _generate_email_patterns(self, domain: str) -> List[str]:
        """Generate common email patterns for a domain."""
        common_prefixes = [
            "admin", "administrator", "info", "contact", "support", "help",
            "sales", "marketing", "hr", "careers", "jobs", "no-reply",
            "noreply", "webmaster", "postmaster", "root", "mail"
        ]
        
        return [f"{prefix}@{domain}" for prefix in common_prefixes]
