"""
OSINT (Open Source Intelligence) gathering tools.
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin
import aiohttp
from mcp.types import Tool
from .base import BaseTools
from ..utils import get_timestamp


class OSINTTools(BaseTools):
    """OSINT and intelligence gathering tools."""
    
    def get_tools(self) -> List[Tool]:
        """Return list of OSINT tools."""
        return [
            Tool(
                name="person_investigation",
                description="Investigate person using multiple OSINT sources",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Person's name"},
                        "email": {"type": "string", "description": "Email address"},
                        "username": {"type": "string", "description": "Username/handle"},
                        "phone": {"type": "string", "description": "Phone number"},
                        "location": {"type": "string", "description": "Known location"}
                    }
                }
            ),
            Tool(
                name="company_investigation",
                description="Gather intelligence on a company",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "company_name": {"type": "string", "description": "Company name"},
                        "domain": {"type": "string", "description": "Company domain"},
                        "industry": {"type": "string", "description": "Industry sector"}
                    },
                    "required": ["company_name"]
                }
            ),
            Tool(
                name="dark_web_monitoring",
                description="Monitor dark web for mentions and leaks",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "keywords": {"type": "array", "items": {"type": "string"}, "description": "Keywords to monitor"},
                        "domains": {"type": "array", "items": {"type": "string"}, "description": "Domains to monitor"},
                        "deep_search": {"type": "boolean", "default": False}
                    },
                    "required": ["keywords"]
                }
            ),
            Tool(
                name="data_breach_check",
                description="Check for data breaches and exposed credentials",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "description": "Email to check"},
                        "domain": {"type": "string", "description": "Domain to check"},
                        "check_passwords": {"type": "boolean", "default": False}
                    }
                }
            ),
            Tool(
                name="social_media_investigation",
                description="Comprehensive social media investigation",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "username": {"type": "string", "description": "Username to investigate"},
                        "platforms": {"type": "array", "items": {"type": "string"}, "description": "Platforms to search"},
                        "deep_analysis": {"type": "boolean", "default": False}
                    },
                    "required": ["username"]
                }
            ),
            Tool(
                name="paste_site_monitoring",
                description="Monitor paste sites for sensitive information",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "keywords": {"type": "array", "items": {"type": "string"}, "description": "Keywords to monitor"},
                        "sites": {"type": "array", "items": {"type": "string"}, "description": "Paste sites to monitor"}
                    },
                    "required": ["keywords"]
                }
            ),
            Tool(
                name="code_repository_search",
                description="Search code repositories for sensitive information",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "organization": {"type": "string", "description": "Organization name"},
                        "keywords": {"type": "array", "items": {"type": "string"}, "description": "Keywords to search"},
                        "file_types": {"type": "array", "items": {"type": "string"}, "description": "File types to focus on"}
                    },
                    "required": ["organization"]
                }
            ),
            Tool(
                name="geolocation_investigation",
                description="Investigate geolocation and physical presence",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target to investigate"},
                        "coordinates": {"type": "string", "description": "GPS coordinates if known"},
                        "address": {"type": "string", "description": "Physical address"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="threat_intelligence_lookup",
                description="Lookup threat intelligence on IPs, domains, and hashes",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "indicator": {"type": "string", "description": "IoC to lookup (IP, domain, hash)"},
                        "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"], "description": "Type of indicator"},
                        "sources": {"type": "array", "items": {"type": "string"}, "description": "TI sources to query"}
                    },
                    "required": ["indicator"]
                }
            ),
            Tool(
                name="metadata_extraction",
                description="Extract metadata from files and documents",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "file_url": {"type": "string", "description": "URL to file"},
                        "file_path": {"type": "string", "description": "Local file path"},
                        "extract_images": {"type": "boolean", "default": True},
                        "extract_documents": {"type": "boolean", "default": True}
                    }
                }
            )
        ]
    
    async def person_investigation(
        self,
        name: Optional[str] = None,
        email: Optional[str] = None,
        username: Optional[str] = None,
        phone: Optional[str] = None,
        location: Optional[str] = None
    ) -> str:
        """Investigate a person using multiple OSINT sources."""
        results = {
            "target": {
                "name": name,
                "email": email,
                "username": username,
                "phone": phone,
                "location": location
            },
            "timestamp": get_timestamp(),
            "findings": {},
            "social_media": {},
            "data_breaches": {},
            "professional_info": {},
            "public_records": {}
        }
        
        # Search social media platforms
        if username:
            social_results = await self._search_social_media(username)
            results["social_media"] = social_results
        
        # Check data breaches
        if email:
            breach_results = await self._check_data_breaches(email)
            results["data_breaches"] = breach_results
        
        # Search professional networks
        if name:
            professional_results = await self._search_professional_networks(name)
            results["professional_info"] = professional_results
        
        # Search public records
        if name and location:
            public_records = await self._search_public_records(name, location)
            results["public_records"] = public_records
        
        # Phone number investigation
        if phone:
            phone_results = await self._investigate_phone_number(phone)
            results["phone_investigation"] = phone_results
        
        return self.format_result(results, f"Person Investigation")
    
    async def company_investigation(
        self,
        company_name: str,
        domain: Optional[str] = None,
        industry: Optional[str] = None
    ) -> str:
        """Gather intelligence on a company."""
        results = {
            "company": {
                "name": company_name,
                "domain": domain,
                "industry": industry
            },
            "timestamp": get_timestamp(),
            "corporate_info": {},
            "employees": [],
            "technology_stack": {},
            "financial_info": {},
            "news_mentions": {},
            "social_presence": {}
        }
        
        # Corporate information lookup
        corporate_info = await self._lookup_corporate_info(company_name)
        results["corporate_info"] = corporate_info
        
        # Employee enumeration
        if domain:
            employees = await self._enumerate_employees(company_name, domain)
            results["employees"] = employees
        
        # Technology stack analysis
        if domain:
            tech_stack = await self._analyze_technology_stack(domain)
            results["technology_stack"] = tech_stack
        
        # Financial information
        financial_info = await self._gather_financial_info(company_name)
        results["financial_info"] = financial_info
        
        # News and media mentions
        news_mentions = await self._search_news_mentions(company_name)
        results["news_mentions"] = news_mentions
        
        # Social media presence
        social_presence = await self._analyze_social_presence(company_name)
        results["social_presence"] = social_presence
        
        return self.format_result(results, f"Company Investigation: {company_name}")
    
    async def dark_web_monitoring(
        self,
        keywords: List[str],
        domains: Optional[List[str]] = None,
        deep_search: bool = False
    ) -> str:
        """Monitor dark web for mentions and leaks."""
        results = {
            "keywords": keywords,
            "domains": domains or [],
            "timestamp": get_timestamp(),
            "dark_web_mentions": [],
            "marketplace_listings": [],
            "forum_discussions": [],
            "data_leaks": [],
            "risk_assessment": {}
        }
        
        # Note: This is a simulated implementation
        # Real dark web monitoring would require specialized tools and infrastructure
        
        # Search known dark web databases (simulated)
        for keyword in keywords:
            mentions = await self._search_dark_web_databases(keyword)
            results["dark_web_mentions"].extend(mentions)
        
        # Check marketplace listings
        marketplace_results = await self._check_marketplace_listings(keywords)
        results["marketplace_listings"] = marketplace_results
        
        # Monitor forum discussions
        forum_results = await self._monitor_forum_discussions(keywords)
        results["forum_discussions"] = forum_results
        
        # Check for data leaks
        if domains:
            leak_results = await self._check_data_leaks(domains)
            results["data_leaks"] = leak_results
        
        # Risk assessment
        risk_assessment = self._assess_dark_web_risk(results)
        results["risk_assessment"] = risk_assessment
        
        return self.format_result(results, f"Dark Web Monitoring")
    
    async def data_breach_check(
        self,
        email: Optional[str] = None,
        domain: Optional[str] = None,
        check_passwords: bool = False
    ) -> str:
        """Check for data breaches and exposed credentials."""
        results = {
            "email": email,
            "domain": domain,
            "timestamp": get_timestamp(),
            "breaches_found": [],
            "exposed_passwords": [],
            "credential_stuffing_risk": {},
            "recommendations": []
        }
        
        # Check HaveIBeenPwned
        if email:
            hibp_results = await self._check_haveibeenpwned(email, check_passwords)
            results["breaches_found"].extend(hibp_results.get("breaches", []))
            if check_passwords:
                results["exposed_passwords"].extend(hibp_results.get("passwords", []))
        
        # Check DeHashed (if API key available)
        if email:
            dehashed_results = await self._check_dehashed(email)
            results["breaches_found"].extend(dehashed_results)
        
        # Check domain breaches
        if domain:
            domain_breaches = await self._check_domain_breaches(domain)
            results["breaches_found"].extend(domain_breaches)
        
        # Assess credential stuffing risk
        if results["breaches_found"]:
            risk_assessment = self._assess_credential_risk(results["breaches_found"])
            results["credential_stuffing_risk"] = risk_assessment
        
        # Generate recommendations
        recommendations = self._generate_breach_recommendations(results)
        results["recommendations"] = recommendations
        
        return self.format_result(results, f"Data Breach Check")
    
    async def social_media_investigation(
        self,
        username: str,
        platforms: Optional[List[str]] = None,
        deep_analysis: bool = False
    ) -> str:
        """Comprehensive social media investigation."""
        results = {
            "username": username,
            "platforms": platforms or [],
            "timestamp": get_timestamp(),
            "accounts_found": [],
            "profile_analysis": {},
            "connection_mapping": {},
            "content_analysis": {},
            "behavioral_patterns": {}
        }
        
        if not platforms:
            platforms = [
                "twitter", "linkedin", "facebook", "instagram", "github",
                "reddit", "youtube", "tiktok", "discord", "telegram"
            ]
        
        # Search for accounts across platforms
        for platform in platforms:
            account_info = await self._search_platform_account(username, platform)
            if account_info["found"]:
                results["accounts_found"].append(account_info)
        
        # Deep analysis if requested
        if deep_analysis:
            for account in results["accounts_found"]:
                profile_data = await self._analyze_profile_deep(account)
                results["profile_analysis"][account["platform"]] = profile_data
        
        # Map connections between accounts
        connection_map = self._map_account_connections(results["accounts_found"])
        results["connection_mapping"] = connection_map
        
        # Analyze content patterns
        content_analysis = await self._analyze_content_patterns(results["accounts_found"])
        results["content_analysis"] = content_analysis
        
        return self.format_result(results, f"Social Media Investigation: {username}")
    
    async def paste_site_monitoring(
        self,
        keywords: List[str],
        sites: Optional[List[str]] = None
    ) -> str:
        """Monitor paste sites for sensitive information."""
        results = {
            "keywords": keywords,
            "sites": sites or [],
            "timestamp": get_timestamp(),
            "pastes_found": [],
            "sensitive_data": [],
            "monitoring_summary": {}
        }
        
        if not sites:
            sites = ["pastebin", "ghostbin", "hastebin", "dpaste", "justpaste"]
        
        # Monitor each paste site
        for site in sites:
            for keyword in keywords:
                paste_results = await self._search_paste_site(site, keyword)
                results["pastes_found"].extend(paste_results)
        
        # Analyze found pastes for sensitive data
        for paste in results["pastes_found"]:
            sensitive_analysis = await self._analyze_paste_sensitivity(paste)
            if sensitive_analysis["is_sensitive"]:
                results["sensitive_data"].append(sensitive_analysis)
        
        # Generate monitoring summary
        summary = self._generate_paste_monitoring_summary(results)
        results["monitoring_summary"] = summary
        
        return self.format_result(results, f"Paste Site Monitoring")
    
    async def code_repository_search(
        self,
        organization: str,
        keywords: Optional[List[str]] = None,
        file_types: Optional[List[str]] = None
    ) -> str:
        """Search code repositories for sensitive information."""
        results = {
            "organization": organization,
            "keywords": keywords or [],
            "file_types": file_types or [],
            "timestamp": get_timestamp(),
            "repositories": [],
            "sensitive_files": [],
            "exposed_secrets": [],
            "code_analysis": {}
        }
        
        if not keywords:
            keywords = ["password", "api_key", "secret", "token", "private_key"]
        
        if not file_types:
            file_types = [".env", ".config", ".json", ".yml", ".yaml", ".xml"]
        
        # Search GitHub
        github_results = await self._search_github_repos(organization, keywords, file_types)
        results["repositories"].extend(github_results.get("repos", []))
        results["sensitive_files"].extend(github_results.get("files", []))
        
        # Search GitLab
        gitlab_results = await self._search_gitlab_repos(organization, keywords, file_types)
        results["repositories"].extend(gitlab_results.get("repos", []))
        results["sensitive_files"].extend(gitlab_results.get("files", []))
        
        # Analyze found secrets
        for file_info in results["sensitive_files"]:
            secret_analysis = await self._analyze_secret_exposure(file_info)
            if secret_analysis["secrets_found"]:
                results["exposed_secrets"].extend(secret_analysis["secrets"])
        
        # Generate code analysis summary
        analysis_summary = self._generate_code_analysis_summary(results)
        results["code_analysis"] = analysis_summary
        
        return self.format_result(results, f"Code Repository Search: {organization}")
    
    async def threat_intelligence_lookup(
        self,
        indicator: str,
        indicator_type: Optional[str] = None,
        sources: Optional[List[str]] = None
    ) -> str:
        """Lookup threat intelligence on IoCs."""
        results = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "timestamp": get_timestamp(),
            "reputation_scores": {},
            "threat_reports": [],
            "malware_families": [],
            "attribution": {},
            "recommendations": []
        }
        
        if not sources:
            sources = ["virustotal", "abuseipdb", "otx", "threatcrowd"]
        
        # Auto-detect indicator type if not provided
        if not indicator_type:
            indicator_type = self._detect_indicator_type(indicator)
            results["indicator_type"] = indicator_type
        
        # Query threat intelligence sources
        for source in sources:
            ti_result = await self._query_threat_intelligence(source, indicator, indicator_type)
            if ti_result:
                results["reputation_scores"][source] = ti_result.get("reputation", {})
                results["threat_reports"].extend(ti_result.get("reports", []))
                results["malware_families"].extend(ti_result.get("malware", []))
        
        # Generate threat assessment
        threat_assessment = self._assess_threat_level(results)
        results["threat_assessment"] = threat_assessment
        
        # Generate recommendations
        recommendations = self._generate_ti_recommendations(results)
        results["recommendations"] = recommendations
        
        return self.format_result(results, f"Threat Intelligence Lookup: {indicator}")
    
    # Helper methods
    
    async def _search_social_media(self, username: str) -> Dict[str, Any]:
        """Search social media platforms for username."""
        platforms = ["twitter", "linkedin", "facebook", "instagram", "github"]
        results = {}
        
        for platform in platforms:
            account_info = await self._search_platform_account(username, platform)
            results[platform] = account_info
        
        return results
    
    async def _search_platform_account(self, username: str, platform: str) -> Dict[str, Any]:
        """Search for account on specific platform."""
        # This would implement actual platform searching
        # For now, return simulated results
        return {
            "platform": platform,
            "username": username,
            "found": False,
            "url": f"https://{platform}.com/{username}",
            "profile_data": {}
        }
    
    async def _check_data_breaches(self, email: str) -> Dict[str, Any]:
        """Check email against breach databases."""
        return {"breaches": [], "total_breaches": 0}
    
    async def _search_professional_networks(self, name: str) -> Dict[str, Any]:
        """Search professional networks."""
        return {"linkedin": {}, "professional_info": {}}
    
    async def _search_public_records(self, name: str, location: str) -> Dict[str, Any]:
        """Search public records."""
        return {"records_found": [], "sources": []}
    
    async def _investigate_phone_number(self, phone: str) -> Dict[str, Any]:
        """Investigate phone number."""
        return {"carrier": "", "location": "", "type": ""}
    
    async def _lookup_corporate_info(self, company_name: str) -> Dict[str, Any]:
        """Lookup corporate information."""
        return {"registration": {}, "officers": [], "addresses": []}
    
    async def _enumerate_employees(self, company_name: str, domain: str) -> List[Dict[str, Any]]:
        """Enumerate company employees."""
        return []
    
    async def _analyze_technology_stack(self, domain: str) -> Dict[str, Any]:
        """Analyze company technology stack."""
        return {"technologies": [], "frameworks": [], "services": []}
    
    async def _gather_financial_info(self, company_name: str) -> Dict[str, Any]:
        """Gather financial information."""
        return {"revenue": "", "funding": [], "investors": []}
    
    async def _search_news_mentions(self, company_name: str) -> Dict[str, Any]:
        """Search news mentions."""
        return {"articles": [], "sentiment": "neutral"}
    
    async def _analyze_social_presence(self, company_name: str) -> Dict[str, Any]:
        """Analyze social media presence."""
        return {"platforms": [], "followers": {}, "engagement": {}}
    
    async def _search_dark_web_databases(self, keyword: str) -> List[Dict[str, Any]]:
        """Search dark web databases (simulated)."""
        return []
    
    async def _check_marketplace_listings(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """Check marketplace listings."""
        return []
    
    async def _monitor_forum_discussions(self, keywords: List[str]) -> List[Dict[str, Any]]:
        """Monitor forum discussions."""
        return []
    
    async def _check_data_leaks(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Check for data leaks."""
        return []
    
    def _assess_dark_web_risk(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess dark web risk."""
        return {"risk_level": "low", "factors": []}
    
    async def _check_haveibeenpwned(self, email: str, check_passwords: bool) -> Dict[str, Any]:
        """Check HaveIBeenPwned database."""
        # This would use the actual HIBP API
        return {"breaches": [], "passwords": []}
    
    async def _check_dehashed(self, email: str) -> List[Dict[str, Any]]:
        """Check DeHashed database."""
        return []
    
    async def _check_domain_breaches(self, domain: str) -> List[Dict[str, Any]]:
        """Check domain-specific breaches."""
        return []
    
    def _assess_credential_risk(self, breaches: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess credential stuffing risk."""
        return {"risk_level": "low", "exposed_count": len(breaches)}
    
    def _generate_breach_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate breach recommendations."""
        return ["Change passwords", "Enable 2FA", "Monitor accounts"]
    
    async def _analyze_profile_deep(self, account: Dict[str, Any]) -> Dict[str, Any]:
        """Deep analysis of social media profile."""
        return {"posts": [], "connections": [], "interests": []}
    
    def _map_account_connections(self, accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map connections between accounts."""
        return {"connections": [], "confidence": {}}
    
    async def _analyze_content_patterns(self, accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze content patterns."""
        return {"patterns": [], "topics": [], "timing": {}}
    
    async def _search_paste_site(self, site: str, keyword: str) -> List[Dict[str, Any]]:
        """Search specific paste site."""
        return []
    
    async def _analyze_paste_sensitivity(self, paste: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze paste for sensitive data."""
        return {"is_sensitive": False, "sensitivity_score": 0}
    
    def _generate_paste_monitoring_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate paste monitoring summary."""
        return {"total_pastes": 0, "sensitive_count": 0}
    
    async def _search_github_repos(self, org: str, keywords: List[str], file_types: List[str]) -> Dict[str, Any]:
        """Search GitHub repositories."""
        return {"repos": [], "files": []}
    
    async def _search_gitlab_repos(self, org: str, keywords: List[str], file_types: List[str]) -> Dict[str, Any]:
        """Search GitLab repositories."""
        return {"repos": [], "files": []}
    
    async def _analyze_secret_exposure(self, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file for secret exposure."""
        return {"secrets_found": False, "secrets": []}
    
    def _generate_code_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate code analysis summary."""
        return {"total_repos": 0, "sensitive_files": 0, "risk_level": "low"}
    
    def _detect_indicator_type(self, indicator: str) -> str:
        """Auto-detect indicator type."""
        if re.match(r'^[0-9a-fA-F]{32}$', indicator):
            return "hash"
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
            return "ip"
        elif "." in indicator:
            return "domain"
        else:
            return "unknown"
    
    async def _query_threat_intelligence(self, source: str, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence source."""
        # This would implement actual TI API calls
        return None
    
    def _assess_threat_level(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall threat level."""
        return {"level": "unknown", "confidence": 0}
    
    def _generate_ti_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate threat intelligence recommendations."""
        return ["Monitor indicator", "Block if malicious", "Investigate further"]
