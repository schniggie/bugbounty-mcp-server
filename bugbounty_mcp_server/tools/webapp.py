"""
Web application specific testing tools.
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin
import aiohttp
from mcp.types import Tool
from .base import BaseTools
from ..utils import get_timestamp


class WebApplicationTools(BaseTools):
    """Web application specific testing tools."""
    
    def get_tools(self) -> List[Tool]:
        """Return list of web application tools."""
        return [
            Tool(
                name="broken_access_control_test",
                description="Test for broken access control vulnerabilities",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "description": "Base application URL"},
                        "endpoints": {"type": "array", "items": {"type": "string"}, "description": "Endpoints to test"},
                        "user_roles": {"type": "array", "items": {"type": "object"}, "description": "User roles and credentials"}
                    },
                    "required": ["base_url"]
                }
            ),
            Tool(
                name="security_misconfiguration_scan",
                description="Scan for security misconfigurations",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "check_headers": {"type": "boolean", "default": True},
                        "check_files": {"type": "boolean", "default": True},
                        "check_directories": {"type": "boolean", "default": True}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="sensitive_data_exposure_test",
                description="Test for sensitive data exposure",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "file_extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions to check"},
                        "deep_scan": {"type": "boolean", "default": False}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="api_security_test",
                description="Comprehensive API security testing",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "api_url": {"type": "string", "description": "API base URL"},
                        "api_key": {"type": "string", "description": "API key for authentication"},
                        "test_methods": {"type": "array", "items": {"type": "string"}, "description": "HTTP methods to test"},
                        "rate_limit_test": {"type": "boolean", "default": True}
                    },
                    "required": ["api_url"]
                }
            ),
            Tool(
                name="file_upload_security_test",
                description="Test file upload security",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "upload_url": {"type": "string", "description": "File upload endpoint"},
                        "file_parameter": {"type": "string", "default": "file", "description": "File parameter name"},
                        "test_malicious": {"type": "boolean", "default": True}
                    },
                    "required": ["upload_url"]
                }
            ),
            Tool(
                name="input_validation_test",
                description="Test input validation and sanitization",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "form_fields": {"type": "array", "items": {"type": "string"}, "description": "Form fields to test"},
                        "validation_types": {"type": "array", "items": {"type": "string"}, "description": "Types of validation to test"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="cookie_security_analysis",
                description="Analyze cookie security settings",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL"},
                        "login_required": {"type": "boolean", "default": False},
                        "credentials": {"type": "object", "description": "Login credentials if required"}
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="websocket_security_test",
                description="Test WebSocket security",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "websocket_url": {"type": "string", "description": "WebSocket URL"},
                        "origin_tests": {"type": "boolean", "default": True},
                        "message_tests": {"type": "boolean", "default": True}
                    },
                    "required": ["websocket_url"]
                }
            ),
            Tool(
                name="graphql_security_test",
                description="Test GraphQL API security",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "graphql_url": {"type": "string", "description": "GraphQL endpoint URL"},
                        "introspection_test": {"type": "boolean", "default": True},
                        "depth_limit_test": {"type": "boolean", "default": True},
                        "rate_limit_test": {"type": "boolean", "default": True}
                    },
                    "required": ["graphql_url"]
                }
            ),
            Tool(
                name="error_handling_analysis",
                description="Analyze application error handling",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "base_url": {"type": "string", "description": "Base application URL"},
                        "error_pages": {"type": "array", "items": {"type": "string"}, "description": "Error page URLs to test"},
                        "trigger_errors": {"type": "boolean", "default": True}
                    },
                    "required": ["base_url"]
                }
            )
        ]
    
    async def broken_access_control_test(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
        user_roles: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """Test for broken access control."""
        parsed_url = urlparse(base_url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "base_url": base_url,
            "timestamp": get_timestamp(),
            "vulnerabilities": [],
            "access_tests": [],
            "tested_endpoints": []
        }
        
        # Default endpoints to test if none provided
        if not endpoints:
            endpoints = [
                "/admin", "/admin/", "/administrator", "/admin/dashboard",
                "/user/profile", "/api/admin", "/api/users", "/management",
                "/config", "/settings", "/dashboard", "/panel"
            ]
        
        results["tested_endpoints"] = endpoints
        
        # Default user roles if none provided
        if not user_roles:
            user_roles = [
                {"role": "anonymous", "headers": {}},
                {"role": "low_privilege", "headers": {"Authorization": "Bearer low_token"}},
                {"role": "admin", "headers": {"Authorization": "Bearer admin_token"}}
            ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                full_url = urljoin(base_url, endpoint)
                
                for role in user_roles:
                    try:
                        await self.rate_limit()
                        
                        headers = role.get("headers", {})
                        async with session.get(full_url, headers=headers, timeout=10) as response:
                            access_result = {
                                "endpoint": endpoint,
                                "role": role["role"],
                                "status_code": response.status,
                                "accessible": response.status in [200, 301, 302],
                                "response_size": len(await response.text())
                            }
                            results["access_tests"].append(access_result)
                            
                            # Check for potential access control bypass
                            if (role["role"] == "anonymous" and response.status == 200 and 
                                "admin" in endpoint.lower()):
                                results["vulnerabilities"].append({
                                    "type": "Broken Access Control",
                                    "endpoint": endpoint,
                                    "description": f"Admin endpoint accessible without authentication",
                                    "severity": "High"
                                })
                    
                    except Exception:
                        continue
        
        return self.format_result(results, f"Access Control Test Results for {base_url}")
    
    async def security_misconfiguration_scan(
        self,
        url: str,
        check_headers: bool = True,
        check_files: bool = True,
        check_directories: bool = True
    ) -> str:
        """Scan for security misconfigurations."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "misconfigurations": [],
            "header_issues": [],
            "exposed_files": [],
            "exposed_directories": []
        }
        
        async with aiohttp.ClientSession() as session:
            # Check security headers
            if check_headers:
                await self.rate_limit()
                async with session.get(url, timeout=10) as response:
                    headers = dict(response.headers)
                    header_issues = self._analyze_security_headers(headers)
                    results["header_issues"] = header_issues
            
            # Check for exposed files
            if check_files:
                exposed_files = await self._check_exposed_files(session, url)
                results["exposed_files"] = exposed_files
            
            # Check for exposed directories
            if check_directories:
                exposed_dirs = await self._check_exposed_directories(session, url)
                results["exposed_directories"] = exposed_dirs
        
        # Aggregate all issues as misconfigurations
        results["misconfigurations"] = (
            results["header_issues"] + 
            results["exposed_files"] + 
            results["exposed_directories"]
        )
        
        return self.format_result(results, f"Security Misconfiguration Scan for {url}")
    
    async def sensitive_data_exposure_test(
        self,
        url: str,
        file_extensions: Optional[List[str]] = None,
        deep_scan: bool = False
    ) -> str:
        """Test for sensitive data exposure."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "exposed_data": [],
            "sensitive_files": [],
            "data_patterns": []
        }
        
        # Default file extensions to check
        if not file_extensions:
            file_extensions = [
                ".txt", ".log", ".bak", ".old", ".config", ".conf",
                ".json", ".xml", ".yml", ".yaml", ".sql", ".db",
                ".env", ".key", ".pem", ".crt", ".p12", ".pfx"
            ]
        
        # Sensitive file patterns
        sensitive_files = [
            "backup.zip", "backup.tar.gz", "database.sql",
            "config.php", "wp-config.php", ".env",
            "settings.py", "application.properties",
            "web.config", "app.config", "credentials.json",
            "private.key", "id_rsa", "server.key"
        ]
        
        async with aiohttp.ClientSession() as session:
            # Check for sensitive files
            for filename in sensitive_files:
                try:
                    file_url = urljoin(url, filename)
                    await self.rate_limit()
                    
                    async with session.get(file_url, timeout=10) as response:
                        if response.status == 200:
                            content = await response.text()
                            sensitivity_score = self._analyze_content_sensitivity(content)
                            
                            if sensitivity_score > 0:
                                results["sensitive_files"].append({
                                    "file": filename,
                                    "url": file_url,
                                    "sensitivity_score": sensitivity_score,
                                    "size": len(content),
                                    "patterns_found": self._extract_sensitive_patterns(content)
                                })
                
                except Exception:
                    continue
            
            # If deep scan, check for additional patterns
            if deep_scan:
                await self._deep_sensitivity_scan(session, url, results)
        
        return self.format_result(results, f"Sensitive Data Exposure Test for {url}")
    
    async def api_security_test(
        self,
        api_url: str,
        api_key: Optional[str] = None,
        test_methods: Optional[List[str]] = None,
        rate_limit_test: bool = True
    ) -> str:
        """Comprehensive API security testing."""
        parsed_url = urlparse(api_url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "api_url": api_url,
            "timestamp": get_timestamp(),
            "vulnerabilities": [],
            "rate_limit_info": {},
            "method_tests": {},
            "authentication_tests": []
        }
        
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            headers["X-API-Key"] = api_key
        
        if not test_methods:
            test_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        
        async with aiohttp.ClientSession() as session:
            # Test HTTP methods
            for method in test_methods:
                try:
                    await self.rate_limit()
                    
                    async with session.request(method, api_url, headers=headers, timeout=10) as response:
                        results["method_tests"][method] = {
                            "status_code": response.status,
                            "allowed": response.status not in [405, 501],
                            "response_size": len(await response.text())
                        }
                        
                        # Check for dangerous methods
                        if method in ["DELETE", "PUT", "PATCH"] and response.status == 200:
                            results["vulnerabilities"].append({
                                "type": "Dangerous HTTP Method",
                                "method": method,
                                "description": f"{method} method is accessible",
                                "severity": "Medium"
                            })
                
                except Exception:
                    continue
            
            # Test rate limiting
            if rate_limit_test:
                rate_limit_result = await self._test_api_rate_limiting(session, api_url, headers)
                results["rate_limit_info"] = rate_limit_result
            
            # Test authentication bypass
            auth_tests = await self._test_api_authentication(session, api_url, headers)
            results["authentication_tests"] = auth_tests
        
        return self.format_result(results, f"API Security Test Results for {api_url}")
    
    async def file_upload_security_test(
        self,
        upload_url: str,
        file_parameter: str = "file",
        test_malicious: bool = True
    ) -> str:
        """Test file upload security."""
        parsed_url = urlparse(upload_url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "upload_url": upload_url,
            "timestamp": get_timestamp(),
            "vulnerabilities": [],
            "upload_tests": [],
            "file_type_tests": []
        }
        
        # Test files
        test_files = [
            {"name": "test.txt", "content": "This is a test file", "type": "text/plain"},
            {"name": "test.jpg", "content": b"\xFF\xD8\xFF\xE0\x00\x10JFIF", "type": "image/jpeg"},
            {"name": "test.pdf", "content": b"%PDF-1.4\n%test", "type": "application/pdf"}
        ]
        
        if test_malicious:
            malicious_files = [
                {"name": "test.php", "content": "<?php echo 'PHP executed'; ?>", "type": "application/x-php"},
                {"name": "test.jsp", "content": "<%@ page import=\"java.io.*\" %><% out.println(\"JSP executed\"); %>", "type": "application/x-jsp"},
                {"name": "test.asp", "content": "<%Response.Write(\"ASP executed\")%>", "type": "application/x-asp"},
                {"name": "shell.php", "content": "<?php system($_GET['cmd']); ?>", "type": "application/x-php"},
                {"name": "test.exe", "content": "MZ\x90\x00\x03\x00\x00\x00", "type": "application/x-executable"}
            ]
            test_files.extend(malicious_files)
        
        async with aiohttp.ClientSession() as session:
            for test_file in test_files:
                try:
                    await self.rate_limit()
                    
                    # Prepare multipart form data
                    data = aiohttp.FormData()
                    data.add_field(file_parameter, 
                                 test_file["content"], 
                                 filename=test_file["name"],
                                 content_type=test_file["type"])
                    
                    async with session.post(upload_url, data=data, timeout=10) as response:
                        upload_result = {
                            "filename": test_file["name"],
                            "status_code": response.status,
                            "uploaded": response.status in [200, 201, 302],
                            "response": await response.text()
                        }
                        results["upload_tests"].append(upload_result)
                        
                        # Check for vulnerabilities
                        if (response.status in [200, 201, 302] and 
                            test_file["name"].endswith(('.php', '.jsp', '.asp', '.exe'))):
                            results["vulnerabilities"].append({
                                "type": "Malicious File Upload",
                                "filename": test_file["name"],
                                "description": "Server accepted potentially malicious file",
                                "severity": "High"
                            })
                
                except Exception as e:
                    results["upload_tests"].append({
                        "filename": test_file["name"],
                        "error": str(e)
                    })
        
        return self.format_result(results, f"File Upload Security Test for {upload_url}")
    
    async def cookie_security_analysis(
        self,
        url: str,
        login_required: bool = False,
        credentials: Optional[Dict[str, str]] = None
    ) -> str:
        """Analyze cookie security settings."""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not self.check_target_allowed(domain):
            return f"Target {domain} is not allowed for scanning"
        
        results = {
            "url": url,
            "timestamp": get_timestamp(),
            "cookies_analyzed": [],
            "security_issues": [],
            "recommendations": []
        }
        
        async with aiohttp.ClientSession() as session:
            # Login if required
            if login_required and credentials:
                await self._perform_login(session, url, credentials)
            
            await self.rate_limit()
            async with session.get(url, timeout=10) as response:
                # Analyze cookies
                for cookie in response.cookies:
                    cookie_analysis = {
                        "name": cookie.key,
                        "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
                        "domain": cookie.get("domain"),
                        "path": cookie.get("path"),
                        "secure": cookie.get("secure", False),
                        "httponly": cookie.get("httponly", False),
                        "samesite": cookie.get("samesite"),
                        "expires": cookie.get("expires")
                    }
                    results["cookies_analyzed"].append(cookie_analysis)
                    
                    # Check for security issues
                    issues = []
                    
                    if not cookie.get("secure") and url.startswith("https://"):
                        issues.append("Missing Secure flag")
                    
                    if not cookie.get("httponly"):
                        issues.append("Missing HttpOnly flag")
                    
                    if not cookie.get("samesite"):
                        issues.append("Missing SameSite attribute")
                    
                    if "session" in cookie.key.lower() or "auth" in cookie.key.lower():
                        if not cookie.get("secure") or not cookie.get("httponly"):
                            issues.append("Insecure session cookie")
                    
                    if issues:
                        results["security_issues"].append({
                            "cookie": cookie.key,
                            "issues": issues
                        })
        
        return self.format_result(results, f"Cookie Security Analysis for {url}")
    
    # Helper methods
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze security headers for misconfigurations."""
        issues = []
        
        # Required security headers
        required_headers = {
            "strict-transport-security": "Missing HSTS header",
            "content-security-policy": "Missing CSP header",
            "x-frame-options": "Missing X-Frame-Options header",
            "x-content-type-options": "Missing X-Content-Type-Options header"
        }
        
        for header, description in required_headers.items():
            if header not in [h.lower() for h in headers.keys()]:
                issues.append({
                    "type": "Missing Security Header",
                    "header": header,
                    "description": description,
                    "severity": "Medium"
                })
        
        # Check for information disclosure headers
        disclosure_headers = ["server", "x-powered-by", "x-aspnet-version"]
        for header in disclosure_headers:
            if header in [h.lower() for h in headers.keys()]:
                issues.append({
                    "type": "Information Disclosure",
                    "header": header,
                    "value": headers.get(header),
                    "description": "Server information disclosed",
                    "severity": "Low"
                })
        
        return issues
    
    async def _check_exposed_files(self, session: aiohttp.ClientSession, base_url: str) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files."""
        exposed_files = []
        
        sensitive_files = [
            ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
            "crossdomain.xml", "clientaccesspolicy.xml",
            "backup.zip", "backup.tar.gz", "dump.sql",
            ".git/config", ".svn/entries", ".env"
        ]
        
        for filename in sensitive_files:
            try:
                file_url = urljoin(base_url, filename)
                await self.rate_limit()
                
                async with session.get(file_url, timeout=10) as response:
                    if response.status == 200:
                        exposed_files.append({
                            "type": "Exposed File",
                            "file": filename,
                            "url": file_url,
                            "size": len(await response.text()),
                            "severity": "Medium"
                        })
            
            except Exception:
                continue
        
        return exposed_files
    
    async def _check_exposed_directories(self, session: aiohttp.ClientSession, base_url: str) -> List[Dict[str, Any]]:
        """Check for exposed directories."""
        exposed_dirs = []
        
        sensitive_dirs = [
            "/admin/", "/backup/", "/config/", "/test/",
            "/dev/", "/staging/", "/.git/", "/.svn/",
            "/uploads/", "/files/", "/documents/"
        ]
        
        for directory in sensitive_dirs:
            try:
                dir_url = urljoin(base_url, directory)
                await self.rate_limit()
                
                async with session.get(dir_url, timeout=10) as response:
                    if response.status == 200:
                        content = await response.text()
                        if "index of" in content.lower() or "directory listing" in content.lower():
                            exposed_dirs.append({
                                "type": "Directory Listing",
                                "directory": directory,
                                "url": dir_url,
                                "severity": "Medium"
                            })
            
            except Exception:
                continue
        
        return exposed_dirs
    
    def _analyze_content_sensitivity(self, content: str) -> int:
        """Analyze content for sensitive information."""
        sensitivity_score = 0
        
        # Patterns indicating sensitive content
        sensitive_patterns = [
            (r'password\s*=\s*["\']?([^"\'\\s]+)', 3),
            (r'api[_-]?key\s*=\s*["\']?([^"\'\\s]+)', 3),
            (r'secret\s*=\s*["\']?([^"\'\\s]+)', 3),
            (r'token\s*=\s*["\']?([^"\'\\s]+)', 2),
            (r'database\s*=\s*["\']?([^"\'\\s]+)', 2),
            (r'username\s*=\s*["\']?([^"\'\\s]+)', 1),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 1)
        ]
        
        for pattern, score in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                sensitivity_score += score
        
        return sensitivity_score
    
    def _extract_sensitive_patterns(self, content: str) -> List[str]:
        """Extract sensitive patterns from content."""
        patterns = []
        
        # Email addresses
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        patterns.extend([f"Email: {email}" for email in emails[:5]])
        
        # API keys (simplified pattern)
        api_keys = re.findall(r'(?:api[_-]?key|token|secret)\s*[:=]\s*["\']?([A-Za-z0-9_-]{16,})', content, re.IGNORECASE)
        patterns.extend([f"API Key: {key[:10]}..." for key in api_keys[:3]])
        
        return patterns
    
    async def _deep_sensitivity_scan(self, session: aiohttp.ClientSession, url: str, results: Dict[str, Any]) -> None:
        """Perform deep sensitivity scanning."""
        # This would implement more comprehensive scanning
        # For now, placeholder implementation
        pass
    
    async def _test_api_rate_limiting(self, session: aiohttp.ClientSession, api_url: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Test API rate limiting."""
        rate_limit_info = {
            "rate_limited": False,
            "requests_sent": 0,
            "rate_limit_headers": {}
        }
        
        # Send multiple requests quickly
        for i in range(20):
            try:
                async with session.get(api_url, headers=headers, timeout=5) as response:
                    rate_limit_info["requests_sent"] += 1
                    
                    if response.status == 429:  # Too Many Requests
                        rate_limit_info["rate_limited"] = True
                        rate_limit_info["rate_limit_headers"] = dict(response.headers)
                        break
                    
                    # Check for rate limit headers
                    rl_headers = {}
                    for header in ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"]:
                        if header in response.headers:
                            rl_headers[header] = response.headers[header]
                    
                    if rl_headers:
                        rate_limit_info["rate_limit_headers"] = rl_headers
            
            except Exception:
                break
        
        return rate_limit_info
    
    async def _test_api_authentication(self, session: aiohttp.ClientSession, api_url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test API authentication."""
        auth_tests = []
        
        # Test without authentication
        try:
            async with session.get(api_url, timeout=10) as response:
                auth_tests.append({
                    "test": "No Authentication",
                    "status_code": response.status,
                    "accessible": response.status not in [401, 403]
                })
        except Exception:
            pass
        
        # Test with invalid token
        invalid_headers = headers.copy()
        invalid_headers["Authorization"] = "Bearer invalid_token"
        
        try:
            async with session.get(api_url, headers=invalid_headers, timeout=10) as response:
                auth_tests.append({
                    "test": "Invalid Token",
                    "status_code": response.status,
                    "accessible": response.status not in [401, 403]
                })
        except Exception:
            pass
        
        return auth_tests
    
    async def _perform_login(self, session: aiohttp.ClientSession, url: str, credentials: Dict[str, str]) -> None:
        """Perform login to get session cookies."""
        # This would implement login functionality
        # For now, placeholder implementation
        pass
