# Issue #3: [HIGH] Implement Web Application Security Testing Functions

## Priority: HIGH 🔴
**File**: `bugbounty_mcp_server/tools/webapp.py`

## Problem
Three critical web application security testing functions have placeholder implementations. These are essential for comprehensive web app penetration testing.

## Affected Functions
1. `_deep_sensitivity_scan()` - Line 697
2. `_test_api_authentication()` - Line 745
3. `_perform_login()` - Line 767

---

## Function 1: _deep_sensitivity_scan()

### Purpose
Perform comprehensive sensitive data and information disclosure scanning on web applications.

### Current State
```python
async def _deep_sensitivity_scan(self, url: str, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
    """Perform deep sensitivity scanning."""
    # This would implement more comprehensive scanning
    # For now, placeholder implementation
    pass
```

### What to Implement

#### 1. Sensitive File Detection
Check for exposed configuration and backup files:
```python
sensitive_files = [
    '.env', '.env.local', '.env.production',
    '.git/config', '.git/HEAD',
    'config.php', 'config.yml', 'settings.py',
    'wp-config.php', 'database.yml',
    '.aws/credentials', '.ssh/id_rsa',
    'id_rsa', 'id_dsa',
    'backup.sql', 'dump.sql', 'database.sql',
    'backup.zip', 'backup.tar.gz',
    '.htaccess', '.htpasswd',
    'web.config', 'composer.json',
    'package.json', 'package-lock.json'
]

findings = []
for file in sensitive_files:
    file_url = urljoin(url, file)
    try:
        async with session.get(file_url, timeout=5) as response:
            if response.status == 200:
                findings.append({
                    'type': 'sensitive_file',
                    'severity': 'high',
                    'url': file_url,
                    'file': file,
                    'status': response.status,
                    'size': len(await response.read())
                })
    except:
        pass
```

#### 2. Sensitive Data Pattern Detection
Scan response bodies for leaked secrets:
```python
import re

patterns = {
    'aws_key': (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    'aws_secret': (r'[0-9a-zA-Z/+]{40}', 'AWS Secret Key'),
    'jwt': (r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 'JWT Token'),
    'private_key': (r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'Private Key'),
    'api_key': (r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'API Key'),
    'bearer_token': (r'Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', 'Bearer Token'),
    'db_connection': (r'(mysql|postgresql|mongodb)://[^\\s]+', 'Database Connection String'),
    'email': (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email Address'),
    'phone': (r'\+?[1-9]\d{1,14}', 'Phone Number'),
    'credit_card': (r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', 'Credit Card'),
    'ssn': (r'\b\d{3}-\d{2}-\d{4}\b', 'Social Security Number'),
}

# Fetch page content
async with session.get(url) as response:
    content = await response.text()
    
    for pattern_name, (regex, description) in patterns.items():
        matches = re.findall(regex, content)
        if matches:
            findings.append({
                'type': 'sensitive_data',
                'severity': 'critical' if pattern_name in ['aws_secret', 'private_key'] else 'high',
                'pattern': pattern_name,
                'description': description,
                'url': url,
                'matches': len(matches),
                'sample': matches[0][:50] + '...' if len(matches[0]) > 50 else matches[0]
            })
```

#### 3. Information Disclosure in Headers
```python
# Check response headers
async with session.get(url) as response:
    headers = response.headers
    
    # Server version disclosure
    if 'Server' in headers:
        findings.append({
            'type': 'info_disclosure',
            'severity': 'low',
            'category': 'server_version',
            'header': 'Server',
            'value': headers['Server']
        })
    
    # Framework disclosure
    framework_headers = {
        'X-Powered-By': 'Framework',
        'X-AspNet-Version': 'ASP.NET Version',
        'X-AspNetMvc-Version': 'ASP.NET MVC Version',
        'X-Generator': 'Generator',
    }
    
    for header, desc in framework_headers.items():
        if header in headers:
            findings.append({
                'type': 'info_disclosure',
                'severity': 'low',
                'category': 'framework_disclosure',
                'header': header,
                'value': headers[header],
                'description': f'{desc} disclosed'
            })
```

#### 4. JavaScript File Analysis
```python
# Find and analyze JavaScript files
js_urls = []
soup = BeautifulSoup(content, 'lxml')
for script in soup.find_all('script', src=True):
    js_url = urljoin(url, script['src'])
    js_urls.append(js_url)

for js_url in js_urls:
    try:
        async with session.get(js_url, timeout=10) as response:
            js_content = await response.text()
            
            # Check for hardcoded credentials
            if re.search(r'password\s*[:=]\s*["\'][^"\']{3,}["\']', js_content, re.I):
                findings.append({
                    'type': 'hardcoded_credential',
                    'severity': 'critical',
                    'url': js_url,
                    'description': 'Potential hardcoded password in JavaScript'
                })
            
            # Check for API endpoints
            api_patterns = [
                r'https?://[^"\'\s]+/api/[^"\'\s]+',
                r'/api/v\d+/[^"\'\s]+',
            ]
            for pattern in api_patterns:
                matches = re.findall(pattern, js_content)
                if matches:
                    findings.append({
                        'type': 'api_endpoint_disclosure',
                        'severity': 'info',
                        'url': js_url,
                        'endpoints': list(set(matches))
                    })
    except:
        pass

return findings
```

### Acceptance Criteria
- [ ] Detects common sensitive files
- [ ] Identifies exposed secrets (AWS keys, JWT, etc.)
- [ ] Finds information disclosure in headers
- [ ] Analyzes JavaScript for secrets and endpoints
- [ ] Returns structured findings with severity levels
- [ ] Handles large responses gracefully

---

## Function 2: _test_api_authentication()

### Purpose
Test API authentication mechanisms for vulnerabilities and bypasses.

### What to Implement

```python
async def _test_api_authentication(
    self, 
    api_url: str, 
    session: aiohttp.ClientSession
) -> List[Dict[str, Any]]:
    """Test API authentication."""
    auth_tests = []
    
    # Test 1: No authentication
    try:
        async with session.get(api_url, timeout=10) as response:
            auth_tests.append({
                'test': 'no_auth',
                'status': response.status,
                'success': response.status != 401,
                'vulnerability': response.status == 200,
                'description': 'API accessible without authentication' if response.status == 200 else 'Authentication required'
            })
    except:
        pass
    
    # Test 2: Empty Authorization header
    headers = {'Authorization': ''}
    async with session.get(api_url, headers=headers) as response:
        auth_tests.append({
            'test': 'empty_auth',
            'status': response.status,
            'vulnerability': response.status == 200,
            'description': 'Empty auth header accepted'
        })
    
    # Test 3: Invalid Bearer token
    headers = {'Authorization': 'Bearer invalid_token_12345'}
    async with session.get(api_url, headers=headers) as response:
        auth_tests.append({
            'test': 'invalid_bearer',
            'status': response.status,
            'vulnerability': response.status == 200,
        })
    
    # Test 4: JWT "alg: none" attack
    headers = {'Authorization': 'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'}
    async with session.get(api_url, headers=headers) as response:
        auth_tests.append({
            'test': 'jwt_none_alg',
            'status': response.status,
            'vulnerability': response.status == 200,
            'severity': 'critical' if response.status == 200 else 'info'
        })
    
    # Test 5: SQL injection in auth
    sql_payloads = ["' OR '1'='1", "admin'--", "' OR 1=1--"]
    for payload in sql_payloads:
        headers = {'Authorization': f'Bearer {payload}'}
        async with session.get(api_url, headers=headers) as response:
            if response.status == 200:
                auth_tests.append({
                    'test': 'sql_injection_auth',
                    'payload': payload,
                    'status': response.status,
                    'vulnerability': True,
                    'severity': 'critical'
                })
    
    return auth_tests
```

---

## Function 3: _perform_login()

### Purpose
Automatically detect and interact with login forms to obtain authenticated sessions.

### What to Implement

```python
async def _perform_login(
    self,
    url: str,
    username: str,
    password: str,
    session: aiohttp.ClientSession
) -> Dict[str, Any]:
    """Perform login to get session cookies."""
    
    result = {
        'success': False,
        'method': None,
        'cookies': {},
        'tokens': {},
        'error': None
    }
    
    try:
        # Step 1: Fetch login page
        async with session.get(url) as response:
            html = await response.text()
            soup = BeautifulSoup(html, 'lxml')
        
        # Step 2: Find login form
        login_form = None
        for form in soup.find_all('form'):
            form_text = str(form).lower()
            if any(keyword in form_text for keyword in ['login', 'signin', 'auth']):
                login_form = form
                break
        
        if not login_form:
            result['error'] = 'No login form found'
            return result
        
        # Step 3: Parse form details
        form_action = login_form.get('action', '')
        form_method = login_form.get('method', 'post').lower()
        form_url = urljoin(url, form_action)
        
        # Step 4: Extract form fields
        form_data = {}
        for input_field in login_form.find_all('input'):
            field_name = input_field.get('name')
            field_type = input_field.get('type', 'text').lower()
            field_value = input_field.get('value', '')
            
            if not field_name:
                continue
            
            # Identify username field
            if field_type in ['text', 'email'] or any(kw in field_name.lower() for kw in ['user', 'email', 'login']):
                form_data[field_name] = username
            
            # Identify password field
            elif field_type == 'password':
                form_data[field_name] = password
            
            # CSRF token
            elif 'csrf' in field_name.lower() or 'token' in field_name.lower():
                form_data[field_name] = field_value
            
            # Hidden fields
            elif field_type == 'hidden':
                form_data[field_name] = field_value
        
        # Step 5: Submit login form
        if form_method == 'post':
            async with session.post(form_url, data=form_data, allow_redirects=True) as response:
                result['method'] = 'POST'
                result['status'] = response.status
                
                # Check for success indicators
                response_text = await response.text()
                
                success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'account']
                failure_indicators = ['invalid', 'incorrect', 'failed', 'error', 'denied']
                
                has_success = any(ind in response_text.lower() for ind in success_indicators)
                has_failure = any(ind in response_text.lower() for ind in failure_indicators)
                
                result['success'] = has_success and not has_failure
                
                # Extract cookies
                if response.cookies:
                    result['cookies'] = {k: v.value for k, v in response.cookies.items()}
                
                # Extract tokens from response
                token_patterns = {
                    'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                    'bearer': r'Bearer\s+([a-zA-Z0-9\-_.]+)',
                    'csrf': r'csrf[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)',
                }
                
                for token_type, pattern in token_patterns.items():
                    matches = re.findall(pattern, response_text)
                    if matches:
                        result['tokens'][token_type] = matches[0]
        
        return result
        
    except Exception as e:
        result['error'] = str(e)
        return result
```

---

## Dependencies
- `beautifulsoup4` ✅
- `lxml` ✅
- `aiohttp` ✅
- `pyjwt` ✅ (for JWT analysis)

## Testing

```python
@pytest.mark.asyncio
async def test_deep_sensitivity_scan():
    webapp = WebApplicationTools(config)
    async with aiohttp.ClientSession() as session:
        findings = await webapp._deep_sensitivity_scan("https://example.com", session)
        assert isinstance(findings, list)

@pytest.mark.asyncio
async def test_api_authentication():
    webapp = WebApplicationTools(config)
    async with aiohttp.ClientSession() as session:
        results = await webapp._test_api_authentication("https://api.example.com/v1/users", session)
        assert len(results) > 0
        assert all('test' in r for r in results)
