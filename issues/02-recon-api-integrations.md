# Issue #2: [HIGH] Implement Reconnaissance API Integrations

## Priority: HIGH 🔴
**File**: `bugbounty_mcp_server/tools/recon.py`

## Problem
The reconnaissance module has 4 critical functions with incomplete implementations that end with `pass` statements. These functions are essential for passive and active subdomain discovery and email harvesting.

## Affected Functions

### 1. `_cert_transparency_search()` - Line 843
### 2. `_dns_passive_enum()` - Line 864
### 3. `_api_subdomain_search()` - Line 894
### 4. `_hunter_io_search()` - Line 1097

---

## Function 1: _cert_transparency_search()

### Current State
```python
async def _cert_transparency_search(self, domain: str) -> Set[str]:
    """Search certificate transparency logs."""
    subdomains = set()
    
    # crt.sh API
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as response:
                # ... some code ...
                pass  # ⚠️ Incomplete!
```

### What to Implement
1. **Complete crt.sh integration**:
   ```python
   if response.status == 200:
       data = await response.json()
       for entry in data:
           name_value = entry.get('name_value', '')
           # Parse certificate Subject Alternative Names
           for name in name_value.split('\n'):
               name = name.strip()
               if name and domain in name:
                   # Remove wildcard prefix
                   subdomain = name.replace('*.', '')
                   subdomains.add(subdomain)
   ```

2. **Add alternative CT log sources**:
   - Censys Certificate Search
   - Google CT Search  
   - Facebook CT Monitor

3. **Handle edge cases**:
   - Wildcard certificates (*.example.com)
   - Multiple SANs in one certificate
   - Invalid/expired certificates
   - Rate limiting from CT logs

### API Details
```python
# crt.sh
url = f"https://crt.sh/?q=%.{domain}&output=json"

# Response format:
# [
#   {
#     "name_value": "example.com\n*.example.com\napi.example.com",
#     "min_cert_id": 123456,
#     "min_entry_timestamp": "2024-01-01T00:00:00"
#   }
# ]
```

---

## Function 2: _dns_passive_enum()

### Current State
```python
async def _dns_passive_enum(self, domain: str) -> Set[str]:
    """Passive DNS enumeration."""
    subdomains = set()
    
    # Common subdomains to check
    common_subs = [
        "www", "mail", "ftp", "admin", "test", "dev", "staging",
        "api", "portal", "vpn", ...
    ]
    pass  # ⚠️ Not implemented!
```

### What to Implement
1. **DNS Resolution Loop**:
   ```python
   import asyncio
   from dns import resolver
   
   # Create async tasks for all subdomains
   tasks = []
   for sub in common_subs:
       subdomain = f"{sub}.{domain}"
       tasks.append(self._check_dns(subdomain))
   
   # Execute in parallel with rate limiting
   results = await asyncio.gather(*tasks, return_exceptions=True)
   
   # Collect successful resolutions
   for subdomain, success in results:
       if success:
           subdomains.add(subdomain)
   ```

2. **Support Custom Wordlists**:
   ```python
   # Load wordlist from config
   wordlist_path = self.config.scanning.subdomain_wordlist
   if os.path.exists(wordlist_path):
       with open(wordlist_path, 'r') as f:
           custom_subs = [line.strip() for line in f]
           common_subs.extend(custom_subs)
   ```

3. **Implement DNS Helper**:
   ```python
   async def _check_dns(self, subdomain: str) -> Tuple[str, bool]:
       """Check if subdomain resolves."""
       try:
           await self.rate_limit()  # Respect rate limits
           answers = await resolve_domain(subdomain)
           return (subdomain, len(answers) > 0)
       except:
           return (subdomain, False)
   ```

### Testing
- Test with known subdomains
- Test with non-existent subdomains
- Test rate limiting (shouldn't overwhelm DNS servers)
- Test with custom wordlists

---

## Function 3: _api_subdomain_search()

### Current State
```python
async def _api_subdomain_search(self, domain: str) -> Set[str]:
    """Search subdomains using third-party APIs."""
    subdomains = set()
    
    # SecurityTrails API
    api_key = self.config.get_api_key("securitytrails")
    if api_key:
        pass  # ⚠️ Not implemented!
```

### What to Implement

#### SecurityTrails Integration
```python
if api_key:
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, timeout=10) as response:
            if response.status == 200:
                data = await response.json()
                for subdomain in data.get('subdomains', []):
                    full_subdomain = f"{subdomain}.{domain}"
                    subdomains.add(full_subdomain)
```

#### VirusTotal Integration
```python
vt_key = self.config.get_api_key("virustotal")
if vt_key:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": vt_key}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id', '')
                    if subdomain:
                        subdomains.add(subdomain)
```

#### Shodan Integration (Optional)
```python
shodan_key = self.config.get_api_key("shodan")
if shodan_key:
    url = f"https://api.shodan.io/dns/domain/{domain}"
    params = {"key": shodan_key}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                for subdomain in data.get('subdomains', []):
                    full_subdomain = f"{subdomain}.{domain}"
                    subdomains.add(full_subdomain)
```

### Error Handling
```python
try:
    # API call
    pass
except aiohttp.ClientError as e:
    self.logger.warning(f"API request failed: {e}")
except json.JSONDecodeError:
    self.logger.error(f"Invalid JSON response from API")
except Exception as e:
    self.logger.error(f"Unexpected error: {e}")
```

### API Rate Limits
- **SecurityTrails**: 50 requests/month (free tier)
- **VirusTotal**: 4 requests/minute (free tier)
- **Shodan**: 1 request/second

Implement rate limiting with:
```python
await self.rate_limit()
```

---

## Function 4: _hunter_io_search()

### Current State
```python
async def _hunter_io_search(self, domain: str) -> List[Dict[str, Any]]:
    """Search emails using Hunter.io API."""
    api_key = self.config.get_api_key("hunter_io")
    if not api_key:
        return []
    
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        pass  # ⚠️ Not implemented!
```

### What to Implement

#### Complete API Request
```python
async with aiohttp.ClientSession() as session:
    async with session.get(url, timeout=15) as response:
        if response.status == 200:
            data = await response.json()
            
            emails = []
            email_data = data.get('data', {})
            
            # Extract email addresses
            for email_info in email_data.get('emails', []):
                email_entry = {
                    'email': email_info.get('value'),
                    'first_name': email_info.get('first_name'),
                    'last_name': email_info.get('last_name'),
                    'position': email_info.get('position'),
                    'type': email_info.get('type'),  # personal or generic
                    'confidence': email_info.get('confidence'),
                    'sources': email_info.get('sources', [])
                }
                emails.append(email_entry)
            
            # Extract email pattern
            pattern = email_data.get('pattern')
            if pattern:
                emails.append({
                    'type': 'pattern',
                    'pattern': pattern,
                    'description': f"Email format: {pattern}"
                })
            
            return emails
        
        elif response.status == 401:
            self.logger.error("Hunter.io API key is invalid or expired")
            return []
        
        elif response.status == 429:
            self.logger.warning("Hunter.io rate limit exceeded")
            return []
        
        else:
            self.logger.error(f"Hunter.io API error: {response.status}")
            return []
```

#### Handle Pagination
```python
# Hunter.io returns paginated results
offset = 0
limit = 100  # Max per request
all_emails = []

while True:
    url = f"https://api.hunter.io/v2/domain-search"
    params = {
        'domain': domain,
        'api_key': api_key,
        'offset': offset,
        'limit': limit
    }
    
    async with session.get(url, params=params) as response:
        data = await response.json()
        emails = data.get('data', {}).get('emails', [])
        
        if not emails:
            break
        
        all_emails.extend(emails)
        offset += limit
        
        # Check if there are more results
        meta = data.get('meta', {})
        if offset >= meta.get('total', 0):
            break

return all_emails
```

#### Cache Results
```python
# Check cache first
cache_key = f"hunter_io:{domain}"
cached_result = self.get_cached(cache_key)
if cached_result:
    return cached_result

# ... make API request ...

# Cache the results
self.set_cached(cache_key, emails)
return emails
```

---

## Dependencies
- `aiohttp` ✅ (in requirements.txt)
- `dnspython` ✅ (in requirements.txt)
- API keys configured in `.env`:
  ```bash
  SECURITYTRAILS_API_KEY=your_key
  VIRUSTOTAL_API_KEY=your_key
  HUNTER_IO_API_KEY=your_key
  SHODAN_API_KEY=your_key  # optional
  ```

## Testing Requirements

### Unit Tests
```python
@pytest.mark.asyncio
async def test_cert_transparency_search():
    recon = ReconTools(config)
    subdomains = await recon._cert_transparency_search("example.com")
    assert len(subdomains) > 0
    assert "www.example.com" in subdomains

@pytest.mark.asyncio
async def test_dns_passive_enum():
    recon = ReconTools(config)
    subdomains = await recon._dns_passive_enum("example.com")
    assert "www.example.com" in subdomains

@pytest.mark.asyncio
async def test_api_subdomain_search_no_key():
    config = BugBountyConfig()  # No API keys
    recon = ReconTools(config)
    subdomains = await recon._api_subdomain_search("example.com")
    assert len(subdomains) == 0  # Should handle gracefully

@pytest.mark.asyncio
async def test_hunter_io_search():
    recon = ReconTools(config)
    emails = await recon._hunter_io_search("example.com")
    assert isinstance(emails, list)
```

### Integration Tests
- Test against real APIs (with valid keys)
- Test rate limiting doesn't cause errors
- Test caching reduces API calls
- Test error handling with invalid keys

### Mock Tests
```python
@pytest.mark.asyncio
async def test_cert_transparency_mocked(aioresponses):
    mock_response = [
        {"name_value": "example.com\n*.example.com\napi.example.com"}
    ]
    aioresponses.get(
        'https://crt.sh/?q=%.example.com&output=json',
        payload=mock_response
    )
    
    recon = ReconTools(config)
    subdomains = await recon._cert_transparency_search("example.com")
    
    assert "example.com" in subdomains
    assert "api.example.com" in subdomains
```

## Acceptance Criteria
- [ ] `_cert_transparency_search()` queries crt.sh successfully
- [ ] `_dns_passive_enum()` resolves subdomains in parallel
- [ ] `_api_subdomain_search()` integrates with at least 2 APIs
- [ ] `_hunter_io_search()` retrieves and parses email data
- [ ] All functions handle missing API keys gracefully
- [ ] Rate limiting implemented for all APIs
- [ ] Results are cached to minimize API usage
- [ ] Proper error handling for network failures
- [ ] Unit tests achieve >80% coverage
- [ ] Integration tests pass with real APIs
- [ ] Documentation complete with examples

## Estimated Effort
**8-12 hours** total:
- _cert_transparency_search: 2-3 hours
- _dns_passive_enum: 2-3 hours
- _api_subdomain_search: 3-4 hours
- _hunter_io_search: 2-3 hours

## Related Issues
- Issue #1: Depends on `validate_target()` being implemented first
- See `IMPLEMENTATION_TASKS.md` for overall roadmap

## Resources
- **crt.sh Documentation**: https://crt.sh/
- **SecurityTrails API**: https://docs.securitytrails.com/
- **VirusTotal API v3**: https://developers.virustotal.com/reference/domains-relationships
- **Hunter.io API**: https://hunter.io/api-documentation/v2
- **Shodan API**: https://developer.shodan.io/api

