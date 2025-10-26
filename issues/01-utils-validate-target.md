# Issue #1: [CRITICAL] Implement `validate_target()` in utils.py

## Priority: CRITICAL ⚠️
**File**: `bugbounty_mcp_server/utils.py` (Line 122)

## Problem
The `validate_target()` function is a critical utility used by almost all other tools in the system, but it currently only has a `pass` statement.

## Description
This function needs to validate and parse various target types including URLs, domains, IP addresses, and CIDR ranges. It's a foundational function that other tools depend on.

## Current Code
```python
def validate_target(target: str) -> Dict[str, Any]:
    """Validate and parse a target (URL, domain, or IP)."""
    result = {
        "valid": False,
        "type": None,
        "original": target,
        "parsed": None,
        "domain": None,
        ...
    }
    pass  # ⚠️ Not implemented!
```

## Requirements

### Input Validation
The function must handle and validate:
1. **URLs**: `http://example.com`, `https://api.example.com:8080/path`
2. **Domains**: `example.com`, `subdomain.example.com`
3. **IPv4 Addresses**: `192.168.1.1`
4. **IPv6 Addresses**: `::1`, `2001:db8::1`
5. **CIDR Ranges**: `192.168.1.0/24`, `2001:db8::/32`

### Expected Return Value
```python
{
    "valid": True,
    "type": "url",  # or "domain", "ipv4", "ipv6", "cidr"
    "original": "https://example.com:443/path",
    "parsed": ParseResult(...),  # from urllib.parse
    "domain": "example.com",
    "host": "example.com",
    "port": 443,
    "scheme": "https",
    "path": "/path",
    "ip": None,  # or IP address for IP types
    "network": None  # or ipaddress.IPv4Network for CIDR
}
```

## Implementation Guide

### Step 1: URL Validation
```python
from urllib.parse import urlparse
import validators

# Parse URL
parsed = urlparse(target)
if parsed.scheme and parsed.netloc:
    result["valid"] = True
    result["type"] = "url"
    result["parsed"] = parsed
    result["domain"] = parsed.netloc.split(':')[0]
    result["port"] = parsed.port or (443 if parsed.scheme == 'https' else 80)
    result["scheme"] = parsed.scheme
    result["path"] = parsed.path
    return result
```

### Step 2: Domain Validation
```python
if validators.domain(target):
    result["valid"] = True
    result["type"] = "domain"
    result["domain"] = target
    result["host"] = target
    return result
```

### Step 3: IP Address Validation
```python
import ipaddress

try:
    ip = ipaddress.ip_address(target)
    result["valid"] = True
    result["type"] = "ipv4" if ip.version == 4 else "ipv6"
    result["ip"] = str(ip)
    result["host"] = str(ip)
    return result
except ValueError:
    pass
```

### Step 4: CIDR Range Validation
```python
try:
    network = ipaddress.ip_network(target, strict=False)
    result["valid"] = True
    result["type"] = "cidr"
    result["network"] = network
    result["ip_range"] = f"{network.network_address} - {network.broadcast_address}"
    return result
except ValueError:
    pass
```

### Step 5: Handle Invalid Targets
```python
# If we get here, target is invalid
result["valid"] = False
result["error"] = "Invalid target format"
return result
```

## Dependencies
- `validators` (already in requirements.txt ✅)
- `urllib.parse` (Python standard library)
- `ipaddress` (Python standard library)

## Testing Requirements

### Test Cases
```python
def test_validate_target():
    # Valid URLs
    assert validate_target("https://example.com")["valid"] == True
    assert validate_target("http://example.com:8080/path")["type"] == "url"
    
    # Valid domains
    assert validate_target("example.com")["type"] == "domain"
    assert validate_target("subdomain.example.com")["valid"] == True
    
    # Valid IPs
    assert validate_target("192.168.1.1")["type"] == "ipv4"
    assert validate_target("::1")["type"] == "ipv6"
    
    # Valid CIDR
    assert validate_target("192.168.1.0/24")["type"] == "cidr"
    
    # Invalid inputs
    assert validate_target("not a valid target")["valid"] == False
    assert validate_target("http://")["valid"] == False
    assert validate_target("")["valid"] == False
```

### Edge Cases to Test
- Empty strings
- Localhost and private IPs
- Domains with special characters
- URLs with authentication (user:pass@domain)
- URLs with fragments (#anchor)
- URLs with query parameters
- International domain names (IDN)
- Very long inputs
- Malformed inputs

## Acceptance Criteria
- [ ] Function validates all target types correctly
- [ ] Returns structured dictionary with all relevant fields
- [ ] Handles invalid inputs gracefully (no exceptions)
- [ ] Provides clear error messages for invalid targets
- [ ] Extracts port numbers correctly
- [ ] Handles both http and https schemes
- [ ] Works with IPv4 and IPv6 addresses
- [ ] Validates CIDR ranges correctly
- [ ] Unit tests achieve >90% code coverage
- [ ] All edge cases handled

## Impact
**CRITICAL** - This function is used by:
- `recon.py` - All reconnaissance tools
- `scanning.py` - Port and vulnerability scanning
- `webapp.py` - Web application testing
- `network.py` - Network analysis
- All other tool modules

**Blocking**: Many other implementations depend on this function being completed first.

## Estimated Effort
**2-4 hours** for implementation and testing

## Example Usage
```python
# After implementation, it will be used like:
from bugbounty_mcp_server.utils import validate_target

# Validate a URL
result = validate_target("https://example.com:443/api/v1")
if result["valid"]:
    print(f"Valid {result['type']}: {result['domain']}")
    # Proceed with scanning
else:
    print(f"Invalid target: {result.get('error')}")
```

## Related Issues
- All other issues depend on this one being completed first
- See `IMPLEMENTATION_TASKS.md` for the complete roadmap

## Notes
- Consider adding support for wildcards (*.example.com) in the future
- May want to add DNS resolution as an optional validation step
- Consider adding support for target lists (multiple targets in one string)

