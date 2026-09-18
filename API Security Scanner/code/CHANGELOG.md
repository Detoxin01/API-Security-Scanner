# Changelog

## Fixed Issues

### 1. ✅ Fixed JSON Serialization
- **Issue**: `ScanResult.to_dict()` was leaving `type` and `severity` as Python enum objects, causing JSON serialization failures
- **Fix**: Modified `to_dict()` to explicitly convert enum values to strings using `.value`
- **Location**: `api_security_scanner.py:81-88`

### 2. ✅ Correct Success Reporting
- **Issue**: Connection failures were swallowed and all endpoints counted as tested even when unreachable
- **Fix**:
  - Added `endpoints_failed` and `errors` fields to `ScanResult`
  - Modified `_test_endpoint()` to return success/failure status
  - Track failed vs successful endpoint tests separately
  - Return HTTP 207 (Multi-Status) for partial successes
- **Location**: `api_security_scanner.py:62-72, 139-189`

### 3. ✅ Removed Destructive Defaults
- **Issue**: SQL injection tests included `DROP TABLE` commands; POST/PUT/DELETE requests were repeated
- **Fix**:
  - Removed `DROP TABLE users` payload from SQL injection tests
  - Added `allow_destructive` flag to `APIEndpoint` (defaults to `False`)
  - SQL injection and rate limiting tests now skip POST/PUT/DELETE unless explicitly allowed
  - Only GET requests tested by default for safety
- **Location**: `api_security_scanner.py:107-115, 262-303, 305-337`

### 4. ✅ Actually Send Request Parameters
- **Issue**: `APIEndpoint.parameters` was stored but never used in requests
- **Fix**:
  - Added support for query parameters via `parameters['query']`
  - Added support for JSON bodies via `parameters['json']`
  - Added `auth_token` field for Bearer token authentication
  - Path parameter resolution (e.g., `{id}` → actual values)
  - All test methods now properly send parameters
- **Location**: `api_security_scanner.py:107-115, 195-200, 233-260, 389-427`

### 5. ✅ Reduce False Positives
- **Issue**:
  - Public resources returning 200 flagged as broken authorization
  - 10 requests without 429 flagged as missing rate limiting (even with 404s)
- **Fix**:
  - **BOLA Test**: Only test authenticated endpoints with ID parameters; require multiple successful unauthorized accesses; check response content for actual data (not error messages)
  - **Rate Limiting**: Increased to 20 requests; only flag if 15+ succeed with 2xx status; reduced severity to MEDIUM
  - **Security Headers**: Only report if 2+ headers missing; reduced severity to LOW
- **Location**: `api_security_scanner.py:305-337, 339-387, 389-427`

### 6. ✅ Validate Inputs and Secure Deployment
- **Issue**: Invalid inputs returned 500; no bounds on timeout/concurrency; debug mode enabled
- **Fix**:
  - Comprehensive input validation returning 400 for invalid requests
  - Bounded timeout (max 60s) and concurrency (max 20)
  - URL validation with optional whitelist (`ALLOWED_HOSTS`)
  - Debug mode disabled by default (controlled via `FLASK_DEBUG` env var)
  - Configurable host/port via environment variables
  - Added `.env.example` with security best practices
- **Location**: `app.py:1-36, 49-195, 330-343`

### 7. ✅ Update Documentation and Tests
- **Issue**: Missing tests for serialization, connection failures, invalid inputs
- **Fix**: Added comprehensive test coverage:
  - `TestSerialization`: Tests enum serialization and error tracking
  - `TestConnectionFailures`: Tests unreachable targets and partial failures
  - `TestParameterHandling`: Tests query params, JSON bodies, auth tokens
  - `TestDestructiveTests`: Tests `allow_destructive` flag
  - `TestInputValidation`: Tests 400 responses for invalid inputs
  - `TestBoundedLimits`: Tests timeout and concurrency caps
- **Location**: `test_scanner.py:276-480`

## New Features

### Environment Configuration
Create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
```

### Enhanced Security
- Rate limiting configured via environment variables
- Host whitelist support
- Bounded resource usage
- Non-destructive testing by default

### Better Error Reporting
- Detailed error messages in scan results
- Separate tracking of successful vs failed endpoints
- HTTP 207 for partial successes

## API Changes

### Endpoint Configuration
```json
{
  "method": "GET",
  "path": "/api/users/{id}",
  "requires_auth": true,
  "parameters": {
    "query": {"limit": 10},
    "json": {"key": "value"}
  },
  "auth_token": "Bearer token-here",
  "allow_destructive": false
}
```

### Scan Response
```json
{
  "status": "success",
  "scan_id": 1,
  "data": {
    "endpoints_tested": 3,
    "endpoints_failed": 0,
    "errors": [],
    "vulnerabilities": [...]
  }
}
```

## Migration Guide

### For Existing Users

1. **Update endpoint definitions** to use new parameter structure:
   ```python
   # Old
   APIEndpoint('GET', '/users', parameters={'id': 123})

   # New
   APIEndpoint('GET', '/users', parameters={'query': {'id': 123}})
   ```

2. **Add `.env` file** for configuration (see `.env.example`)

3. **Review scan results** - failures now properly reported in `endpoints_failed` and `errors`

4. **Adjust expectations** - fewer false positives, more accurate vulnerability detection

## Known Limitations

1. Only 5 vulnerability checks implemented (not 10+ as originally advertised)
2. Rate limiting detection may still have false positives for APIs with soft limits
3. BOLA detection requires specific conditions (auth required + ID parameters)
