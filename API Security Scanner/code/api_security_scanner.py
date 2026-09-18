"""
elliotoxin | 2026
API Security Scanner
Enterprise-grade API vulnerability scanner for testing OWASP API Top 10 vulnerabilities
"""

import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """Types of vulnerabilities to test"""
    BROKEN_AUTH = "broken_authentication"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    LACK_OF_ENCRYPTION = "lack_of_encryption"
    INJECTION = "injection"
    BROKEN_OBJECT_LEVEL_AUTH = "broken_object_level_auth"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    RATE_LIMITING = "rate_limiting"
    INSUFFICIENT_LOGGING = "insufficient_logging"


@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    type: VulnerabilityType
    severity: VulnerabilitySeverity
    endpoint: str
    method: str
    title: str
    description: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    """Complete scan result"""
    api_url: str
    scan_start: str
    scan_end: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    endpoints_tested: int = 0
    endpoints_failed: int = 0
    success_rate: float = 0.0
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'api_url': self.api_url,
            'scan_start': self.scan_start,
            'scan_end': self.scan_end,
            'endpoints_tested': self.endpoints_tested,
            'endpoints_failed': self.endpoints_failed,
            'success_rate': self.success_rate,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': [
                {
                    **asdict(v),
                    'type': v.type.value,
                    'severity': v.severity.value,
                }
                for v in self.vulnerabilities
            ],
            'severity_breakdown': self._get_severity_breakdown(),
            'errors': self.errors
        }
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by severity"""
        breakdown = {severity.value: 0 for severity in VulnerabilitySeverity}
        for vuln in self.vulnerabilities:
            breakdown[vuln.severity.value] += 1
        return breakdown


class APIEndpoint:
    """Represents an API endpoint to test"""

    def __init__(self, method: str, path: str, requires_auth: bool = False,
                 parameters: Optional[Dict] = None, auth_token: Optional[str] = None,
                 allow_destructive: bool = False):
        self.method = method.upper()
        self.path = path
        self.requires_auth = requires_auth
        self.parameters = parameters or {}
        self.auth_token = auth_token
        self.allow_destructive = allow_destructive


class SecurityScanner:
    """Main API Security Scanner"""

    def __init__(self, base_url: str, timeout: int = 10,
                 concurrent_requests: int = 5, allowed_hosts: Optional[List[str]] = None):
        """
        Initialize the security scanner

        Args:
            base_url: Target API base URL
            timeout: Request timeout in seconds (max 60)
            concurrent_requests: Number of concurrent requests (max 20)
            allowed_hosts: List of allowed hosts for redirects (optional)
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = min(timeout, 60)  # Cap at 60 seconds
        self.concurrent_requests = min(concurrent_requests, 20)  # Cap at 20
        self.allowed_hosts = allowed_hosts or []
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoints_tested = 0
        self.endpoints_failed = 0
        self.errors: List[str] = []
        
    async def scan(self, endpoints: List[APIEndpoint]) -> ScanResult:
        """
        Perform security scan on API endpoints

        Args:
            endpoints: List of API endpoints to scan

        Returns:
            ScanResult containing all findings
        """
        scan_start = datetime.now().isoformat()
        logger.info(f"Starting API security scan for {self.base_url}")

        self.vulnerabilities = []
        self.endpoints_tested = 0
        self.endpoints_failed = 0
        self.errors = []

        # Run scans concurrently
        connector = aiohttp.TCPConnector(limit=self.concurrent_requests)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self._test_endpoint(session, endpoint) for endpoint in endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Count successful vs failed endpoints
            for i, result in enumerate(results):
                if isinstance(result, Exception) or result is False:
                    self.endpoints_failed += 1
                    error_msg = f"{endpoints[i].method} {endpoints[i].path}: {str(result) if isinstance(result, Exception) else 'Connection failed'}"
                    self.errors.append(error_msg)
                    logger.error(error_msg)
                else:
                    self.endpoints_tested += 1

        scan_end = datetime.now().isoformat()

        result = ScanResult(
            api_url=self.base_url,
            scan_start=scan_start,
            scan_end=scan_end,
            vulnerabilities=self.vulnerabilities,
            endpoints_tested=self.endpoints_tested,
            endpoints_failed=self.endpoints_failed,
            success_rate=self._calculate_success_rate(endpoints),
            errors=self.errors
        )

        logger.info(f"Scan completed. Tested {self.endpoints_tested}/{len(endpoints)} endpoints. Found {len(self.vulnerabilities)} vulnerabilities")
        return result
    
    async def _test_endpoint(self, session: aiohttp.ClientSession,
                            endpoint: APIEndpoint) -> bool:
        """Test a single endpoint for vulnerabilities. Returns True if successful, False if failed."""
        url = f"{self.base_url}{endpoint.path}"

        # Resolve path parameters
        if endpoint.parameters and '{' in url:
            for key, value in endpoint.parameters.items():
                url = url.replace(f'{{{key}}}', str(value))

        # Track if at least one test succeeded
        any_test_succeeded = False

        # Test 1: Authentication bypass
        try:
            await self._test_auth_bypass(session, url, endpoint)
            any_test_succeeded = True
        except aiohttp.ClientError as e:
            logger.error(f"Connection error in auth bypass test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout in auth bypass test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except Exception as e:
            logger.debug(f"Auth bypass test skipped for {endpoint.method} {endpoint.path}: {str(e)}")

        # Test 2: SQL Injection (non-destructive only)
        try:
            await self._test_sql_injection(session, url, endpoint)
            any_test_succeeded = True
        except aiohttp.ClientError as e:
            logger.error(f"Connection error in SQL injection test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout in SQL injection test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except Exception as e:
            logger.debug(f"SQL injection test skipped for {endpoint.method} {endpoint.path}: {str(e)}")

        # Test 3: Missing Rate Limiting
        try:
            await self._test_rate_limiting(session, url, endpoint)
            any_test_succeeded = True
        except aiohttp.ClientError as e:
            logger.error(f"Connection error in rate limiting test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout in rate limiting test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except Exception as e:
            logger.debug(f"Rate limiting test skipped for {endpoint.method} {endpoint.path}: {str(e)}")

        # Test 4: Broken Object Level Authorization
        try:
            await self._test_object_level_auth(session, url, endpoint)
            any_test_succeeded = True
        except aiohttp.ClientError as e:
            logger.error(f"Connection error in object level auth test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout in object level auth test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except Exception as e:
            logger.debug(f"Object level auth test skipped for {endpoint.method} {endpoint.path}: {str(e)}")

        # Test 5: Security misconfiguration
        try:
            await self._test_security_headers(session, url, endpoint)
            any_test_succeeded = True
        except aiohttp.ClientError as e:
            logger.error(f"Connection error in security headers test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except asyncio.TimeoutError as e:
            logger.error(f"Timeout in security headers test for {endpoint.method} {endpoint.path}: {str(e)}")
            return False
        except Exception as e:
            logger.debug(f"Security headers test skipped for {endpoint.method} {endpoint.path}: {str(e)}")

        if any_test_succeeded:
            logger.info(f"✓ Tested {endpoint.method} {endpoint.path}")
            return True
        else:
            logger.error(f"✗ All tests failed for {endpoint.method} {endpoint.path}")
            return False
    
    async def _test_auth_bypass(self, session: aiohttp.ClientSession,
                               url: str, endpoint: APIEndpoint) -> None:
        """Test for broken authentication"""
        if not endpoint.requires_auth:
            return

        # Build headers with authentication token if provided
        headers = {}
        if endpoint.auth_token:
            headers['Authorization'] = f'Bearer {endpoint.auth_token}'

        # Test with empty credentials
        test_headers = {'Authorization': ''}

        # Send query params and JSON body if present
        params = endpoint.parameters.get('query', {})
        json_data = endpoint.parameters.get('json', None)

        # Use GET for destructive methods when allow_destructive is False
        test_method = endpoint.method
        if endpoint.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and not endpoint.allow_destructive:
            test_method = 'GET'

        async with await self._safe_request(session, test_method, url, headers=test_headers,
                                  params=params, json=json_data if test_method != 'GET' else None) as resp:
            if resp.status in [200, 201]:
                self.vulnerabilities.append(Vulnerability(
                    type=VulnerabilityType.BROKEN_AUTH,
                    severity=VulnerabilitySeverity.CRITICAL,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    title="Authentication Bypass - Empty Bearer Token",
                    description="API accepted empty authentication token",
                    evidence=f"HTTP {resp.status} response with empty Authorization header",
                    remediation="Implement proper authentication validation",
                    cvss_score=9.8
                ))
    
    async def _test_sql_injection(self, session: aiohttp.ClientSession,
                                 url: str, endpoint: APIEndpoint) -> None:
        """Test for SQL injection vulnerabilities (non-destructive tests only)"""
        # Only use non-destructive SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "admin'--",
            "' AND 1=1--"
        ]

        # Only test if endpoint allows destructive tests or uses GET method
        if endpoint.method not in ['GET'] and not endpoint.allow_destructive:
            logger.debug(f"Skipping SQL injection test for {endpoint.method} {endpoint.path} (destructive test not allowed)")
            return

        for payload in payloads:
            # Only test query parameters, not body
            params = endpoint.parameters.get('query', {}).copy()
            params.update({'id': payload, 'search': payload})

            async with await self._safe_request(session, endpoint.method, url, params=params) as resp:
                content = await resp.text()

                # Simple detection - look for SQL errors
                sql_indicators = ['SQL syntax', 'mysql_fetch', 'SQL error', 'ORA-', 'sqlite_', 'PostgreSQL']
                if any(indicator in content for indicator in sql_indicators):
                    self.vulnerabilities.append(Vulnerability(
                        type=VulnerabilityType.INJECTION,
                        severity=VulnerabilitySeverity.CRITICAL,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        title="SQL Injection Vulnerability",
                        description="Endpoint vulnerable to SQL injection attacks",
                        evidence=f"SQL error revealed with payload: {payload}",
                        remediation="Use parameterized queries and prepared statements",
                        cvss_score=9.9
                    ))
                    break
    
    async def _test_rate_limiting(self, session: aiohttp.ClientSession,
                                 url: str, endpoint: APIEndpoint) -> None:
        """Test for lack of rate limiting"""
        # Only test GET endpoints or if explicitly allowed
        if endpoint.method not in ['GET'] and not endpoint.allow_destructive:
            logger.debug(f"Skipping rate limiting test for {endpoint.method} {endpoint.path}")
            return

        # Send multiple requests rapidly
        responses = []
        params = endpoint.parameters.get('query', {})
        headers = {}
        if endpoint.auth_token:
            headers['Authorization'] = f'Bearer {endpoint.auth_token}'

        for i in range(20):  # Increased to 20 to be more thorough
            async with await self._safe_request(session, endpoint.method, url, params=params, headers=headers) as resp:
                responses.append(resp.status)

        # Check if we got rate limited (429 = rate limited, which is good)
        # Only report if all requests succeeded with 2xx status
        successful_responses = [s for s in responses if 200 <= s < 300]
        if len(successful_responses) >= 15 and 429 not in responses:
            self.vulnerabilities.append(Vulnerability(
                type=VulnerabilityType.RATE_LIMITING,
                severity=VulnerabilitySeverity.MEDIUM,
                endpoint=endpoint.path,
                method=endpoint.method,
                title="Potential Missing Rate Limiting",
                description="API may not implement rate limiting",
                evidence=f"Sent 20 consecutive requests, {len(successful_responses)} succeeded without 429 response",
                remediation="Implement rate limiting using token bucket or similar algorithm",
                cvss_score=5.3
            ))
    
    async def _test_object_level_auth(self, session: aiohttp.ClientSession,
                                     url: str, endpoint: APIEndpoint) -> None:
        """Test for broken object-level authorization"""
        # Check if endpoint.path (not url) has ID parameters
        # This needs to be checked BEFORE path replacement
        if not endpoint.requires_auth or ('{id}' not in endpoint.path and '{' not in endpoint.path):
            logger.debug(f"Skipping BOLA test for {endpoint.path} (no auth or no ID parameter)")
            return

        # Test accessing different user IDs without auth token
        test_ids = ['1', '2', '999', 'admin']
        successful_accesses = []

        for test_id in test_ids:
            test_url = url
            if '{id}' in test_url:
                test_url = test_url.replace('{id}', test_id)
            elif '{' in test_url:
                # Replace any path parameter
                import re
                test_url = re.sub(r'\{[^}]+\}', test_id, url, count=1)
            else:
                test_url = url + f"/{test_id}"

            # Use GET for destructive methods when allow_destructive is False
            test_method = endpoint.method
            if endpoint.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and not endpoint.allow_destructive:
                test_method = 'GET'

            # Test WITHOUT authentication header (should fail if properly secured)
            params = endpoint.parameters.get('query', {})
            async with await self._safe_request(session, test_method, test_url, params=params) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    # Only flag if we got actual data (not empty or error message)
                    if content and len(content) > 50 and not any(err in content.lower() for err in ['error', 'unauthorized', 'forbidden', 'not found']):
                        successful_accesses.append(test_id)

        # Only report if we successfully accessed multiple different IDs without auth
        if len(successful_accesses) >= 2:
            self.vulnerabilities.append(Vulnerability(
                type=VulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH,
                severity=VulnerabilitySeverity.HIGH,
                endpoint=endpoint.path,
                method=endpoint.method,
                title="Broken Object Level Authorization",
                description="Can access resources with different IDs without authentication",
                evidence=f"Successfully accessed resources without auth: {', '.join(successful_accesses)}",
                remediation="Implement proper authorization checks for each resource access",
                cvss_score=7.1
            ))
    
    async def _test_security_headers(self, session: aiohttp.ClientSession,
                                    url: str, endpoint: APIEndpoint) -> None:
        """Test for missing security headers"""
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': 'default-src'
        }

        params = endpoint.parameters.get('query', {})
        json_data = endpoint.parameters.get('json', None)
        headers = {}
        if endpoint.auth_token:
            headers['Authorization'] = f'Bearer {endpoint.auth_token}'

        # Use GET for destructive methods when allow_destructive is False
        test_method = endpoint.method
        if endpoint.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and not endpoint.allow_destructive:
            test_method = 'GET'

        async with await self._safe_request(session, test_method, url, params=params,
                                  json=json_data if test_method != 'GET' else None, headers=headers) as resp:
            missing_headers = []
            for header, expected_value in required_headers.items():
                if header not in resp.headers:
                    missing_headers.append(header)

            # Only report if multiple critical headers are missing
            if len(missing_headers) >= 2:
                self.vulnerabilities.append(Vulnerability(
                    type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                    severity=VulnerabilitySeverity.LOW,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    title="Missing Security Headers",
                    description=f"Missing {len(missing_headers)} security headers",
                    evidence=f"Headers not found: {', '.join(missing_headers)}",
                    remediation="Add security headers to all API responses",
                    cvss_score=3.7
                ))
    
    def _calculate_success_rate(self, endpoints: List[APIEndpoint]) -> float:
        """Calculate successful endpoint tests"""
        if not endpoints:
            return 0.0
        return (self.endpoints_tested / len(endpoints)) * 100

    def _validate_redirect_host(self, url: str) -> bool:
        """Validate that a redirect destination is in allowed hosts"""
        if not self.allowed_hosts:
            return True  # No restrictions if allowed_hosts not set

        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc in self.allowed_hosts

    async def _safe_request(self, session: aiohttp.ClientSession, method: str, url: str,
                           **kwargs) -> aiohttp.ClientResponse:
        """Make a request and validate redirects if allowed_hosts is configured"""
        if not self.allowed_hosts:
            # No validation needed
            return await session.request(method, url, **kwargs)

        # Disable redirects and handle manually
        kwargs['allow_redirects'] = False
        resp = await session.request(method, url, **kwargs)

        # Check if it's a redirect
        if resp.status in (301, 302, 303, 307, 308):
            redirect_url = resp.headers.get('Location', '')
            if redirect_url:
                if not self._validate_redirect_host(redirect_url):
                    raise ValueError(f"Redirect to unauthorized host: {redirect_url}")

        return resp


async def main():
    """Example usage"""
    # Define endpoints to scan
    endpoints = [
        APIEndpoint('GET', '/api/users', requires_auth=True),
        APIEndpoint('GET', '/api/users/{id}', requires_auth=True),
        APIEndpoint('POST', '/api/users', requires_auth=True),
        APIEndpoint('PUT', '/api/users/{id}', requires_auth=True),
        APIEndpoint('DELETE', '/api/users/{id}', requires_auth=True),
        APIEndpoint('GET', '/api/products'),
        APIEndpoint('GET', '/api/products/{id}'),
        APIEndpoint('POST', '/api/auth/login'),
    ]
    
    # Create scanner
    scanner = SecurityScanner(
        base_url='http://localhost:3000',
        timeout=10,
        concurrent_requests=5
    )
    
    # Run scan
    result = await scanner.scan(endpoints)
    
    # Print results
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == '__main__':
    asyncio.run(main())
