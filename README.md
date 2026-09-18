# 🔒 API Security Scanner - Complete Implementation

## 📋 Project Overview

This is a **production-ready API Security Scanner** based on the CarterPerez-dev Cybersecurity-Projects repository. It's an enterprise-grade tool for testing APIs against the **OWASP API Top 10** vulnerabilities.

### Key Features
✅ Tests for 10+ major API security vulnerabilities  
✅ Concurrent endpoint scanning (5+ endpoints simultaneously)  
✅ REST API with full history tracking  
✅ Detailed vulnerability reports with CVSS scoring  
✅ Remediation recommendations included  
✅ Production-ready Flask backend  

---

## 📂 Files Included

### Core Application
| File | Purpose |
|------|---------|
| **api_security_scanner.py** | Main scanner engine with all vulnerability tests |
| **app.py** | Flask web server for REST API |
| **requirements.txt** | Python dependencies |
| **.env.example** | Configuration template |

### Documentation
| File | Purpose |
|------|---------|
| **QUICKSTART.md** | 5-minute setup guide (START HERE!) |
| **API_SECURITY_SCANNER_GUIDE.md** | Complete documentation & reference |
| **README.md** | This file |

### Examples & Tests
| File | Purpose |
|------|---------|
| **example_scans.py** | 5 ready-to-use scan configurations |
| **test_scanner.py** | Unit tests (run with pytest) |

---

## 🚀 Quick Start

### 1️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 2️⃣ Start the Web Server
```bash
python app.py
# Server running on http://localhost:5000
```

### 3️⃣ Run Your First Scan
```bash
# Using cURL
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "base_url": "http://localhost:3000",
    "endpoints": [
      {"method": "GET", "path": "/api/users", "requires_auth": true},
      {"method": "POST", "path": "/api/auth/login", "requires_auth": false}
    ]
  }'
```

### 4️⃣ View Results
```bash
# Get scan report
curl http://localhost:5000/api/report/1

# Get all scans
curl http://localhost:5000/api/scans

# Get statistics
curl http://localhost:5000/api/vulnerabilities/stats
```

---

## 🔐 What Gets Tested

### 10 Vulnerability Types

1. **Broken Authentication** (CVSS 9.8)
   - Empty token acceptance
   - Missing credential validation

2. **SQL Injection** (CVSS 9.9)
   - Parameterization detection
   - Database error exposure

3. **Rate Limiting** (CVSS 7.5)
   - Missing rate limit enforcement
   - No 429 responses

4. **Broken Object-Level Authorization** (CVSS 7.1)
   - Accessing other users' resources
   - Missing ownership checks

5. **Security Headers** (CVSS 5.3)
   - Missing X-Frame-Options
   - Missing Content-Security-Policy
   - Missing Strict-Transport-Security

6. **Excessive Data Exposure**
7. **Lack of Encryption**
8. **Mass Assignment Issues**
9. **Security Misconfiguration**
10. **Insufficient Logging**

---

## 📊 REST API Endpoints

### Scanning
```
POST /api/scan                 Start new security scan
GET  /api/scan/{id}           Get specific scan result
GET  /api/scans               List all scans
GET  /api/report/{id}         Get detailed report
```

### Analytics
```
GET  /api/vulnerabilities/stats    Vulnerability statistics
GET  /health                       Health check
```

### Example Request
```json
{
  "base_url": "http://api.example.com",
  "timeout": 10,
  "concurrent_requests": 5,
  "endpoints": [
    {
      "method": "GET",
      "path": "/api/users",
      "requires_auth": true,
      "parameters": {}
    },
    {
      "method": "POST",
      "path": "/api/auth/login",
      "requires_auth": false,
      "parameters": {
        "username": "user",
        "password": "pass"
      }
    }
  ]
}
```

### Example Response
```json
{
  "status": "success",
  "scan_id": 1,
  "data": {
    "api_url": "http://api.example.com",
    "endpoints_tested": 2,
    "total_vulnerabilities": 3,
    "severity_breakdown": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    "vulnerabilities": [
      {
        "type": "broken_authentication",
        "severity": "critical",
        "endpoint": "/api/users",
        "method": "GET",
        "title": "Authentication Bypass",
        "description": "API accepted empty token",
        "evidence": "HTTP 200 with empty Authorization",
        "remediation": "Validate all tokens",
        "cvss_score": 9.8
      }
    ]
  }
}
```

---

## 💻 Python Usage

### Basic Scan
```python
import asyncio
from api_security_scanner import SecurityScanner, APIEndpoint

async def scan_api():
    # Define endpoints
    endpoints = [
        APIEndpoint('GET', '/api/users', requires_auth=True),
        APIEndpoint('POST', '/api/auth/login', requires_auth=False),
    ]
    
    # Create scanner
    scanner = SecurityScanner('http://localhost:3000')
    
    # Run scan
    result = await scanner.scan(endpoints)
    
    # Print results
    print(f"Found {len(result.vulnerabilities)} vulnerabilities:")
    for vuln in result.vulnerabilities:
        print(f"  {vuln.severity.value}: {vuln.title}")
        print(f"  CVSS Score: {vuln.cvss_score}")
        print(f"  Fix: {vuln.remediation}\n")

asyncio.run(scan_api())
```

### Parallel Scanning
```python
import asyncio
from api_security_scanner import SecurityScanner, APIEndpoint

async def scan_multiple_apis():
    apis = [
        'http://api1.example.com',
        'http://api2.example.com',
        'http://api3.example.com'
    ]
    
    endpoints = [
        APIEndpoint('GET', '/api/health'),
        APIEndpoint('GET', '/api/users', requires_auth=True),
    ]
    
    tasks = []
    for api_url in apis:
        scanner = SecurityScanner(api_url)
        tasks.append(scanner.scan(endpoints))
    
    results = await asyncio.gather(*tasks)
    return results

asyncio.run(scan_multiple_apis())
```

---

## 🛠️ Configuration

### Environment Variables (.env)
```bash
SCANNER_TIMEOUT=10                    # Request timeout (seconds)
CONCURRENT_REQUESTS=5                 # Parallel requests
FLASK_ENV=development                 # Flask environment
FLASK_PORT=5000                       # Server port
LOG_LEVEL=INFO                        # Logging level
```

### Custom Configuration
```python
scanner = SecurityScanner(
    base_url='http://api.example.com',
    timeout=30,                    # Increase timeout for slow APIs
    concurrent_requests=3          # Reduce for rate-limited APIs
)
```

---

## 📈 Understanding CVSS Scores

| Score | Severity | Action |
|-------|----------|--------|
| 9.0-10.0 | CRITICAL | Fix immediately ⚠️ |
| 7.0-8.9 | HIGH | Fix within days 🟠 |
| 5.0-6.9 | MEDIUM | Fix within weeks 🟡 |
| 3.0-4.9 | LOW | Fix within months 🔵 |
| 0.0-2.9 | INFO | Informational ℹ️ |

---

## ✅ Best Practices for Your API

### 1. Authentication
```python
@app.route('/api/protected')
def protected():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    # ✓ Validate token exists
    if not token:
        return 'Unauthorized', 401
    
    # ✓ Verify token
    try:
        user = verify_token(token)
    except:
        return 'Invalid token', 401
    
    return get_data()
```

### 2. SQL Injection Prevention
```python
# ✗ DON'T DO THIS
result = db.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ✓ DO THIS INSTEAD
result = db.execute("SELECT * FROM users WHERE id = ?", [user_id])
```

### 3. Rate Limiting
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/data')
@limiter.limit("100 per hour")
def get_data():
    return jsonify({"data": "..."})
```

### 4. Security Headers
```python
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

### 5. Authorization Checks
```python
@app.route('/api/users/<user_id>')
def get_user(user_id):
    current_user = get_current_user()
    
    # ✓ Check ownership
    if current_user.id != user_id:
        return 'Forbidden', 403
    
    return get_user_data(user_id)
```

---

## 🧪 Testing

### Run Unit Tests
```bash
pytest test_scanner.py -v
```

### Run Specific Test
```bash
pytest test_scanner.py::TestSecurityScanner::test_scanner_creation -v
```

### Run with Coverage
```bash
pip install pytest-cov
pytest test_scanner.py --cov=api_security_scanner
```

---

## 🐛 Troubleshooting

### "Connection refused"
```
❌ Error: Cannot connect to http://localhost:3000
✓ Solution: Start your target API first
```

### "401 Unauthorized" on protected endpoints
```
❌ Error: Getting 401 on protected endpoints
✓ Solution: This is expected! The scanner tests if you can access
             protected endpoints without proper auth. It's a feature.
```

### Scan taking too long
```
❌ Problem: Scan never finishes
✓ Solution: 
  - Reduce concurrent_requests (5 → 3)
  - Increase timeout (10 → 30)
  - Check if API is responding slowly
```

### False positives
```
❌ Problem: Getting vulnerabilities that shouldn't exist
✓ Solution: 
  - Review the evidence
  - Check if it's a true positive
  - Whitelist if it's a false positive
```

---

## 📚 Example Scans

The `example_scans.py` file includes 5 real-world examples:

1. **E-Commerce API** - User accounts, products, orders
2. **Healthcare API** - Patient records, appointments
3. **Social Media API** - Posts, comments, follows
4. **Banking API** - Accounts, transfers, transactions
5. **Minimal Scan** - Just health check

Run any of them:
```bash
python example_scans.py
```

---

## 🔗 Related Resources

- **OWASP API Top 10**: https://owasp.org/www-project-api-security/
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **CarterPerez-dev**: https://github.com/CarterPerez-dev/Cybersecurity-Projects
- **API Security Best Practices**: https://owasp.org/www-project-api-security/

---

## 📋 Checklist: Securing Your API

- [ ] Implement authentication on all protected endpoints
- [ ] Validate all incoming data
- [ ] Use parameterized queries (prevent SQL injection)
- [ ] Implement rate limiting
- [ ] Add security headers
- [ ] Check authorization for each request
- [ ] Log all API access
- [ ] Encrypt sensitive data in transit (HTTPS)
- [ ] Encrypt sensitive data at rest
- [ ] Keep dependencies updated
- [ ] Run security scans regularly
- [ ] Document API behavior
- [ ] Test with this scanner

---

## 🚀 Deployment

### Local Development
```bash
python app.py
# Runs on http://localhost:5000
```

### Production (Gunicorn)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker (Optional)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

```bash
docker build -t api-scanner .
docker run -p 5000:5000 api-scanner
```

---

## 📞 Support

- **Documentation**: See `API_SECURITY_SCANNER_GUIDE.md`
- **Quick Start**: See `QUICKSTART.md`
- **Examples**: See `example_scans.py`
- **Tests**: Run `pytest test_scanner.py`

---

## 📝 License

This project is based on the CarterPerez-dev Cybersecurity-Projects repository.
Used for educational and security testing purposes.

---

## 🎯 Next Steps

1. ✅ Read `QUICKSTART.md` - Get running in 5 minutes
2. 📖 Read `API_SECURITY_SCANNER_GUIDE.md` - Understand all features
3. 🧪 Run `example_scans.py` - See it in action
4. 🔐 Scan your own API - Find and fix vulnerabilities
5. 🛡️ Apply best practices - Secure your API

---

**Happy scanning! 🔒**

*Last Updated: February 2024*
