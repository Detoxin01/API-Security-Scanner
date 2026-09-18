"""
elliotoxin | 2026
Flask Web API for API Security Scanner
Provides REST endpoints to perform security scans
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import asyncio
import json
import os
from datetime import datetime
from api_security_scanner import SecurityScanner, APIEndpoint
from urllib.parse import urlparse
import logging

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store scan history
scan_history = []

# Configuration
MAX_ENDPOINTS = int(os.getenv('MAX_ENDPOINTS', '50'))
MAX_TIMEOUT = int(os.getenv('MAX_TIMEOUT', '60'))
MAX_CONCURRENT = int(os.getenv('MAX_CONCURRENT', '20'))
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',') if os.getenv('ALLOWED_HOSTS') else []


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'API Security Scanner'
    }), 200


def validate_url(url):
    """Validate URL format and check against allowed hosts"""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format"

        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS protocols are allowed"

        # Check against whitelist if configured
        if ALLOWED_HOSTS and parsed.netloc not in ALLOWED_HOSTS:
            return False, f"Host {parsed.netloc} is not in the allowed hosts list"

        return True, None
    except Exception as e:
        return False, str(e)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """
    Start a new security scan

    Request body:
    {
        "base_url": "http://target-api.com",
        "endpoints": [
            {
                "method": "GET",
                "path": "/api/users",
                "requires_auth": true,
                "parameters": {"query": {}, "json": {}},
                "auth_token": "optional_token",
                "allow_destructive": false
            }
        ],
        "timeout": 10,
        "concurrent_requests": 5
    }
    """
    try:
        data = request.get_json()

        # Validate required fields
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        if 'base_url' not in data:
            return jsonify({'error': 'Missing required field: base_url'}), 400

        if 'endpoints' not in data:
            return jsonify({'error': 'Missing required field: endpoints'}), 400

        if not isinstance(data['endpoints'], list):
            return jsonify({'error': 'Field "endpoints" must be an array'}), 400

        if len(data['endpoints']) == 0:
            return jsonify({'error': 'At least one endpoint is required'}), 400

        if len(data['endpoints']) > MAX_ENDPOINTS:
            return jsonify({'error': f'Maximum {MAX_ENDPOINTS} endpoints allowed'}), 400

        base_url = data['base_url']

        # Validate URL
        is_valid, error_msg = validate_url(base_url)
        if not is_valid:
            return jsonify({'error': f'Invalid base_url: {error_msg}'}), 400

        # Validate and bound timeout and concurrency
        timeout = data.get('timeout', 10)
        concurrent_requests = data.get('concurrent_requests', 5)

        if not isinstance(timeout, (int, float)) or timeout <= 0:
            return jsonify({'error': 'timeout must be a positive number'}), 400

        if not isinstance(concurrent_requests, int) or concurrent_requests <= 0:
            return jsonify({'error': 'concurrent_requests must be a positive integer'}), 400

        timeout = min(timeout, MAX_TIMEOUT)
        concurrent_requests = min(concurrent_requests, MAX_CONCURRENT)

        # Validate and convert endpoint dictionaries to APIEndpoint objects
        endpoints = []
        for i, ep in enumerate(data['endpoints']):
            if not isinstance(ep, dict):
                return jsonify({'error': f'Endpoint {i} must be an object'}), 400

            if 'path' not in ep:
                return jsonify({'error': f'Endpoint {i} missing required field: path'}), 400

            method = ep.get('method', 'GET')
            if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                return jsonify({'error': f'Endpoint {i} has invalid method: {method}'}), 400

            endpoint = APIEndpoint(
                method=method,
                path=ep.get('path'),
                requires_auth=ep.get('requires_auth', False),
                parameters=ep.get('parameters', {}),
                auth_token=ep.get('auth_token'),
                allow_destructive=ep.get('allow_destructive', False)
            )
            endpoints.append(endpoint)

        logger.info(f"Starting scan for {base_url} with {len(endpoints)} endpoints")

        # Create scanner and run scan
        scanner = SecurityScanner(
            base_url=base_url,
            timeout=timeout,
            concurrent_requests=concurrent_requests
        )

        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(scanner.scan(endpoints))
        loop.close()

        result_dict = result.to_dict()

        # Check if scan had errors
        if result.endpoints_failed > 0:
            status_code = 207  # Multi-Status - partial success
        else:
            status_code = 200

        # Store in history
        scan_history.append({
            'timestamp': datetime.now().isoformat(),
            'result': result_dict
        })

        return jsonify({
            'status': 'success' if result.endpoints_failed == 0 else 'partial_success',
            'scan_id': len(scan_history),
            'data': result_dict
        }), status_code

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'error': f'Validation error: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Scan error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan_result(scan_id):
    """Get a previous scan result"""
    try:
        if scan_id < 1 or scan_id > len(scan_history):
            return jsonify({'error': 'Scan not found'}), 404
        
        scan = scan_history[scan_id - 1]
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'timestamp': scan['timestamp'],
            'data': scan['result']
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving scan: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans in history"""
    try:
        scan_list = []
        for i, scan in enumerate(scan_history, 1):
            scan_list.append({
                'scan_id': i,
                'timestamp': scan['timestamp'],
                'api_url': scan['result']['api_url'],
                'total_vulnerabilities': scan['result']['total_vulnerabilities'],
                'endpoints_tested': scan['result']['endpoints_tested']
            })
        
        return jsonify({
            'status': 'success',
            'total_scans': len(scan_history),
            'scans': scan_list
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing scans: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/<int:scan_id>', methods=['GET'])
def get_report(scan_id):
    """Get detailed report for a scan"""
    try:
        if scan_id < 1 or scan_id > len(scan_history):
            return jsonify({'error': 'Scan not found'}), 404
        
        scan = scan_history[scan_id - 1]
        result = scan['result']
        
        # Create detailed report
        report = {
            'status': 'success',
            'scan_id': scan_id,
            'timestamp': scan['timestamp'],
            'summary': {
                'api_url': result['api_url'],
                'scan_start': result['scan_start'],
                'scan_end': result['scan_end'],
                'endpoints_tested': result['endpoints_tested'],
                'success_rate': f"{result['success_rate']:.2f}%",
                'total_vulnerabilities': result['total_vulnerabilities'],
                'severity_breakdown': result['severity_breakdown']
            },
            'vulnerabilities': result['vulnerabilities']
        }
        
        return jsonify(report), 200
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/vulnerabilities/stats', methods=['GET'])
def vulnerability_stats():
    """Get statistics about all vulnerabilities found"""
    try:
        total_vulns = 0
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        vuln_types = {}
        
        for scan in scan_history:
            result = scan['result']
            total_vulns += result['total_vulnerabilities']
            
            # Aggregate severity
            for severity, count in result['severity_breakdown'].items():
                if severity in severity_counts:
                    severity_counts[severity] += count
            
            # Aggregate vulnerability types
            for vuln in result['vulnerabilities']:
                vuln_type = vuln.get('type', 'unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        return jsonify({
            'status': 'success',
            'total_scans': len(scan_history),
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'vulnerability_types': vuln_types
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Starting API Security Scanner Web Server")
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', '5000'))

    if debug_mode:
        logger.warning("⚠️  Running in DEBUG mode - not suitable for production!")

    app.run(
        host=host,
        port=port,
        debug=debug_mode
    )
