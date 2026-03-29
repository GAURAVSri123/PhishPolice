"""
Unit tests for Transparent Proxy Detection (Task 5.1)
Tests HTTP header analysis, connection IP comparison, and redirect detection
"""

import sys
import os
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_blocking import (
    detect_proxy_headers,
    detect_http_redirects,
    compare_dns_and_connection_ip,
    analyze_transparent_proxy,
    REQUESTS_AVAILABLE
)


def test_via_header_detection():
    """Test detection of Via header indicating proxy presence"""
    print("\n=== Test: Via Header Detection ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock HTTP response with Via header
    mock_response = Mock()
    mock_response.headers = {
        'Via': '1.1 proxy.example.com (squid/3.5.20)'
    }
    
    with patch('dns_blocking.requests.head', return_value=mock_response):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected: {proxy_detected}")
        print(f"Indicators: {indicators}")
        
        assert proxy_detected, "Should detect proxy from Via header"
        assert any('Via header' in ind for ind in indicators), "Should report Via header"
        
    print("✓ Via header detection works correctly")


def test_x_forwarded_for_header_detection():
    """Test detection of X-Forwarded-For header"""
    print("\n=== Test: X-Forwarded-For Header Detection ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock HTTP response with X-Forwarded-For header
    mock_response = Mock()
    mock_response.headers = {
        'X-Forwarded-For': '203.0.113.1, 198.51.100.1'
    }
    
    with patch('dns_blocking.requests.head', return_value=mock_response):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected: {proxy_detected}")
        print(f"Indicators: {indicators}")
        
        assert proxy_detected, "Should detect proxy from X-Forwarded-For header"
        assert any('X-Forwarded-For' in ind for ind in indicators), "Should report X-Forwarded-For header"
        
    print("✓ X-Forwarded-For header detection works correctly")


def test_x_cache_header_detection():
    """Test detection of X-Cache header with proxy indicators"""
    print("\n=== Test: X-Cache Header Detection ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Test case 1: X-Cache with proxy indicator
    mock_response_proxy = Mock()
    mock_response_proxy.headers = {
        'X-Cache': 'HIT from proxy.isp.com'
    }
    
    with patch('dns_blocking.requests.head', return_value=mock_response_proxy):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected (with 'proxy' keyword): {proxy_detected}")
        print(f"Indicators: {indicators}")
        
        assert proxy_detected, "Should detect proxy from X-Cache with 'proxy' keyword"
        assert any('X-Cache' in ind for ind in indicators), "Should report X-Cache header"
    
    # Test case 2: X-Cache without proxy indicator (CDN)
    mock_response_cdn = Mock()
    mock_response_cdn.headers = {
        'X-Cache': 'HIT from cloudfront'
    }
    
    with patch('dns_blocking.requests.head', return_value=mock_response_cdn):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected (CDN without 'proxy'): {proxy_detected}")
        
        # Should report X-Cache but not flag as proxy (CDN behavior)
        assert any('X-Cache' in ind for ind in indicators), "Should report X-Cache header"
        
    print("✓ X-Cache header detection works correctly")


def test_multiple_proxy_headers():
    """Test detection when multiple proxy headers are present"""
    print("\n=== Test: Multiple Proxy Headers ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock HTTP response with multiple proxy headers
    mock_response = Mock()
    mock_response.headers = {
        'Via': '1.1 proxy.isp.com',
        'X-Forwarded-For': '203.0.113.1',
        'X-Forwarded-Host': 'example.com',
        'X-Real-IP': '203.0.113.1'
    }
    
    with patch('dns_blocking.requests.head', return_value=mock_response):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected: {proxy_detected}")
        print(f"Number of Indicators: {len(indicators)}")
        print(f"Indicators: {indicators}")
        
        assert proxy_detected, "Should detect proxy from multiple headers"
        assert len(indicators) >= 3, "Should report multiple proxy headers"
        
    print("✓ Multiple proxy header detection works correctly")


def test_no_proxy_headers():
    """Test when no proxy headers are present"""
    print("\n=== Test: No Proxy Headers ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock HTTP response with no proxy headers
    mock_response = Mock()
    mock_response.headers = {
        'Content-Type': 'text/html',
        'Server': 'nginx'
    }
    
    with patch('dns_blocking.requests.head', return_value=mock_response):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected: {proxy_detected}")
        print(f"Indicators: {indicators}")
        
        assert not proxy_detected, "Should NOT detect proxy when no proxy headers present"
        
    print("✓ No proxy header detection works correctly")


def test_http_redirect_to_blocking_page():
    """Test detection of HTTP redirects to ISP warning pages"""
    print("\n=== Test: HTTP Redirect to Blocking Page ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock redirect to ISP blocking page
    mock_response = Mock()
    mock_response.url = 'http://isp.com/blocked?url=example.com'
    mock_response.history = [Mock(url='http://example.com')]
    
    with patch('dns_blocking.requests.get', return_value=mock_response):
        redirect_detected, details = detect_http_redirects('http://example.com')
        
        print(f"Redirect Detected: {redirect_detected}")
        print(f"Details: {details}")
        
        assert redirect_detected, "Should detect redirect to blocking page"
        assert any('blocked' in detail.lower() for detail in details), "Should identify 'blocked' keyword"
        
    print("✓ HTTP redirect to blocking page detection works correctly")


def test_http_redirect_domain_change():
    """Test detection of redirects that change domain"""
    print("\n=== Test: HTTP Redirect Domain Change ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock redirect to different domain
    mock_response = Mock()
    mock_response.url = 'http://warning.isp.com/page.html'
    mock_response.history = [Mock(url='http://example.com')]
    
    with patch('dns_blocking.requests.get', return_value=mock_response):
        redirect_detected, details = detect_http_redirects('http://example.com')
        
        print(f"Redirect Detected: {redirect_detected}")
        print(f"Details: {details}")
        
        assert redirect_detected, "Should detect domain change in redirect"
        assert any('Domain changed' in detail for detail in details), "Should report domain change"
        
    print("✓ HTTP redirect domain change detection works correctly")


def test_no_http_redirect():
    """Test when no redirect occurs"""
    print("\n=== Test: No HTTP Redirect ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock response with no redirect
    mock_response = Mock()
    mock_response.url = 'http://example.com'
    mock_response.history = []
    
    with patch('dns_blocking.requests.get', return_value=mock_response):
        redirect_detected, details = detect_http_redirects('http://example.com')
        
        print(f"Redirect Detected: {redirect_detected}")
        
        assert not redirect_detected, "Should NOT detect redirect when none occurs"
        
    print("✓ No redirect detection works correctly")


def test_connection_ip_matches_dns():
    """Test when connection IP matches DNS resolution"""
    print("\n=== Test: Connection IP Matches DNS ===")
    
    dns_ips = ['93.184.216.34', '93.184.216.35']
    
    # Mock socket connection
    mock_socket = MagicMock()
    mock_socket.getpeername.return_value = ('93.184.216.34', 443)
    
    with patch('dns_blocking.socket.socket', return_value=mock_socket):
        mismatch, connection_ip, details = compare_dns_and_connection_ip('example.com', dns_ips)
        
        print(f"Mismatch Detected: {mismatch}")
        print(f"Connection IP: {connection_ip}")
        print(f"Details: {details}")
        
        assert not mismatch, "Should NOT detect mismatch when IPs match"
        assert connection_ip == '93.184.216.34', "Should capture connection IP"
        
    print("✓ Connection IP match detection works correctly")


def test_connection_ip_differs_from_dns():
    """Test when connection IP differs from DNS (transparent proxy)"""
    print("\n=== Test: Connection IP Differs from DNS ===")
    
    dns_ips = ['93.184.216.34']
    
    # Mock socket connection to different IP
    mock_socket = MagicMock()
    mock_socket.getpeername.return_value = ('203.0.113.1', 443)  # Different IP
    
    with patch('dns_blocking.socket.socket', return_value=mock_socket):
        mismatch, connection_ip, details = compare_dns_and_connection_ip('example.com', dns_ips)
        
        print(f"Mismatch Detected: {mismatch}")
        print(f"Connection IP: {connection_ip}")
        print(f"Details: {details}")
        
        assert mismatch, "Should detect mismatch when IPs differ"
        assert connection_ip == '203.0.113.1', "Should capture actual connection IP"
        assert any('transparent proxy' in detail.lower() for detail in details), "Should mention transparent proxy"
        
    print("✓ Connection IP mismatch detection works correctly")


def test_comprehensive_proxy_analysis():
    """Test comprehensive transparent proxy detection combining all methods"""
    print("\n=== Test: Comprehensive Proxy Analysis ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    hostname = 'example.com'
    url = 'http://example.com'
    dns_ips = ['93.184.216.34']
    
    # Mock HTTP response with proxy headers
    mock_http_response = Mock()
    mock_http_response.headers = {
        'Via': '1.1 proxy.isp.com',
        'X-Forwarded-For': '203.0.113.1'
    }
    
    # Mock redirect response
    mock_redirect_response = Mock()
    mock_redirect_response.url = url
    mock_redirect_response.history = []
    
    # Mock socket connection to different IP
    mock_socket = MagicMock()
    mock_socket.getpeername.return_value = ('203.0.113.1', 443)
    
    with patch('dns_blocking.requests.head', return_value=mock_http_response), \
         patch('dns_blocking.requests.get', return_value=mock_redirect_response), \
         patch('dns_blocking.socket.socket', return_value=mock_socket):
        
        proxy_detected, indicators, proxy_ip = analyze_transparent_proxy(hostname, url, dns_ips)
        
        print(f"Proxy Detected: {proxy_detected}")
        print(f"Number of Indicators: {len(indicators)}")
        print(f"Proxy IP: {proxy_ip}")
        print(f"Indicators: {indicators}")
        
        assert proxy_detected, "Should detect proxy from combined analysis"
        assert len(indicators) > 0, "Should have multiple indicators"
        assert proxy_ip is not None, "Should capture proxy IP"
        
    print("✓ Comprehensive proxy analysis works correctly")


def test_http_request_timeout_handling():
    """Test graceful handling of HTTP request timeouts"""
    print("\n=== Test: HTTP Request Timeout Handling ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock timeout exception
    import requests
    with patch('dns_blocking.requests.head', side_effect=requests.exceptions.Timeout):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected: {proxy_detected}")
        print(f"Indicators: {indicators}")
        
        assert not proxy_detected, "Should NOT detect proxy on timeout"
        assert any('timeout' in ind.lower() for ind in indicators), "Should report timeout"
        
    print("✓ HTTP timeout handling works correctly")


def test_http_request_error_handling():
    """Test graceful handling of HTTP request errors"""
    print("\n=== Test: HTTP Request Error Handling ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    # Mock connection error
    import requests
    with patch('dns_blocking.requests.head', side_effect=requests.exceptions.ConnectionError("Connection refused")):
        proxy_detected, indicators, connection_ip = detect_proxy_headers('http://example.com')
        
        print(f"Proxy Detected: {proxy_detected}")
        print(f"Indicators: {indicators}")
        
        assert not proxy_detected, "Should NOT detect proxy on connection error"
        assert any('failed' in ind.lower() for ind in indicators), "Should report error"
        
    print("✓ HTTP error handling works correctly")


if __name__ == "__main__":
    print("=" * 70)
    print("Transparent Proxy Detection Tests (Task 5.1)")
    print("=" * 70)
    
    if not REQUESTS_AVAILABLE:
        print("\n⚠️ WARNING: requests library not available")
        print("Some tests will be skipped")
    
    try:
        test_via_header_detection()
        test_x_forwarded_for_header_detection()
        test_x_cache_header_detection()
        test_multiple_proxy_headers()
        test_no_proxy_headers()
        test_http_redirect_to_blocking_page()
        test_http_redirect_domain_change()
        test_no_http_redirect()
        test_connection_ip_matches_dns()
        test_connection_ip_differs_from_dns()
        test_comprehensive_proxy_analysis()
        test_http_request_timeout_handling()
        test_http_request_error_handling()
        
        print("\n" + "=" * 70)
        print("✓ All transparent proxy detection tests passed!")
        print("=" * 70)
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
