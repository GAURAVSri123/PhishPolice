"""
Integration test for transparent proxy detection in check_dns_blocking
"""

import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_blocking import check_dns_blocking, REQUESTS_AVAILABLE


def test_check_dns_blocking_with_proxy_detection():
    """Test that check_dns_blocking integrates proxy detection correctly"""
    print("\n=== Integration Test: check_dns_blocking with Proxy Detection ===")
    
    if not REQUESTS_AVAILABLE:
        print("⚠️ Skipping test - requests library not available")
        return
    
    hostname = 'example.com'
    url = 'http://example.com'
    
    # Mock DNS resolution
    mock_dns_result = Mock()
    mock_dns_result.success = True
    mock_dns_result.ips = ['93.184.216.34']
    mock_dns_result.ttl = 300
    mock_dns_result.error = None
    
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
    
    # Mock socket connection
    mock_socket = MagicMock()
    mock_socket.getpeername.return_value = ('93.184.216.34', 443)
    
    with patch('dns_blocking.query_dns_resolver', return_value=mock_dns_result), \
         patch('dns_blocking.requests.head', return_value=mock_http_response), \
         patch('dns_blocking.requests.get', return_value=mock_redirect_response), \
         patch('dns_blocking.socket.socket', return_value=mock_socket):
        
        # Call check_dns_blocking with URL for proxy detection
        evidence = check_dns_blocking(hostname, url)
        
        print(f"Hostname: {evidence.hostname}")
        print(f"Transparent Proxy Detected: {evidence.transparent_proxy_detected}")
        print(f"Proxy Indicators: {evidence.proxy_indicators}")
        print(f"Blocking Detected: {evidence.blocking_detected}")
        print(f"Details: {evidence.details}")
        
        assert evidence.transparent_proxy_detected, "Should detect transparent proxy"
        assert len(evidence.proxy_indicators) > 0, "Should have proxy indicators"
        assert any('Via header' in ind for ind in evidence.proxy_indicators), "Should detect Via header"
        
    print("✓ Integration test passed")


def test_check_dns_blocking_without_url():
    """Test that check_dns_blocking works without URL (no proxy detection)"""
    print("\n=== Integration Test: check_dns_blocking without URL ===")
    
    hostname = 'example2.com'  # Use different hostname to avoid cache
    
    # Mock DNS resolution
    mock_dns_result = Mock()
    mock_dns_result.success = True
    mock_dns_result.ips = ['93.184.216.34']
    mock_dns_result.ttl = 300
    mock_dns_result.error = None
    
    with patch('dns_blocking.query_dns_resolver', return_value=mock_dns_result):
        # Call check_dns_blocking without URL (no proxy detection)
        evidence = check_dns_blocking(hostname)
        
        print(f"Hostname: {evidence.hostname}")
        print(f"Transparent Proxy Detected: {evidence.transparent_proxy_detected}")
        print(f"Blocking Detected: {evidence.blocking_detected}")
        
        # Should not perform proxy detection without URL
        assert not evidence.transparent_proxy_detected, "Should not detect proxy without URL"
        
    print("✓ Integration test passed")


if __name__ == "__main__":
    print("=" * 70)
    print("Integration Tests for Proxy Detection in check_dns_blocking")
    print("=" * 70)
    
    try:
        test_check_dns_blocking_with_proxy_detection()
        test_check_dns_blocking_without_url()
        
        print("\n" + "=" * 70)
        print("✓ All integration tests passed!")
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
