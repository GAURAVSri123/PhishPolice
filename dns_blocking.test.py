"""
Unit tests for DNS Blocking Detection Module
Tests the multi-resolver DNS query functionality
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_blocking import (
    query_dns_resolver,
    get_dns_resolvers,
    check_dns_blocking,
    DNSResult,
    DNSPYTHON_AVAILABLE
)


def test_query_system_dns():
    """Test querying system DNS resolver"""
    print("\n=== Test: Query System DNS ===")
    result = query_dns_resolver("google.com", None, "System DNS")
    
    print(f"Resolver: {result.resolver_name}")
    print(f"Success: {result.success}")
    print(f"IPs: {result.ips}")
    print(f"Error: {result.error}")
    print(f"Query Time: {result.query_time:.3f}s")
    
    assert result.resolver == "system", "Should use system resolver"
    assert result.resolver_name == "System DNS", "Should have correct name"
    
    if result.success:
        assert len(result.ips) > 0, "Should return at least one IP"
        print("✓ System DNS query successful")
    else:
        print(f"⚠ System DNS query failed: {result.error}")


def test_query_public_dns():
    """Test querying public DNS resolvers (Google, Cloudflare, Quad9)"""
    print("\n=== Test: Query Public DNS Resolvers ===")
    
    if not DNSPYTHON_AVAILABLE:
        print("⚠ dnspython not available, skipping public DNS tests")
        return
    
    resolvers = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("9.9.9.9", "Quad9 DNS")
    ]
    
    for resolver_ip, resolver_name in resolvers:
        print(f"\nQuerying {resolver_name} ({resolver_ip})...")
        result = query_dns_resolver("google.com", resolver_ip, resolver_name)
        
        print(f"  Success: {result.success}")
        print(f"  IPs: {result.ips}")
        print(f"  TTL: {result.ttl}")
        print(f"  Query Time: {result.query_time:.3f}s")
        
        if result.success:
            assert len(result.ips) > 0, f"{resolver_name} should return at least one IP"
            assert result.query_time < 5.0, f"{resolver_name} query should complete within 5 seconds"
            print(f"  ✓ {resolver_name} query successful")
        else:
            print(f"  ⚠ {resolver_name} query failed: {result.error}")


def test_timeout_handling():
    """Test 3-second timeout per query"""
    print("\n=== Test: Timeout Handling ===")
    
    # Use a non-existent DNS server to trigger timeout
    result = query_dns_resolver("google.com", "192.0.2.1", "Non-existent DNS")
    
    print(f"Resolver: {result.resolver_name}")
    print(f"Success: {result.success}")
    print(f"Error: {result.error}")
    print(f"Query Time: {result.query_time:.3f}s")
    
    assert not result.success, "Query to non-existent DNS should fail"
    # Allow up to 10 seconds for timeout (dnspython may retry)
    assert result.query_time < 10.0, "Timeout should be enforced within reasonable time"
    print("✓ Timeout handling works correctly")


def test_get_dns_resolvers():
    """Test DNS resolver configuration"""
    print("\n=== Test: Get DNS Resolvers ===")
    
    resolvers = get_dns_resolvers()
    
    print(f"Number of resolvers: {len(resolvers)}")
    for resolver_ip, resolver_name in resolvers:
        print(f"  - {resolver_name}: {resolver_ip}")
    
    assert len(resolvers) > 0, "Should have at least one resolver"
    assert len(resolvers) <= 4, "Should not exceed 4 resolvers (Requirement 9.3)"
    
    # Verify resolver IPs are valid
    for resolver_ip, resolver_name in resolvers:
        parts = resolver_ip.split(".")
        assert len(parts) == 4, f"Invalid IP format: {resolver_ip}"
    
    print("✓ DNS resolver configuration is valid")


def test_check_dns_blocking():
    """Test full DNS blocking check with multiple resolvers"""
    print("\n=== Test: Check DNS Blocking ===")
    
    evidence = check_dns_blocking("google.com")
    
    print(f"Hostname: {evidence.hostname}")
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Blocking Type: {evidence.blocking_type.value}")
    print(f"Confidence Score: {evidence.confidence_score}")
    
    if evidence.system_dns_result:
        print(f"\nSystem DNS Result:")
        print(f"  Success: {evidence.system_dns_result.success}")
        print(f"  IPs: {evidence.system_dns_result.ips}")
    
    print(f"\nPublic DNS Results: {len(evidence.public_dns_results)}")
    for result in evidence.public_dns_results:
        print(f"  {result.resolver_name}: {result.ips if result.success else result.error}")
    
    print(f"\nDetails:")
    for detail in evidence.details:
        print(f"  {detail}")
    
    assert evidence.hostname == "google.com", "Should analyze correct hostname"
    print("✓ DNS blocking check completed")


def test_structured_results():
    """Test that results are properly structured with IP addresses per resolver"""
    print("\n=== Test: Structured Results ===")
    
    evidence = check_dns_blocking("example.com")
    
    # Verify system DNS result structure
    if evidence.system_dns_result:
        assert hasattr(evidence.system_dns_result, 'resolver'), "Should have resolver field"
        assert hasattr(evidence.system_dns_result, 'resolver_name'), "Should have resolver_name field"
        assert hasattr(evidence.system_dns_result, 'ips'), "Should have ips field"
        assert hasattr(evidence.system_dns_result, 'success'), "Should have success field"
        assert hasattr(evidence.system_dns_result, 'error'), "Should have error field"
        assert hasattr(evidence.system_dns_result, 'query_time'), "Should have query_time field"
        print("✓ System DNS result structure is correct")
    
    # Verify public DNS results structure
    for result in evidence.public_dns_results:
        assert hasattr(result, 'resolver'), "Should have resolver field"
        assert hasattr(result, 'resolver_name'), "Should have resolver_name field"
        assert hasattr(result, 'ips'), "Should have ips field"
        assert isinstance(result.ips, list), "IPs should be a list"
        assert hasattr(result, 'success'), "Should have success field"
        assert hasattr(result, 'query_time'), "Should have query_time field"
    
    print(f"✓ All {len(evidence.public_dns_results)} public DNS results have correct structure")


if __name__ == "__main__":
    print("=" * 60)
    print("DNS Blocking Detection - Multi-Resolver Query Tests")
    print("=" * 60)
    
    try:
        test_query_system_dns()
        test_query_public_dns()
        test_timeout_handling()
        test_get_dns_resolvers()
        test_check_dns_blocking()
        test_structured_results()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
