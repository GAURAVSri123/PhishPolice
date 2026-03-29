"""
Unit tests for DNS response comparison logic (Task 2.2)
Tests the comparison of IP addresses from different resolvers
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_blocking import (
    compare_ip_sets,
    analyze_dns_results,
    DNSResult,
    DNSBlockingEvidence,
    BlockingType
)


def test_identical_ips():
    """Test that identical IPs from all resolvers are not flagged"""
    print("\n=== Test: Identical IPs ===")
    
    system_ips = {'93.184.216.34'}
    public_ips = {'93.184.216.34'}
    
    is_suspicious, confidence = compare_ip_sets(system_ips, public_ips)
    
    print(f"System IPs: {system_ips}")
    print(f"Public IPs: {public_ips}")
    print(f"Suspicious: {is_suspicious}, Confidence: {confidence}")
    
    assert not is_suspicious, "Identical IPs should not be flagged as suspicious"
    assert confidence == 0, "Confidence should be 0 for identical IPs"
    print("✓ Identical IPs correctly identified as legitimate")


def test_subset_ips():
    """Test that subset relationships are not flagged (normal for CDN)"""
    print("\n=== Test: Subset IPs ===")
    
    # System returns subset of public IPs
    system_ips = {'93.184.216.34'}
    public_ips = {'93.184.216.34', '93.184.216.35'}
    
    is_suspicious, confidence = compare_ip_sets(system_ips, public_ips)
    
    print(f"System IPs: {system_ips}")
    print(f"Public IPs: {public_ips}")
    print(f"Suspicious: {is_suspicious}, Confidence: {confidence}")
    
    assert not is_suspicious, "Subset IPs should not be flagged as suspicious"
    print("✓ Subset relationship correctly identified as legitimate")


def test_overlapping_ips():
    """Test that overlapping IPs are not flagged"""
    print("\n=== Test: Overlapping IPs ===")
    
    system_ips = {'93.184.216.34', '93.184.216.35'}
    public_ips = {'93.184.216.34', '93.184.216.36'}
    
    is_suspicious, confidence = compare_ip_sets(system_ips, public_ips)
    
    print(f"System IPs: {system_ips}")
    print(f"Public IPs: {public_ips}")
    print(f"Suspicious: {is_suspicious}, Confidence: {confidence}")
    
    assert not is_suspicious, "Overlapping IPs should not be flagged as suspicious"
    print("✓ Overlapping IPs correctly identified as legitimate")


def test_same_subnet_24():
    """Test that IPs in same /24 subnet are not flagged"""
    print("\n=== Test: Same /24 Subnet ===")
    
    system_ips = {'192.168.1.10'}
    public_ips = {'192.168.1.20', '192.168.1.30'}
    
    is_suspicious, confidence = compare_ip_sets(system_ips, public_ips)
    
    print(f"System IPs: {system_ips}")
    print(f"Public IPs: {public_ips}")
    print(f"Suspicious: {is_suspicious}, Confidence: {confidence}")
    
    assert not is_suspicious, "Same /24 subnet should not be flagged as suspicious"
    print("✓ Same /24 subnet correctly identified as legitimate")


def test_same_subnet_16():
    """Test that IPs in same /16 subnet are not flagged (CDN behavior)"""
    print("\n=== Test: Same /16 Subnet (CDN) ===")
    
    # Google's IP range example
    system_ips = {'142.250.67.78'}
    public_ips = {'142.250.183.206', '142.251.43.174'}
    
    is_suspicious, confidence = compare_ip_sets(system_ips, public_ips)
    
    print(f"System IPs: {system_ips}")
    print(f"Public IPs: {public_ips}")
    print(f"Suspicious: {is_suspicious}, Confidence: {confidence}")
    
    assert not is_suspicious, "Same /16 subnet should not be flagged as suspicious"
    print("✓ Same /16 subnet correctly identified as legitimate CDN behavior")


def test_completely_different_ips():
    """Test that completely different IPs are flagged as suspicious"""
    print("\n=== Test: Completely Different IPs ===")
    
    # System returns completely different IP range
    system_ips = {'127.0.0.1'}
    public_ips = {'93.184.216.34'}
    
    is_suspicious, confidence = compare_ip_sets(system_ips, public_ips)
    
    print(f"System IPs: {system_ips}")
    print(f"Public IPs: {public_ips}")
    print(f"Suspicious: {is_suspicious}, Confidence: {confidence}")
    
    assert is_suspicious, "Completely different IPs should be flagged as suspicious"
    assert confidence > 0, "Confidence should be > 0 for suspicious IPs"
    print(f"✓ Completely different IPs correctly flagged as suspicious (confidence: {confidence})")


def test_localhost_blocking():
    """Test detection of localhost redirect blocking"""
    print("\n=== Test: Localhost Blocking Detection ===")
    
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["127.0.0.1"],
        success=True,
        query_time=0.01
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],
            success=True,
            query_time=0.01
        )
    ]
    
    evidence = analyze_dns_results("example.com", system_result, public_results)
    
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Blocking Type: {evidence.blocking_type.value}")
    print(f"Confidence Score: {evidence.confidence_score}")
    print(f"Details: {evidence.details}")
    
    assert evidence.blocking_detected, "Localhost redirect should be detected"
    assert evidence.blocking_type == BlockingType.LOCALHOST_REDIRECT, "Should identify as localhost redirect"
    assert evidence.confidence_score >= 80, "Confidence should be high for localhost redirect"
    print("✓ Localhost blocking correctly detected")


def test_nxdomain_blocking():
    """Test detection of NXDOMAIN blocking"""
    print("\n=== Test: NXDOMAIN Blocking Detection ===")
    
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=[],
        success=False,
        error="NXDOMAIN: Domain does not exist",
        query_time=0.01
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],
            success=True,
            query_time=0.01
        )
    ]
    
    evidence = analyze_dns_results("blocked-site.com", system_result, public_results)
    
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Blocking Type: {evidence.blocking_type.value}")
    print(f"Confidence Score: {evidence.confidence_score}")
    print(f"NXDOMAIN Detected: {evidence.nxdomain_detected}")
    print(f"Details: {evidence.details}")
    
    assert evidence.blocking_detected, "NXDOMAIN blocking should be detected"
    assert evidence.nxdomain_detected, "NXDOMAIN flag should be set"
    assert evidence.blocking_type == BlockingType.NXDOMAIN, "Should identify as NXDOMAIN blocking"
    print("✓ NXDOMAIN blocking correctly detected")


def test_partial_resolver_failure():
    """Test handling of partial resolver failures"""
    print("\n=== Test: Partial Resolver Failure Handling ===")
    
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["93.184.216.34"],
        success=True,
        query_time=0.01
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],
            success=True,
            query_time=0.01
        ),
        DNSResult(
            resolver="1.1.1.1",
            resolver_name="Cloudflare DNS",
            ips=[],
            success=False,
            error="DNS query timeout",
            query_time=3.0
        )
    ]
    
    evidence = analyze_dns_results("example.com", system_result, public_results)
    
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"System DNS Success: {evidence.system_dns_result.success}")
    print(f"Public DNS Results: {len(evidence.public_dns_results)}")
    print(f"Successful Public Queries: {len([r for r in evidence.public_dns_results if r.success])}")
    print(f"Details: {evidence.details}")
    
    assert not evidence.blocking_detected, "Should not detect blocking when IPs match"
    assert len(evidence.public_dns_results) == 2, "Should record all resolver attempts"
    print("✓ Partial resolver failure handled correctly")


def test_all_resolvers_fail():
    """Test handling when all resolvers fail"""
    print("\n=== Test: All Resolvers Fail ===")
    
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=[],
        success=False,
        error="DNS resolution failed",
        query_time=0.01
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=[],
            success=False,
            error="DNS query timeout",
            query_time=3.0
        )
    ]
    
    evidence = analyze_dns_results("nonexistent.invalid", system_result, public_results)
    
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Details: {evidence.details}")
    
    assert not evidence.blocking_detected, "Should not detect blocking when all fail"
    assert "DNS analysis not possible" in evidence.details[0], "Should indicate analysis not possible"
    print("✓ All resolvers failure handled correctly")


def test_confidence_score_calculation():
    """Test that confidence scores are calculated appropriately"""
    print("\n=== Test: Confidence Score Calculation ===")
    
    test_cases = [
        {
            "name": "Localhost redirect",
            "system_ips": ["127.0.0.1"],
            "public_ips": ["93.184.216.34"],
            "expected_min_confidence": 80
        },
        {
            "name": "Completely different IPs",
            "system_ips": ["10.0.0.1"],
            "public_ips": ["93.184.216.34"],
            "expected_min_confidence": 50
        }
    ]
    
    for test_case in test_cases:
        print(f"\n  Testing: {test_case['name']}")
        
        system_result = DNSResult(
            resolver="system",
            resolver_name="System DNS",
            ips=test_case["system_ips"],
            success=True,
            query_time=0.01
        )
        
        public_results = [
            DNSResult(
                resolver="8.8.8.8",
                resolver_name="Google DNS",
                ips=test_case["public_ips"],
                success=True,
                query_time=0.01
            )
        ]
        
        evidence = analyze_dns_results("test.com", system_result, public_results)
        
        print(f"    Confidence Score: {evidence.confidence_score}")
        print(f"    Expected Min: {test_case['expected_min_confidence']}")
        
        if evidence.blocking_detected:
            assert evidence.confidence_score >= test_case["expected_min_confidence"], \
                f"Confidence score should be >= {test_case['expected_min_confidence']}"
            print(f"    ✓ Confidence score appropriate for {test_case['name']}")


if __name__ == "__main__":
    print("=" * 60)
    print("DNS Response Comparison Logic Tests (Task 2.2)")
    print("=" * 60)
    
    try:
        # Test IP comparison logic
        test_identical_ips()
        test_subset_ips()
        test_overlapping_ips()
        test_same_subnet_24()
        test_same_subnet_16()
        test_completely_different_ips()
        
        # Test blocking detection scenarios
        test_localhost_blocking()
        test_nxdomain_blocking()
        
        # Test error handling
        test_partial_resolver_failure()
        test_all_resolvers_fail()
        
        # Test confidence scoring
        test_confidence_score_calculation()
        
        print("\n" + "=" * 60)
        print("✓ All DNS comparison tests passed!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
