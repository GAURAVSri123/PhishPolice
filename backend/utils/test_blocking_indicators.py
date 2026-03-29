"""
Unit tests for DNS Blocking Indicator Detection (Task 3.2)
Tests NXDOMAIN detection, low TTL detection, known blocking IPs, and suspicious patterns
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_blocking import (
    DNSResult,
    DNSBlockingEvidence,
    BlockingType,
    analyze_dns_results,
    KNOWN_BLOCKING_IPS,
    is_localhost_ip,
    is_private_ip
)


def test_nxdomain_detection():
    """Test detection of NXDOMAIN responses indicating potential blocking"""
    print("\n=== Test: NXDOMAIN Detection ===")
    
    # Create system DNS result with NXDOMAIN error
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        success=False,
        error="NXDOMAIN: Domain does not exist"
    )
    
    # Create successful public DNS results
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],
            success=True,
            ttl=300
        )
    ]
    
    evidence = analyze_dns_results("example.com", system_result, public_results)
    
    print(f"NXDOMAIN Detected: {evidence.nxdomain_detected}")
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Blocking Type: {evidence.blocking_type.value}")
    print(f"Confidence Score: {evidence.confidence_score}")
    print(f"Details: {evidence.details}")
    
    assert evidence.nxdomain_detected, "Should detect NXDOMAIN"
    assert evidence.blocking_detected, "Should detect blocking when public DNS succeeds"
    assert evidence.blocking_type == BlockingType.NXDOMAIN, "Should identify NXDOMAIN blocking type"
    assert evidence.confidence_score == 70, "Should have confidence score of 70"
    
    print("✓ NXDOMAIN detection works correctly")


def test_low_ttl_detection():
    """Test identification of unusually low TTL values (< 60 seconds)"""
    print("\n=== Test: Low TTL Detection ===")
    
    # Test case 1: Very low TTL (30 seconds)
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["192.0.2.1"],
        success=True,
        ttl=30
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["192.0.2.1"],
            success=True,
            ttl=300
        )
    ]
    
    evidence = analyze_dns_results("test.com", system_result, public_results)
    
    print(f"Low TTL Detected: {evidence.low_ttl_detected}")
    print(f"TTL Value: {system_result.ttl}")
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Confidence Score: {evidence.confidence_score}")
    
    assert evidence.low_ttl_detected, "Should detect low TTL (30 seconds)"
    assert evidence.blocking_detected, "Should flag as potential blocking"
    assert evidence.confidence_score >= 40, "Should have confidence score >= 40"
    
    # Test case 2: Borderline TTL (59 seconds - should trigger)
    system_result_59 = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["192.0.2.2"],
        success=True,
        ttl=59
    )
    
    evidence_59 = analyze_dns_results("test2.com", system_result_59, public_results)
    
    print(f"\nBorderline TTL (59s) Detected: {evidence_59.low_ttl_detected}")
    assert evidence_59.low_ttl_detected, "Should detect TTL of 59 seconds"
    
    # Test case 3: Normal TTL (60 seconds - should NOT trigger)
    system_result_60 = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["192.0.2.3"],
        success=True,
        ttl=60
    )
    
    evidence_60 = analyze_dns_results("test3.com", system_result_60, public_results)
    
    print(f"Normal TTL (60s) Detected as Low: {evidence_60.low_ttl_detected}")
    assert not evidence_60.low_ttl_detected, "Should NOT detect TTL of 60 seconds as low"
    
    # Test case 4: High TTL (300 seconds - should NOT trigger)
    system_result_300 = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["192.0.2.4"],
        success=True,
        ttl=300
    )
    
    evidence_300 = analyze_dns_results("test4.com", system_result_300, public_results)
    
    print(f"High TTL (300s) Detected as Low: {evidence_300.low_ttl_detected}")
    assert not evidence_300.low_ttl_detected, "Should NOT detect TTL of 300 seconds as low"
    
    print("✓ Low TTL detection works correctly")


def test_known_blocking_ip_detection():
    """Test checking for known ISP blocking page IP addresses"""
    print("\n=== Test: Known Blocking IP Detection ===")
    
    # Test localhost blocking (127.0.0.1)
    system_result_localhost = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["127.0.0.1"],
        success=True,
        ttl=300
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],
            success=True,
            ttl=300
        )
    ]
    
    evidence_localhost = analyze_dns_results("blocked.com", system_result_localhost, public_results)
    
    print(f"Localhost IP Detected: {evidence_localhost.blocking_detected}")
    print(f"Blocking Type: {evidence_localhost.blocking_type.value}")
    print(f"Confidence Score: {evidence_localhost.confidence_score}")
    
    assert evidence_localhost.blocking_detected, "Should detect localhost blocking"
    assert evidence_localhost.blocking_type == BlockingType.LOCALHOST_REDIRECT, "Should identify localhost redirect"
    assert evidence_localhost.confidence_score == 90, "Should have high confidence (90)"
    
    # Test null route blocking (0.0.0.0)
    system_result_null = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["0.0.0.0"],
        success=True,
        ttl=300
    )
    
    evidence_null = analyze_dns_results("blocked2.com", system_result_null, public_results)
    
    print(f"\nNull Route IP Detected: {evidence_null.blocking_detected}")
    assert evidence_null.blocking_detected, "Should detect null route blocking"
    
    # Test systemd-resolved blocking (127.0.0.53)
    system_result_systemd = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["127.0.0.53"],
        success=True,
        ttl=300
    )
    
    evidence_systemd = analyze_dns_results("blocked3.com", system_result_systemd, public_results)
    
    print(f"systemd-resolved Block Detected: {evidence_systemd.blocking_detected}")
    assert evidence_systemd.blocking_detected, "Should detect systemd-resolved blocking"
    
    print("✓ Known blocking IP detection works correctly")


def test_private_ip_detection():
    """Test detection of private IP ranges"""
    print("\n=== Test: Private IP Detection ===")
    
    # Test 10.0.0.0/8 range
    system_result_10 = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["10.1.2.3"],
        success=True,
        ttl=300
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],
            success=True,
            ttl=300
        )
    ]
    
    evidence_10 = analyze_dns_results("internal.com", system_result_10, public_results)
    
    print(f"Private IP (10.x) Detected: {evidence_10.private_ip_detected}")
    print(f"Blocking Detected: {evidence_10.blocking_detected}")
    
    assert evidence_10.private_ip_detected, "Should detect 10.x private IP"
    assert evidence_10.blocking_detected, "Should flag as potential blocking"
    
    # Test 192.168.0.0/16 range
    system_result_192 = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["192.168.1.1"],
        success=True,
        ttl=300
    )
    
    evidence_192 = analyze_dns_results("internal2.com", system_result_192, public_results)
    
    print(f"Private IP (192.168.x) Detected: {evidence_192.private_ip_detected}")
    assert evidence_192.private_ip_detected, "Should detect 192.168.x private IP"
    
    # Test 172.16.0.0/12 range
    system_result_172 = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["172.16.0.1"],
        success=True,
        ttl=300
    )
    
    evidence_172 = analyze_dns_results("internal3.com", system_result_172, public_results)
    
    print(f"Private IP (172.16.x) Detected: {evidence_172.private_ip_detected}")
    assert evidence_172.private_ip_detected, "Should detect 172.16.x private IP"
    
    print("✓ Private IP detection works correctly")


def test_suspicious_pattern_detection():
    """Test detection of suspicious DNS response patterns"""
    print("\n=== Test: Suspicious Pattern Detection ===")
    
    # Test completely different IP ranges (no overlap)
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["203.0.113.1"],  # TEST-NET-3 range
        success=True,
        ttl=300
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],  # Completely different range
            success=True,
            ttl=300
        )
    ]
    
    evidence = analyze_dns_results("suspicious.com", system_result, public_results)
    
    print(f"IP Discrepancies: {evidence.ip_discrepancies}")
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Blocking Type: {evidence.blocking_type.value}")
    print(f"Confidence Score: {evidence.confidence_score}")
    
    assert len(evidence.ip_discrepancies) > 0, "Should detect IP discrepancies"
    assert evidence.blocking_detected, "Should detect suspicious pattern"
    assert evidence.blocking_type == BlockingType.DNS_HIJACK, "Should identify as DNS hijack"
    
    print("✓ Suspicious pattern detection works correctly")


def test_legitimate_cdn_not_flagged():
    """Test that legitimate CDN behavior is not flagged as blocking"""
    print("\n=== Test: Legitimate CDN Not Flagged ===")
    
    # Test case: System DNS returns subset of public DNS IPs (normal CDN behavior)
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["172.217.1.1"],  # One Google IP
        success=True,
        ttl=300
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["172.217.1.1", "172.217.1.2"],  # Multiple Google IPs
            success=True,
            ttl=300
        )
    ]
    
    evidence = analyze_dns_results("google.com", system_result, public_results)
    
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Details: {evidence.details}")
    
    # Should not flag as blocking since system IPs are subset of public IPs
    assert not evidence.blocking_detected, "Should NOT flag legitimate CDN as blocking"
    
    print("✓ Legitimate CDN behavior not flagged")


def test_combined_indicators():
    """Test detection when multiple blocking indicators are present"""
    print("\n=== Test: Combined Blocking Indicators ===")
    
    # Combine low TTL + IP discrepancy
    system_result = DNSResult(
        resolver="system",
        resolver_name="System DNS",
        ips=["203.0.113.1"],
        success=True,
        ttl=15  # Very low TTL
    )
    
    public_results = [
        DNSResult(
            resolver="8.8.8.8",
            resolver_name="Google DNS",
            ips=["93.184.216.34"],
            success=True,
            ttl=300
        )
    ]
    
    evidence = analyze_dns_results("suspicious.com", system_result, public_results)
    
    print(f"Low TTL Detected: {evidence.low_ttl_detected}")
    print(f"IP Discrepancies: {len(evidence.ip_discrepancies)}")
    print(f"Blocking Detected: {evidence.blocking_detected}")
    print(f"Confidence Score: {evidence.confidence_score}")
    
    assert evidence.low_ttl_detected, "Should detect low TTL"
    assert len(evidence.ip_discrepancies) > 0, "Should detect IP discrepancy"
    assert evidence.blocking_detected, "Should detect blocking"
    # Confidence should be higher due to multiple indicators
    assert evidence.confidence_score >= 60, "Should have higher confidence with multiple indicators"
    
    print("✓ Combined indicator detection works correctly")


def test_helper_functions():
    """Test helper functions for IP validation"""
    print("\n=== Test: Helper Functions ===")
    
    # Test is_localhost_ip
    assert is_localhost_ip("127.0.0.1"), "Should detect 127.0.0.1 as localhost"
    assert is_localhost_ip("127.0.0.53"), "Should detect 127.0.0.53 as localhost"
    assert is_localhost_ip("0.0.0.0"), "Should detect 0.0.0.0 as localhost"
    assert not is_localhost_ip("8.8.8.8"), "Should NOT detect 8.8.8.8 as localhost"
    
    # Test is_private_ip
    assert is_private_ip("10.0.0.1"), "Should detect 10.x as private"
    assert is_private_ip("192.168.1.1"), "Should detect 192.168.x as private"
    assert is_private_ip("172.16.0.1"), "Should detect 172.16.x as private"
    assert is_private_ip("127.0.0.1"), "Should detect 127.x as private"
    assert not is_private_ip("8.8.8.8"), "Should NOT detect 8.8.8.8 as private"
    assert not is_private_ip("93.184.216.34"), "Should NOT detect public IP as private"
    
    # Test KNOWN_BLOCKING_IPS dictionary
    assert "127.0.0.1" in KNOWN_BLOCKING_IPS, "Should have 127.0.0.1 in known blocking IPs"
    assert "0.0.0.0" in KNOWN_BLOCKING_IPS, "Should have 0.0.0.0 in known blocking IPs"
    
    print("✓ Helper functions work correctly")


if __name__ == "__main__":
    print("=" * 70)
    print("DNS Blocking Indicator Detection Tests (Task 3.2)")
    print("=" * 70)
    
    try:
        test_nxdomain_detection()
        test_low_ttl_detection()
        test_known_blocking_ip_detection()
        test_private_ip_detection()
        test_suspicious_pattern_detection()
        test_legitimate_cdn_not_flagged()
        test_combined_indicators()
        test_helper_functions()
        
        print("\n" + "=" * 70)
        print("✓ All blocking indicator detection tests passed!")
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
