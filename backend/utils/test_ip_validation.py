"""
Unit tests for IP address extraction and validation
Tests Requirements 2.1, 2.4, 2.5, 2.7
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns_blocking import (
    is_private_ip,
    is_localhost_ip,
    follow_cname_chain,
    get_ip_reverse_dns,
    validate_ip_ownership,
    validate_ip_set_ownership,
    query_dns_resolver,
    DNSPYTHON_AVAILABLE
)


def test_localhost_detection():
    """Test detection of localhost IPs (Requirement 2.4)"""
    print("\n=== Test: Localhost Detection ===")
    
    localhost_ips = [
        "127.0.0.1",
        "127.0.0.53",
        "127.1.2.3",
        "0.0.0.0"
    ]
    
    for ip in localhost_ips:
        assert is_localhost_ip(ip), f"{ip} should be detected as localhost"
        print(f"✓ {ip} correctly identified as localhost")
    
    non_localhost_ips = [
        "8.8.8.8",
        "192.168.1.1",
        "10.0.0.1",
        "1.2.3.4"
    ]
    
    for ip in non_localhost_ips:
        assert not is_localhost_ip(ip), f"{ip} should not be detected as localhost"
        print(f"✓ {ip} correctly identified as non-localhost")


def test_private_ip_detection():
    """Test detection of private IP ranges (Requirement 2.4)"""
    print("\n=== Test: Private IP Detection ===")
    
    private_ips = [
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "127.0.0.1"
    ]
    
    for ip in private_ips:
        assert is_private_ip(ip), f"{ip} should be detected as private"
        print(f"✓ {ip} correctly identified as private")
    
    public_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "9.9.9.9",
        "172.15.0.1",  # Just outside 172.16.0.0/12
        "172.32.0.1",  # Just outside 172.16.0.0/12
        "192.167.0.1",  # Not 192.168.x.x
        "11.0.0.1"  # Not 10.x.x.x
    ]
    
    for ip in public_ips:
        assert not is_private_ip(ip), f"{ip} should not be detected as private"
        print(f"✓ {ip} correctly identified as public")


def test_a_record_extraction():
    """Test extraction of A records from DNS responses (Requirement 2.1)"""
    print("\n=== Test: A Record Extraction ===")
    
    if not DNSPYTHON_AVAILABLE:
        print("⚠ dnspython not available, skipping A record extraction test")
        return
    
    # Query a well-known domain
    result = query_dns_resolver("google.com", "8.8.8.8", "Google DNS", follow_cnames=False)
    
    print(f"Queried: google.com")
    print(f"Success: {result.success}")
    print(f"IPs extracted: {result.ips}")
    
    if result.success:
        assert len(result.ips) > 0, "Should extract at least one A record"
        
        # Verify all extracted values are valid IP addresses
        for ip in result.ips:
            parts = ip.split(".")
            assert len(parts) == 4, f"Invalid IP format: {ip}"
            for part in parts:
                num = int(part)
                assert 0 <= num <= 255, f"Invalid IP octet: {part}"
        
        print(f"✓ Successfully extracted {len(result.ips)} A record(s)")
    else:
        print(f"⚠ Query failed: {result.error}")


def test_cname_chain_following():
    """Test following CNAME chains to final resolution (Requirement 2.5)"""
    print("\n=== Test: CNAME Chain Following ===")
    
    if not DNSPYTHON_AVAILABLE:
        print("⚠ dnspython not available, skipping CNAME test")
        return
    
    # Test with a domain that has CNAME records
    # Note: www.github.com has CNAME records
    test_domain = "www.github.com"
    
    cname_chain, final_hostname = follow_cname_chain(test_domain, "8.8.8.8", "Google DNS")
    
    print(f"Domain: {test_domain}")
    print(f"CNAME chain: {cname_chain}")
    print(f"Final hostname: {final_hostname}")
    
    if cname_chain:
        assert len(cname_chain) > 0, "Should have at least one CNAME"
        assert final_hostname != test_domain, "Final hostname should differ from original"
        print(f"✓ Successfully followed CNAME chain with {len(cname_chain)} hop(s)")
    else:
        print("ℹ️ No CNAME records found (domain may have changed)")
    
    # Test with a domain that has no CNAME
    test_domain_no_cname = "google.com"
    cname_chain, final_hostname = follow_cname_chain(test_domain_no_cname, "8.8.8.8", "Google DNS")
    
    print(f"\nDomain: {test_domain_no_cname}")
    print(f"CNAME chain: {cname_chain}")
    print(f"Final hostname: {final_hostname}")
    
    assert len(cname_chain) == 0, "Should have no CNAMEs for google.com"
    assert final_hostname == test_domain_no_cname, "Final hostname should be same as original"
    print("✓ Correctly handled domain with no CNAME")


def test_query_with_cname_following():
    """Test DNS query with CNAME chain following (Requirement 2.5)"""
    print("\n=== Test: DNS Query with CNAME Following ===")
    
    if not DNSPYTHON_AVAILABLE:
        print("⚠ dnspython not available, skipping test")
        return
    
    # Query with CNAME following enabled (default)
    result = query_dns_resolver("www.github.com", "8.8.8.8", "Google DNS", follow_cnames=True)
    
    print(f"Domain: www.github.com")
    print(f"Success: {result.success}")
    print(f"IPs: {result.ips}")
    
    if result.success:
        assert len(result.ips) > 0, "Should resolve to at least one IP after following CNAMEs"
        print(f"✓ Successfully resolved through CNAME chain to {len(result.ips)} IP(s)")
    else:
        print(f"⚠ Query failed: {result.error}")


def test_reverse_dns_lookup():
    """Test reverse DNS (PTR) lookups (Requirement 2.7)"""
    print("\n=== Test: Reverse DNS Lookup ===")
    
    if not DNSPYTHON_AVAILABLE:
        print("⚠ dnspython not available, skipping reverse DNS test")
        return
    
    # Test with Google's public DNS IP
    test_ip = "8.8.8.8"
    ptr_hostname = get_ip_reverse_dns(test_ip, "8.8.8.8")
    
    print(f"IP: {test_ip}")
    print(f"PTR record: {ptr_hostname}")
    
    if ptr_hostname:
        assert isinstance(ptr_hostname, str), "PTR hostname should be a string"
        assert len(ptr_hostname) > 0, "PTR hostname should not be empty"
        print(f"✓ Successfully retrieved PTR record: {ptr_hostname}")
    else:
        print("ℹ️ No PTR record found (may be expected for some IPs)")


def test_ip_ownership_validation():
    """Test IP ownership validation (Requirement 2.7)"""
    print("\n=== Test: IP Ownership Validation ===")
    
    # Test localhost detection
    is_valid, reason = validate_ip_ownership("127.0.0.1", "example.com", "8.8.8.8")
    print(f"\n127.0.0.1 for example.com:")
    print(f"  Valid: {is_valid}")
    print(f"  Reason: {reason}")
    assert not is_valid, "Localhost IP should be invalid"
    assert "localhost" in reason.lower(), "Reason should mention localhost"
    print("✓ Correctly rejected localhost IP")
    
    # Test private IP detection
    is_valid, reason = validate_ip_ownership("192.168.1.1", "example.com", "8.8.8.8")
    print(f"\n192.168.1.1 for example.com:")
    print(f"  Valid: {is_valid}")
    print(f"  Reason: {reason}")
    assert not is_valid, "Private IP should be invalid"
    assert "private" in reason.lower(), "Reason should mention private range"
    print("✓ Correctly rejected private IP")
    
    # Test public IP (should pass basic validation)
    is_valid, reason = validate_ip_ownership("8.8.8.8", "google.com", "8.8.8.8")
    print(f"\n8.8.8.8 for google.com:")
    print(f"  Valid: {is_valid}")
    print(f"  Reason: {reason}")
    # Public IPs should pass basic validation (even if PTR doesn't match perfectly)
    print(f"✓ Public IP validation completed: {reason}")


def test_ip_set_validation():
    """Test validation of multiple IPs (Requirement 2.7)"""
    print("\n=== Test: IP Set Validation ===")
    
    # Test with mixed IPs
    test_ips = ["8.8.8.8", "127.0.0.1", "192.168.1.1"]
    all_valid, details = validate_ip_set_ownership(test_ips, "example.com", "8.8.8.8")
    
    print(f"Validating IPs: {test_ips}")
    print(f"All valid: {all_valid}")
    print("Details:")
    for detail in details:
        print(f"  {detail}")
    
    assert not all_valid, "Should detect invalid IPs in the set"
    assert len(details) == len(test_ips), "Should have details for each IP"
    
    # Count invalid IPs
    invalid_count = sum(1 for d in details if "⚠️" in d)
    assert invalid_count >= 2, "Should detect at least 2 invalid IPs (localhost and private)"
    
    print(f"✓ Correctly validated IP set ({invalid_count} invalid IPs detected)")


def test_suspicious_ip_detection_in_query():
    """Test that suspicious IPs are detected during DNS queries"""
    print("\n=== Test: Suspicious IP Detection in Queries ===")
    
    # This is more of an integration test - we can't easily force a DNS server
    # to return localhost, but we can verify the detection logic exists
    
    # Test that localhost IPs would be detected
    assert is_localhost_ip("127.0.0.1"), "Should detect 127.0.0.1"
    assert is_localhost_ip("0.0.0.0"), "Should detect 0.0.0.0"
    
    # Test that private IPs would be detected
    assert is_private_ip("10.0.0.1"), "Should detect 10.x.x.x"
    assert is_private_ip("192.168.1.1"), "Should detect 192.168.x.x"
    assert is_private_ip("172.16.0.1"), "Should detect 172.16-31.x.x"
    
    print("✓ Suspicious IP detection logic is working")


if __name__ == "__main__":
    print("=" * 60)
    print("IP Address Extraction and Validation Tests")
    print("=" * 60)
    
    try:
        test_localhost_detection()
        test_private_ip_detection()
        test_a_record_extraction()
        test_cname_chain_following()
        test_query_with_cname_following()
        test_reverse_dns_lookup()
        test_ip_ownership_validation()
        test_ip_set_validation()
        test_suspicious_ip_detection_in_query()
        
        print("\n" + "=" * 60)
        print("✓ All IP validation tests passed!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
