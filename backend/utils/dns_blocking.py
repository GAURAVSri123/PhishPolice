"""
DNS Blocking Detection Module
Detects DNS-based blocking, filtering, and manipulation by ISPs or network administrators.
Compares DNS responses from multiple resolvers to identify discrepancies.

IMPLEMENTATION NOTES:
- Uses dnspython library for DNS queries with custom resolver support
- Queries system DNS resolver (ISP-provided) and public DNS resolvers
- Implements 3-second timeout per query with graceful error handling
- Returns structured results with IP addresses per resolver

REQUIREMENTS COVERAGE:
- Requirement 7.1: Module structure in backend/utils/dns_blocking.py
- Requirement 7.2: check_dns_blocking(hostname) function
- Requirement 7.3: get_dns_blocking_risk_score(hostname) function  
- Requirement 7.4: format_dns_blocking_summary(dns_result) function
- Requirement 8.4: Comprehensive error handling
- Requirement 10.1-10.6: DNS resolver configuration management
"""

import sys
import socket
import time
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field
from enum import Enum

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False
    print("[DNS Blocking] Warning: dnspython not available, DNS resolver queries will be limited", file=sys.stderr)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[DNS Blocking] Warning: requests library not available, HTTP proxy detection will be limited", file=sys.stderr)

# DNS query timeout settings
DNS_QUERY_TIMEOUT = 3  # seconds per query (Requirement 8.4)
DNS_TOTAL_TIMEOUT = 5  # seconds for all queries (Requirement 1.6)

# DNS resolver configuration (Requirement 10.2)
DEFAULT_DNS_RESOLVERS = [
    ("8.8.8.8", "Google DNS"),
    ("1.1.1.1", "Cloudflare DNS"),
    ("9.9.9.9", "Quad9 DNS")
]

# Known ISP blocking page IPs (Requirement 4.1)
# This is a starter list - should be expanded based on real-world observations
KNOWN_BLOCKING_IPS = {
    "127.0.0.1": "Localhost Block",
    "0.0.0.0": "Null Route Block",
    "127.0.0.53": "systemd-resolved Block"
}

# Cache for DNS results (Requirement 9.1)
_dns_cache = {}
_cache_ttl = 300  # 5 minutes


class BlockingType(Enum):
    """Types of DNS blocking detected"""
    NONE = "none"
    ISP_FILTER = "isp_filter"
    DNS_HIJACK = "dns_hijack"
    TRANSPARENT_PROXY = "transparent_proxy"
    NXDOMAIN = "nxdomain"
    LOCALHOST_REDIRECT = "localhost_redirect"


@dataclass
class DNSResult:
    """Result from a single DNS resolver query"""
    resolver: str
    resolver_name: str
    ips: List[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None
    query_time: float = 0.0
    ttl: Optional[int] = None


@dataclass
class DNSBlockingEvidence:
    """
    Complete evidence structure for DNS blocking detection.
    Implements Requirement 5 (DNS Blocking Evidence Collection)
    """
    hostname: str
    blocking_detected: bool = False
    blocking_type: BlockingType = BlockingType.NONE
    confidence_score: int = 0  # 0-100
    
    # DNS query results from different resolvers
    system_dns_result: Optional[DNSResult] = None
    public_dns_results: List[DNSResult] = field(default_factory=list)
    
    # Detected discrepancies
    ip_discrepancies: List[str] = field(default_factory=list)
    blocking_ips_found: List[Tuple[str, str]] = field(default_factory=list)  # (IP, description)
    
    # ISP/blocking entity identification
    blocking_entity: Optional[str] = None
    
    # Proxy detection
    transparent_proxy_detected: bool = False
    proxy_indicators: List[str] = field(default_factory=list)
    
    # Additional evidence
    low_ttl_detected: bool = False
    nxdomain_detected: bool = False
    private_ip_detected: bool = False
    
    # Human-readable details
    details: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "hostname": self.hostname,
            "blocking_detected": self.blocking_detected,
            "blocking_type": self.blocking_type.value,
            "confidence_score": self.confidence_score,
            "blocking_entity": self.blocking_entity,
            "transparent_proxy_detected": self.transparent_proxy_detected,
            "low_ttl_detected": self.low_ttl_detected,
            "nxdomain_detected": self.nxdomain_detected,
            "private_ip_detected": self.private_ip_detected,
            "ip_discrepancies": self.ip_discrepancies,
            "blocking_ips_found": [{"ip": ip, "description": desc} for ip, desc in self.blocking_ips_found],
            "proxy_indicators": self.proxy_indicators,
            "details": self.details
        }


def get_system_dns() -> Optional[str]:
    """
    Get the system's default DNS resolver.
    Implements Requirement 1.2 (query system DNS resolver)
    """
    try:
        # On most systems, we can't directly get the DNS server
        # Instead, we'll use the system's default resolver by not specifying one
        # This is handled in query_dns_resolver by passing None
        return None
    except Exception as e:
        print(f"[DNS Blocking] Error getting system DNS: {e}", file=sys.stderr)
        return None


def validate_dns_resolver(resolver_ip: str) -> bool:
    """
    Validate DNS resolver IP address.
    Implements Requirement 10.5 (validate DNS resolver IPs)
    """
    try:
        # Check if it's a valid IPv4 address
        parts = resolver_ip.split(".")
        if len(parts) != 4:
            return False
        
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        
        return True
    except (ValueError, AttributeError):
        return False


def get_dns_resolvers() -> List[Tuple[str, str]]:
    """
    Get list of DNS resolvers to query.
    Implements Requirement 10.1-10.3 (configurable DNS resolvers)
    
    Returns list of (resolver_ip, resolver_name) tuples
    """
    resolvers = []
    
    # TODO: Add support for reading from environment variables (Requirement 10.1)
    # For now, use default public resolvers
    
    # Validate and add default resolvers
    for resolver_ip, resolver_name in DEFAULT_DNS_RESOLVERS:
        if validate_dns_resolver(resolver_ip):
            resolvers.append((resolver_ip, resolver_name))
        else:
            print(f"[DNS Blocking] Invalid resolver IP: {resolver_ip}", file=sys.stderr)
    
    # Limit to 4 resolvers max (Requirement 9.3)
    return resolvers[:4]


def follow_cname_chain(hostname: str, resolver_ip: Optional[str] = None, 
                       resolver_name: str = "System DNS", max_depth: int = 10) -> Tuple[List[str], Optional[str]]:
    """
    Follow CNAME chain to final resolution.
    Implements Requirement 2.5 (follow CNAME chains)
    
    Args:
        hostname: Domain name to resolve
        resolver_ip: DNS server IP (None for system default)
        resolver_name: Human-readable name for the resolver
        max_depth: Maximum CNAME chain depth to prevent infinite loops
    
    Returns:
        Tuple of (cname_chain, final_hostname)
        cname_chain: List of CNAMEs encountered
        final_hostname: Final hostname after following CNAMEs (None if error)
    """
    cname_chain = []
    current_hostname = hostname
    
    if not DNSPYTHON_AVAILABLE or not resolver_ip:
        # Can't follow CNAME chains without dnspython
        return (cname_chain, hostname)
    
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.timeout = DNS_QUERY_TIMEOUT
        resolver.lifetime = DNS_QUERY_TIMEOUT
        
        for _ in range(max_depth):
            try:
                # Query for CNAME records
                cname_answers = resolver.resolve(current_hostname, 'CNAME')
                
                # Extract CNAME target
                cname_target = str(cname_answers[0].target).rstrip('.')
                cname_chain.append(cname_target)
                
                print(f"[DNS Blocking] {resolver_name} CNAME: {current_hostname} -> {cname_target}", file=sys.stderr)
                
                current_hostname = cname_target
                
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # No more CNAMEs, we've reached the final hostname
                break
            except dns.exception.DNSException:
                # Error following CNAME chain
                break
        
        return (cname_chain, current_hostname)
        
    except Exception as e:
        print(f"[DNS Blocking] Error following CNAME chain: {e}", file=sys.stderr)
        return (cname_chain, hostname)


def query_dns_resolver(hostname: str, resolver_ip: Optional[str] = None, 
                       resolver_name: str = "System DNS", follow_cnames: bool = True) -> DNSResult:
    """
    Query a specific DNS resolver for a hostname.
    Implements Requirements 1.1-1.4, 8.1-8.4 (DNS queries with error handling)
    Implements Requirement 2.5 (follow CNAME chains to final resolution)
    
    Args:
        hostname: Domain name to resolve
        resolver_ip: DNS server IP (None for system default)
        resolver_name: Human-readable name for the resolver
        follow_cnames: Whether to follow CNAME chains (default True)
    
    Returns:
        DNSResult with query results and metadata
    """
    result = DNSResult(
        resolver=resolver_ip or "system",
        resolver_name=resolver_name
    )
    
    start_time = time.time()
    
    try:
        if DNSPYTHON_AVAILABLE and resolver_ip:
            # Follow CNAME chain first if requested (Requirement 2.5)
            cname_chain = []
            final_hostname = hostname
            
            if follow_cnames:
                cname_chain, final_hostname = follow_cname_chain(hostname, resolver_ip, resolver_name)
            
            # Query specific DNS resolver using dnspython (Requirement 1.3)
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [resolver_ip]
            resolver.timeout = DNS_QUERY_TIMEOUT  # Requirement 9.4
            resolver.lifetime = DNS_QUERY_TIMEOUT
            
            try:
                # Perform DNS query for A records on final hostname
                answers = resolver.resolve(final_hostname, 'A')
                
                # Extract IP addresses (Requirement 2.1)
                ips = [str(rdata) for rdata in answers]
                
                result.ips = ips
                result.success = True
                result.query_time = time.time() - start_time
                
                # Extract TTL from first answer
                if answers.rrset:
                    result.ttl = answers.rrset.ttl
                
                if cname_chain:
                    print(f"[DNS Blocking] {resolver_name} resolved {hostname} via CNAME chain {' -> '.join(cname_chain)} to {ips} (TTL: {result.ttl})", file=sys.stderr)
                else:
                    print(f"[DNS Blocking] {resolver_name} resolved {hostname} to {ips} (TTL: {result.ttl})", file=sys.stderr)
                
            except dns.resolver.NXDOMAIN:
                # Domain does not exist (Requirement 2.3)
                result.error = "NXDOMAIN: Domain does not exist"
                result.query_time = time.time() - start_time
                print(f"[DNS Blocking] {resolver_name} returned NXDOMAIN for {hostname}", file=sys.stderr)
                
            except dns.resolver.NoAnswer:
                # No A records found
                result.error = "No A records found"
                result.query_time = time.time() - start_time
                print(f"[DNS Blocking] {resolver_name} returned no answer for {hostname}", file=sys.stderr)
                
            except dns.resolver.Timeout:
                # Query timeout (Requirement 8.1)
                result.error = "DNS query timeout"
                result.query_time = time.time() - start_time
                print(f"[DNS Blocking] Timeout querying {resolver_name} for {hostname}", file=sys.stderr)
                
            except dns.exception.DNSException as e:
                # Other DNS errors
                result.error = f"DNS error: {str(e)}"
                result.query_time = time.time() - start_time
                print(f"[DNS Blocking] DNS error from {resolver_name} for {hostname}: {e}", file=sys.stderr)
        
        else:
            # Fallback to system DNS using socket (Requirement 1.2)
            socket.setdefaulttimeout(DNS_QUERY_TIMEOUT)
            
            try:
                # Perform DNS query using system resolver
                addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
                
                # Extract unique IP addresses
                ips = list(set([addr[4][0] for addr in addr_info]))
                
                result.ips = ips
                result.success = True
                result.query_time = time.time() - start_time
                
                print(f"[DNS Blocking] {resolver_name} resolved {hostname} to {ips}", file=sys.stderr)
                
            except socket.timeout:
                # Requirement 8.1: Log timeout and continue
                result.error = "DNS query timeout"
                result.query_time = time.time() - start_time
                print(f"[DNS Blocking] Timeout querying {resolver_name} for {hostname}", file=sys.stderr)
                
            except socket.gaierror as e:
                # DNS resolution error (could be NXDOMAIN)
                result.error = f"DNS resolution failed: {str(e)}"
                result.query_time = time.time() - start_time
                print(f"[DNS Blocking] DNS error from {resolver_name} for {hostname}: {e}", file=sys.stderr)
            
            finally:
                # Reset timeout
                socket.setdefaulttimeout(None)
        
    except Exception as e:
        # Requirement 8.4: Don't raise unhandled exceptions
        result.error = f"Query error: {str(e)}"
        result.query_time = time.time() - start_time
        print(f"[DNS Blocking] Error querying {resolver_name} for {hostname}: {e}", file=sys.stderr)
    
    return result


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private range"""
    try:
        parts = [int(p) for p in ip.split(".")]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        # 127.0.0.0/8 (localhost)
        if parts[0] == 127:
            return True
        
        return False
    except:
        return False


def is_localhost_ip(ip: str) -> bool:
    """Check if an IP is localhost/loopback"""
    return ip.startswith("127.") or ip == "0.0.0.0"


def get_ip_reverse_dns(ip: str, resolver_ip: Optional[str] = None) -> Optional[str]:
    """
    Get reverse DNS (PTR record) for an IP address.
    Implements Requirement 2.7 (validate IP addresses belong to expected domain owner)
    
    Args:
        ip: IP address to look up
        resolver_ip: DNS server IP (None for system default)
    
    Returns:
        Reverse DNS hostname or None if lookup fails
    """
    if not DNSPYTHON_AVAILABLE or not resolver_ip:
        # Can't do reverse DNS without dnspython
        return None
    
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.timeout = DNS_QUERY_TIMEOUT
        resolver.lifetime = DNS_QUERY_TIMEOUT
        
        # Convert IP to reverse DNS format (e.g., 1.2.3.4 -> 4.3.2.1.in-addr.arpa)
        rev_name = dns.reversename.from_address(ip)
        
        # Query PTR record
        answers = resolver.resolve(rev_name, 'PTR')
        
        if answers:
            ptr_hostname = str(answers[0].target).rstrip('.')
            return ptr_hostname
        
        return None
        
    except Exception as e:
        print(f"[DNS Blocking] Reverse DNS lookup failed for {ip}: {e}", file=sys.stderr)
        return None


def validate_ip_ownership(ip: str, expected_domain: str, resolver_ip: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validate that an IP address belongs to the expected domain owner.
    Implements Requirement 2.7 (validate IP addresses belong to expected domain owner)
    
    This performs basic validation by checking:
    1. Reverse DNS (PTR) record matches domain or known CDN
    2. IP is not in suspicious ranges (localhost, private)
    
    Args:
        ip: IP address to validate
        expected_domain: Domain name we expect the IP to belong to
        resolver_ip: DNS server IP for lookups
    
    Returns:
        Tuple of (is_valid, reason)
    """
    # Check for suspicious IPs first (Requirement 2.4)
    if is_localhost_ip(ip):
        return (False, f"IP {ip} is localhost/loopback")
    
    if is_private_ip(ip):
        return (False, f"IP {ip} is in private range")
    
    # Try reverse DNS lookup
    ptr_hostname = get_ip_reverse_dns(ip, resolver_ip)
    
    if ptr_hostname:
        # Extract base domain from both hostnames
        expected_parts = expected_domain.split('.')
        ptr_parts = ptr_hostname.split('.')
        
        # Check if PTR hostname ends with expected domain
        # e.g., www.example.com should match *.example.com
        if len(expected_parts) >= 2 and len(ptr_parts) >= 2:
            expected_base = '.'.join(expected_parts[-2:])
            ptr_base = '.'.join(ptr_parts[-2:])
            
            if expected_base == ptr_base:
                return (True, f"PTR record {ptr_hostname} matches domain")
            
            # Also check if PTR hostname contains the expected domain
            # e.g., "dns.google" should match "google.com" (both have "google")
            expected_domain_lower = expected_domain.lower()
            ptr_hostname_lower = ptr_hostname.lower()
            
            # Check if the main part of the domain is in the PTR
            if len(expected_parts) >= 2:
                domain_main_part = expected_parts[-2]  # e.g., "google" from "google.com"
                if domain_main_part in ptr_hostname_lower:
                    return (True, f"PTR record {ptr_hostname} contains domain identifier")
        
        # Check for known CDN providers (these are legitimate)
        cdn_indicators = [
            'cloudflare', 'akamai', 'fastly', 'cloudfront', 
            'cdn', 'edgecast', 'incapsula', 'sucuri', 'azure',
            'amazonaws', 'googleusercontent', 'github',
            '1e100'  # Google's internal network (1e100 = googol)
        ]
        
        ptr_lower = ptr_hostname.lower()
        for cdn in cdn_indicators:
            if cdn in ptr_lower:
                return (True, f"IP belongs to CDN/cloud provider: {ptr_hostname}")
        
        # PTR exists but doesn't match - might be suspicious
        return (False, f"PTR record {ptr_hostname} doesn't match expected domain {expected_domain}")
    
    # No PTR record - not necessarily suspicious (many legitimate IPs don't have PTR)
    return (True, "No PTR record (common for many legitimate IPs)")


def validate_ip_set_ownership(ips: List[str], expected_domain: str, 
                               resolver_ip: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Validate that a set of IP addresses belong to the expected domain owner.
    Implements Requirement 2.7 (validate IP addresses belong to expected domain owner)
    
    Args:
        ips: List of IP addresses to validate
        expected_domain: Domain name we expect the IPs to belong to
        resolver_ip: DNS server IP for lookups
    
    Returns:
        Tuple of (all_valid, validation_details)
    """
    validation_details = []
    all_valid = True
    
    for ip in ips:
        is_valid, reason = validate_ip_ownership(ip, expected_domain, resolver_ip)
        
        if not is_valid:
            all_valid = False
            validation_details.append(f"⚠️ {ip}: {reason}")
        else:
            validation_details.append(f"✓ {ip}: {reason}")
    
    return (all_valid, validation_details)


def compare_ip_sets(system_ips: set, public_ips: set) -> Tuple[bool, int]:
    """
    Compare IP sets to determine if discrepancy indicates blocking.
    Implements smart comparison that handles CDN/load balancing scenarios.
    
    Args:
        system_ips: IPs from system DNS
        public_ips: IPs from public DNS resolvers
    
    Returns:
        Tuple of (is_suspicious, confidence_score)
    """
    # If IPs are identical, no blocking
    if system_ips == public_ips:
        return (False, 0)
    
    # Check if system IPs are a subset of public IPs (normal for CDN)
    if system_ips.issubset(public_ips):
        return (False, 0)
    
    # Check if public IPs are a subset of system IPs (also normal)
    if public_ips.issubset(system_ips):
        return (False, 0)
    
    # Check if there's any overlap (might be CDN with different pools)
    overlap = system_ips.intersection(public_ips)
    if overlap:
        # Some overlap suggests legitimate CDN behavior
        return (False, 0)
    
    # No overlap at all - check subnet similarity
    # Check /24 subnet (xxx.xxx.xxx.0/24)
    system_subnets_24 = set(['.'.join(ip.split('.')[:3]) for ip in system_ips])
    public_subnets_24 = set(['.'.join(ip.split('.')[:3]) for ip in public_ips])
    
    if system_subnets_24.intersection(public_subnets_24):
        # Same /24 subnet, likely legitimate
        return (False, 0)
    
    # Check /16 subnet (xxx.xxx.0.0/16) for large CDNs
    system_subnets_16 = set(['.'.join(ip.split('.')[:2]) for ip in system_ips])
    public_subnets_16 = set(['.'.join(ip.split('.')[:2]) for ip in public_ips])
    
    if system_subnets_16.intersection(public_subnets_16):
        # Same /16 subnet, likely legitimate CDN (e.g., Google, Cloudflare)
        return (False, 0)
    
    # Completely different IP ranges with no overlap - suspicious
    return (True, 60)


def analyze_dns_results(hostname: str, system_result: DNSResult, 
                        public_results: List[DNSResult]) -> DNSBlockingEvidence:
    """
    Analyze DNS results from multiple resolvers to detect blocking.
    Implements Requirements 1.4-1.5, 2.1-2.7, 4.1-4.6
    
    This function compares DNS responses from different resolvers and:
    - Flags discrepancies between ISP and public DNS results (Req 1.4)
    - Handles cases where some resolvers timeout or fail (Req 8.5)
    - Calculates confidence scores for DNS manipulation detection (Req 1.5)
    
    Args:
        hostname: Domain being analyzed
        system_result: Result from system DNS
        public_results: Results from public DNS resolvers
    
    Returns:
        DNSBlockingEvidence with complete analysis
    """
    evidence = DNSBlockingEvidence(hostname=hostname)
    evidence.system_dns_result = system_result
    evidence.public_dns_results = public_results
    
    # Requirement 8.5: Handle cases where some resolvers timeout or fail
    successful_public = [r for r in public_results if r.success and r.ips]
    
    if not system_result.success and not successful_public:
        # Requirement 8.3: Return result indicating analysis not possible
        evidence.details.append("DNS analysis not possible - all queries failed")
        return evidence
    
    # Requirement 2.3: Detect NXDOMAIN
    if system_result.error and ("NXDOMAIN" in system_result.error or "resolution failed" in system_result.error.lower()):
        evidence.nxdomain_detected = True
        evidence.details.append("⚠️ System DNS returned NXDOMAIN (domain not found)")
        
        # Check if public DNS can resolve it
        if successful_public:
            evidence.blocking_detected = True
            evidence.blocking_type = BlockingType.NXDOMAIN
            evidence.confidence_score = 70
            evidence.details.append("🚨 Public DNS can resolve domain - possible DNS blocking")
    
    # Requirement 2.6: Detect unusually low TTL values (< 60 seconds)
    if system_result.success and system_result.ttl is not None:
        if system_result.ttl < 60:
            evidence.low_ttl_detected = True
            evidence.details.append(f"⚠️ Unusually low TTL detected: {system_result.ttl} seconds (normal is 300+)")
            # Low TTL can indicate DNS manipulation or temporary blocking
            if not evidence.blocking_detected:
                evidence.blocking_detected = True
                evidence.blocking_type = BlockingType.DNS_HIJACK
                evidence.confidence_score = 40
            else:
                # Increase confidence if already suspicious
                evidence.confidence_score = min(100, evidence.confidence_score + 15)
    
    # Requirement 8.5: Handle partial results when some resolvers fail
    if not system_result.success and successful_public:
        evidence.details.append("⚠️ System DNS failed but public DNS succeeded")
        # Continue with analysis using available public DNS results
    
    # Requirement 1.4: Compare IP addresses returned by different resolvers
    if system_result.success and system_result.ips and successful_public:
        system_ips = set(system_result.ips)
        
        # Get consensus from public resolvers
        public_ips = set()
        for result in successful_public:
            public_ips.update(result.ips)
        
        # Requirement 2.7: Validate IP ownership for system DNS results
        if system_ips:
            # Use first successful public resolver for validation lookups
            validation_resolver = successful_public[0].resolver if successful_public else None
            all_valid, validation_details = validate_ip_set_ownership(
                list(system_ips), hostname, validation_resolver
            )
            
            # Add validation details to evidence
            for detail in validation_details:
                if "⚠️" in detail:
                    evidence.details.append(detail)
                    # If validation fails, increase suspicion
                    if not all_valid and not evidence.blocking_detected:
                        evidence.blocking_detected = True
                        evidence.blocking_type = BlockingType.DNS_HIJACK
                        evidence.confidence_score = max(evidence.confidence_score, 50)
        
        # Requirement 1.4: Flag discrepancies between ISP and public DNS results
        if system_ips != public_ips:
            discrepancy = f"System DNS: {sorted(system_ips)} vs Public DNS: {sorted(public_ips)}"
            evidence.ip_discrepancies.append(discrepancy)
            
            # Requirement 4.1: Check if system DNS returned known blocking IPs
            blocking_ip_found = False
            for ip in system_ips:
                if ip in KNOWN_BLOCKING_IPS:
                    evidence.blocking_ips_found.append((ip, KNOWN_BLOCKING_IPS[ip]))
                    evidence.blocking_detected = True
                    evidence.blocking_type = BlockingType.ISP_FILTER
                    evidence.confidence_score = 85
                    evidence.details.append(f"🚨 Known blocking IP detected: {ip} ({KNOWN_BLOCKING_IPS[ip]})")
                    blocking_ip_found = True
            
            # Requirement 2.4: Check for localhost/private IPs
            suspicious_ip_found = False
            for ip in system_ips:
                if is_localhost_ip(ip):
                    evidence.blocking_detected = True
                    evidence.blocking_type = BlockingType.LOCALHOST_REDIRECT
                    evidence.confidence_score = 90
                    evidence.details.append(f"🚨 Localhost redirect detected: {ip}")
                    suspicious_ip_found = True
                elif is_private_ip(ip) and ip not in public_ips:
                    evidence.private_ip_detected = True
                    evidence.blocking_detected = True
                    evidence.blocking_type = BlockingType.DNS_HIJACK
                    evidence.confidence_score = 75
                    evidence.details.append(f"⚠️ Private IP returned: {ip}")
                    suspicious_ip_found = True
            
            # Requirement 1.5: Calculate confidence scores for DNS manipulation detection
            # Use smart comparison to avoid false positives from CDN/load balancing
            if not blocking_ip_found and not suspicious_ip_found:
                is_suspicious, confidence = compare_ip_sets(system_ips, public_ips)
                
                if is_suspicious:
                    evidence.blocking_detected = True
                    evidence.blocking_type = BlockingType.DNS_HIJACK
                    evidence.confidence_score = confidence
                    evidence.details.append(f"⚠️ DNS discrepancy detected: {discrepancy}")
                    evidence.details.append("⚠️ DNS responses differ between resolvers - possible manipulation")
                else:
                    # IPs differ but it's likely normal CDN/load balancing
                    evidence.details.append(f"ℹ️ Different IPs returned (likely CDN/load balancing): {discrepancy}")
    
    # Log successful resolution
    if system_result.success and system_result.ips and not evidence.blocking_detected:
        evidence.details.append(f"✓ DNS resolution successful: {', '.join(system_result.ips)}")
    
    return evidence


def detect_proxy_headers(url: str, timeout: int = 3) -> Tuple[bool, List[str], Optional[str]]:
    """
    Perform HTTP header analysis to detect proxy indicators.
    Implements Requirement 3.1, 3.2 (HTTP header analysis for proxy detection)
    
    Args:
        url: Full URL to analyze (must include scheme)
        timeout: HTTP request timeout in seconds
    
    Returns:
        Tuple of (proxy_detected, proxy_indicators, connection_ip)
        - proxy_detected: True if proxy headers found
        - proxy_indicators: List of detected proxy header details
        - connection_ip: Actual connection IP (if available)
    """
    if not REQUESTS_AVAILABLE:
        return (False, ["HTTP analysis unavailable - requests library not installed"], None)
    
    proxy_indicators = []
    proxy_detected = False
    connection_ip = None
    
    try:
        # Make HTTP request with timeout (Requirement 3.1)
        # Use HEAD request to minimize data transfer
        response = requests.head(url, timeout=timeout, allow_redirects=False)
        
        # Requirement 3.2: Check for Via header
        if 'Via' in response.headers:
            via_value = response.headers['Via']
            proxy_indicators.append(f"Via header detected: {via_value}")
            proxy_detected = True
        
        # Requirement 3.2: Check for X-Forwarded-For header
        if 'X-Forwarded-For' in response.headers:
            xff_value = response.headers['X-Forwarded-For']
            proxy_indicators.append(f"X-Forwarded-For header detected: {xff_value}")
            proxy_detected = True
        
        # Requirement 3.2: Check for X-Cache header (common in CDN/proxy)
        if 'X-Cache' in response.headers:
            xcache_value = response.headers['X-Cache']
            proxy_indicators.append(f"X-Cache header detected: {xcache_value}")
            # X-Cache alone doesn't necessarily mean transparent proxy (could be CDN)
            # Only flag if it indicates a proxy hit
            if 'proxy' in xcache_value.lower():
                proxy_detected = True
        
        # Check for other common proxy headers
        proxy_headers = [
            'X-Proxy-ID', 'X-Proxy-Cache', 'Proxy-Connection',
            'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Real-IP'
        ]
        
        for header in proxy_headers:
            if header in response.headers:
                value = response.headers[header]
                proxy_indicators.append(f"{header} header detected: {value}")
                proxy_detected = True
        
        # Try to extract connection IP from response
        # Some servers include this in custom headers
        if 'X-Client-IP' in response.headers:
            connection_ip = response.headers['X-Client-IP']
        elif 'X-Real-IP' in response.headers:
            connection_ip = response.headers['X-Real-IP']
        
        print(f"[DNS Blocking] HTTP header analysis for {url}: proxy_detected={proxy_detected}", file=sys.stderr)
        
    except requests.exceptions.Timeout:
        proxy_indicators.append("HTTP request timeout")
        print(f"[DNS Blocking] HTTP request timeout for {url}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        proxy_indicators.append(f"HTTP request failed: {str(e)}")
        print(f"[DNS Blocking] HTTP request error for {url}: {e}", file=sys.stderr)
    except Exception as e:
        proxy_indicators.append(f"HTTP analysis error: {str(e)}")
        print(f"[DNS Blocking] Unexpected error in HTTP analysis for {url}: {e}", file=sys.stderr)
    
    return (proxy_detected, proxy_indicators, connection_ip)


def detect_http_redirects(url: str, timeout: int = 3) -> Tuple[bool, List[str]]:
    """
    Detect HTTP redirects to ISP warning or preview pages.
    Implements Requirement 3.5 (detect HTTP redirects to ISP warning/preview pages)
    
    Args:
        url: Full URL to analyze
        timeout: HTTP request timeout in seconds
    
    Returns:
        Tuple of (redirect_detected, redirect_details)
    """
    if not REQUESTS_AVAILABLE:
        return (False, ["HTTP redirect detection unavailable"])
    
    redirect_details = []
    redirect_detected = False
    
    try:
        # Make HTTP request and follow redirects
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        
        # Check if we were redirected
        if response.history:
            redirect_chain = [r.url for r in response.history]
            final_url = response.url
            
            redirect_details.append(f"Redirected from {url} to {final_url}")
            
            # Check if final URL indicates ISP blocking/warning page
            blocking_indicators = [
                'blocked', 'warning', 'filter', 'restricted',
                'denied', 'forbidden', 'isp', 'preview',
                'parental', 'safeguard', 'protection'
            ]
            
            final_url_lower = final_url.lower()
            for indicator in blocking_indicators:
                if indicator in final_url_lower:
                    redirect_detected = True
                    redirect_details.append(f"Suspicious redirect keyword detected: '{indicator}'")
                    break
            
            # Check if redirect goes to a different domain (potential ISP interception)
            original_domain = urlparse(url).netloc
            final_domain = urlparse(final_url).netloc
            
            if original_domain != final_domain:
                redirect_details.append(f"Domain changed: {original_domain} -> {final_domain}")
                # This could indicate ISP interception
                redirect_detected = True
        
        print(f"[DNS Blocking] HTTP redirect analysis for {url}: redirect_detected={redirect_detected}", file=sys.stderr)
        
    except requests.exceptions.Timeout:
        redirect_details.append("HTTP request timeout during redirect check")
        print(f"[DNS Blocking] HTTP redirect check timeout for {url}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        redirect_details.append(f"HTTP redirect check failed: {str(e)}")
        print(f"[DNS Blocking] HTTP redirect check error for {url}: {e}", file=sys.stderr)
    except Exception as e:
        redirect_details.append(f"Redirect analysis error: {str(e)}")
        print(f"[DNS Blocking] Unexpected error in redirect analysis for {url}: {e}", file=sys.stderr)
    
    return (redirect_detected, redirect_details)


def compare_dns_and_connection_ip(hostname: str, dns_ips: List[str], timeout: int = 3) -> Tuple[bool, Optional[str], List[str]]:
    """
    Compare DNS-resolved IP with actual connection IP.
    Implements Requirement 3.3, 3.4 (compare resolved IP with connection IP)
    
    Args:
        hostname: Domain name to analyze
        dns_ips: List of IPs from DNS resolution
        timeout: Connection timeout in seconds
    
    Returns:
        Tuple of (mismatch_detected, connection_ip, comparison_details)
    """
    comparison_details = []
    connection_ip = None
    mismatch_detected = False
    
    try:
        # Create a socket connection to get the actual connection IP
        # We'll try to connect to port 80 (HTTP) or 443 (HTTPS)
        for port in [443, 80]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                # Connect to the hostname
                sock.connect((hostname, port))
                
                # Get the peer address (actual connection IP)
                connection_ip = sock.getpeername()[0]
                
                sock.close()
                
                print(f"[DNS Blocking] Connected to {hostname}:{port}, actual IP: {connection_ip}", file=sys.stderr)
                break
                
            except (socket.timeout, socket.error) as e:
                print(f"[DNS Blocking] Connection failed to {hostname}:{port}: {e}", file=sys.stderr)
                continue
        
        if connection_ip:
            # Requirement 3.3: Compare resolved IP with connection IP
            if connection_ip in dns_ips:
                comparison_details.append(f"✓ Connection IP {connection_ip} matches DNS resolution")
            else:
                # Requirement 3.4: Flag potential transparent proxy
                mismatch_detected = True
                comparison_details.append(f"⚠️ Connection IP {connection_ip} differs from DNS IPs {dns_ips}")
                comparison_details.append("Possible transparent proxy or load balancer")
        else:
            comparison_details.append("Could not establish connection to determine actual IP")
    
    except Exception as e:
        comparison_details.append(f"IP comparison error: {str(e)}")
        print(f"[DNS Blocking] Error comparing IPs for {hostname}: {e}", file=sys.stderr)
    
    return (mismatch_detected, connection_ip, comparison_details)


def analyze_transparent_proxy(hostname: str, url: str, dns_ips: List[str]) -> Tuple[bool, List[str], Optional[str]]:
    """
    Comprehensive transparent proxy detection analysis.
    Implements Requirements 3.1-3.6 (complete transparent proxy detection)
    
    This function combines:
    - HTTP header analysis (Req 3.1, 3.2)
    - DNS vs connection IP comparison (Req 3.3, 3.4)
    - HTTP redirect detection (Req 3.5)
    - Proxy IP and header recording (Req 3.6)
    
    Args:
        hostname: Domain name being analyzed
        url: Full URL to analyze (with scheme)
        dns_ips: List of IPs from DNS resolution
    
    Returns:
        Tuple of (proxy_detected, proxy_indicators, proxy_ip)
    """
    all_indicators = []
    proxy_detected = False
    proxy_ip = None
    
    # Requirement 3.1, 3.2: HTTP header analysis
    header_proxy_detected, header_indicators, connection_ip = detect_proxy_headers(url)
    all_indicators.extend(header_indicators)
    
    if header_proxy_detected:
        proxy_detected = True
    
    # Requirement 3.3, 3.4: Compare DNS IP with connection IP
    if dns_ips:
        ip_mismatch, actual_connection_ip, comparison_details = compare_dns_and_connection_ip(hostname, dns_ips)
        all_indicators.extend(comparison_details)
        
        if ip_mismatch:
            proxy_detected = True
            proxy_ip = actual_connection_ip
        
        # Use connection IP from socket if header didn't provide one
        if not connection_ip and actual_connection_ip:
            connection_ip = actual_connection_ip
    
    # Requirement 3.5: Detect HTTP redirects
    redirect_detected, redirect_details = detect_http_redirects(url)
    all_indicators.extend(redirect_details)
    
    if redirect_detected:
        proxy_detected = True
    
    # Requirement 3.6: Record proxy IP
    if proxy_detected and not proxy_ip:
        proxy_ip = connection_ip
    
    return (proxy_detected, all_indicators, proxy_ip)



def check_dns_blocking(hostname: str, url: Optional[str] = None) -> DNSBlockingEvidence:
    """
    Main function to check for DNS blocking on a hostname.
    Implements Requirement 7.2 (expose check_dns_blocking function)
    
    Args:
        hostname: Domain name to analyze
        url: Optional full URL for HTTP-based proxy detection (with scheme)
    
    Returns:
        DNSBlockingEvidence with complete analysis results
    """
    # Check cache first (Requirement 9.1)
    cache_key = f"dns_blocking:{hostname}"
    if cache_key in _dns_cache:
        cached_time, cached_result = _dns_cache[cache_key]
        if time.time() - cached_time < _cache_ttl:
            print(f"[DNS Blocking] Cache hit for {hostname}", file=sys.stderr)
            return cached_result
    
    print(f"[DNS Blocking] Analyzing DNS for: {hostname}", file=sys.stderr)
    
    start_time = time.time()
    
    # Query system DNS (Requirement 1.2)
    system_result = query_dns_resolver(hostname, None, "System DNS")
    
    # Query public DNS resolvers (Requirement 1.3)
    public_results = []
    resolvers = get_dns_resolvers()
    
    for resolver_ip, resolver_name in resolvers:
        # Check if we're approaching timeout (Requirement 1.6)
        elapsed = time.time() - start_time
        if elapsed >= DNS_TOTAL_TIMEOUT:
            print(f"[DNS Blocking] Timeout reached, stopping queries", file=sys.stderr)
            break
        
        result = query_dns_resolver(hostname, resolver_ip, resolver_name)
        public_results.append(result)
    
    # Analyze results (Requirements 1.4-1.5, 2.1-2.7)
    evidence = analyze_dns_results(hostname, system_result, public_results)
    
    # Perform transparent proxy detection if URL provided (Requirements 3.1-3.6)
    if url and system_result.success and system_result.ips:
        print(f"[DNS Blocking] Performing transparent proxy detection for {url}", file=sys.stderr)
        
        proxy_detected, proxy_indicators, proxy_ip = analyze_transparent_proxy(
            hostname, url, system_result.ips
        )
        
        # Update evidence with proxy detection results (Requirement 5.5)
        evidence.transparent_proxy_detected = proxy_detected
        evidence.proxy_indicators = proxy_indicators
        
        # Add proxy details to evidence (Requirement 3.6)
        if proxy_detected:
            evidence.details.append("🔍 Transparent proxy detected")
            for indicator in proxy_indicators:
                evidence.details.append(f"  {indicator}")
            
            # Update blocking type if not already set
            if not evidence.blocking_detected:
                evidence.blocking_detected = True
                evidence.blocking_type = BlockingType.TRANSPARENT_PROXY
                evidence.confidence_score = 60
            
            # Record proxy IP if found
            if proxy_ip:
                evidence.details.append(f"  Proxy IP: {proxy_ip}")
    
    # Cache the result (Requirement 9.1)
    _dns_cache[cache_key] = (time.time(), evidence)
    
    total_time = time.time() - start_time
    print(f"[DNS Blocking] Analysis completed in {total_time:.2f}s", file=sys.stderr)
    
    return evidence


def get_dns_blocking_risk_score(hostname: str) -> Tuple[float, List[str]]:
    """
    Calculate DNS blocking risk score for integration with PhishPolice risk scoring.
    Implements Requirement 7.3 (expose get_dns_blocking_risk_score function)
    Implements Requirement 6 (Risk Score Integration)
    
    Args:
        hostname: Domain name to analyze
    
    Returns:
        Tuple of (risk_score 0.0-0.15, evidence_list)
    """
    try:
        evidence = check_dns_blocking(hostname)
        
        if not evidence.blocking_detected:
            return (0.0, evidence.details)
        
        # Calculate risk score based on blocking type and confidence
        # Requirement 6.1: DNS manipulation risk score between 0.0 and 0.15
        
        if evidence.blocking_type == BlockingType.LOCALHOST_REDIRECT:
            # Localhost redirect is highly suspicious
            risk_score = 0.15
        elif evidence.blocking_type == BlockingType.DNS_HIJACK:
            # Suspicious DNS hijacking (Requirement 6.3)
            risk_score = 0.10 + (evidence.confidence_score / 1000)  # 0.10-0.15
        elif evidence.blocking_type == BlockingType.NXDOMAIN:
            # NXDOMAIN blocking
            risk_score = 0.08
        elif evidence.blocking_type == BlockingType.ISP_FILTER:
            # Legitimate ISP filtering (Requirement 6.2)
            risk_score = 0.02 + (evidence.confidence_score / 2000)  # 0.02-0.05
        else:
            # Generic blocking detected
            risk_score = 0.05
        
        # Requirement 6.4: Add score for transparent proxy
        if evidence.transparent_proxy_detected:
            risk_score += 0.03
        
        # Cap at 0.15 (Requirement 6.1)
        risk_score = min(0.15, risk_score)
        
        return (risk_score, evidence.details)
        
    except Exception as e:
        # Requirement 8.4: Handle errors gracefully
        print(f"[DNS Blocking] Error calculating risk score: {e}", file=sys.stderr)
        return (0.0, ["DNS blocking analysis failed"])


def format_dns_blocking_summary(dns_result: DNSBlockingEvidence) -> str:
    """
    Format DNS blocking evidence as human-readable summary.
    Implements Requirement 7.4 (expose format_dns_blocking_summary function)
    Implements Requirement 5.6 (format evidence as human-readable strings)
    
    Args:
        dns_result: DNSBlockingEvidence to format
    
    Returns:
        Formatted summary string
    """
    if not dns_result.blocking_detected:
        if dns_result.details:
            return dns_result.details[0]
        return "✓ No DNS blocking detected"
    
    # Build summary with blocking type and confidence
    summary_parts = []
    
    if dns_result.blocking_type == BlockingType.ISP_FILTER:
        summary_parts.append(f"⚠️ ISP Filtering Detected (confidence: {dns_result.confidence_score}%)")
    elif dns_result.blocking_type == BlockingType.DNS_HIJACK:
        summary_parts.append(f"🚨 DNS Hijacking Suspected (confidence: {dns_result.confidence_score}%)")
    elif dns_result.blocking_type == BlockingType.LOCALHOST_REDIRECT:
        summary_parts.append(f"🚨 Localhost Redirect Detected (confidence: {dns_result.confidence_score}%)")
    elif dns_result.blocking_type == BlockingType.NXDOMAIN:
        summary_parts.append(f"⚠️ DNS Blocking via NXDOMAIN (confidence: {dns_result.confidence_score}%)")
    else:
        summary_parts.append(f"⚠️ DNS Manipulation Detected (confidence: {dns_result.confidence_score}%)")
    
    if dns_result.blocking_entity:
        summary_parts.append(f"Entity: {dns_result.blocking_entity}")
    
    if dns_result.transparent_proxy_detected:
        summary_parts.append("Transparent Proxy Detected")
    
    # Add key details
    if dns_result.ip_discrepancies:
        summary_parts.append(f"IP Discrepancies: {len(dns_result.ip_discrepancies)}")
    
    return " | ".join(summary_parts)


def extract_hostname_from_url(url: str) -> str:
    """
    Extract hostname from a URL.
    Helper function for URL-based analysis.
    
    Args:
        url: Full URL to extract hostname from
    
    Returns:
        Hostname string
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc or url
        return hostname
    except Exception:
        return url


# Module initialization
print("[DNS Blocking] DNS blocking detection module loaded", file=sys.stderr)
print(f"[DNS Blocking] Using {len(get_dns_resolvers())} public DNS resolvers", file=sys.stderr)
