#!/usr/bin/env python3
"""
Test script for autonomous blocking with AI explanations
"""
import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_explain_block_endpoint():
    """Test the new /api/explain-block endpoint"""
    print("Testing /api/explain-block endpoint...")
    
    payload = {
        "hostname": "suspicious-site.tk",
        "verdict": "suspicious",
        "score": 0.65,
        "evidence": [
            "🚨 DNS Hijacking Suspected (confidence: 75%)",
            "⚠️ Suspicious TLD: .tk",
            "⚠️ Young domain: Only 15 days old",
            "🔐 1 form(s) collecting passwords"
        ],
        "ssl_info": {
            "is_valid": False,
            "issuer": "Unknown"
        },
        "domain_info": {
            "is_typosquat": False,
            "age_days": 15,
            "age_category": "new"
        },
        "dns_info": {
            "blocking_detected": True,
            "blocking_type": "dns_hijack",
            "confidence_score": 75
        }
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/explain-block",
            json=payload,
            timeout=10
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✅ Success!")
            print(f"Hostname: {data.get('hostname')}")
            print(f"\nAI Explanation:")
            print(f"  {data.get('explanation')}")
            return True
        else:
            print(f"❌ Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Request failed: {e}")
        return False


def test_health_endpoint():
    """Test the health endpoint to verify server is running"""
    print("Testing /api/health endpoint...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Server is healthy!")
            print(f"   Version: {data.get('version')}")
            print(f"   Features: {', '.join(data.get('features', []))}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("PhishPolice Autonomous Blocking Test")
    print("=" * 60)
    print()
    
    # Test health first
    if not test_health_endpoint():
        print("\n⚠️ Server is not running. Start it with: python backend/app.py")
        exit(1)
    
    print()
    print("-" * 60)
    print()
    
    # Test explain-block endpoint
    if test_explain_block_endpoint():
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("❌ Tests failed")
        print("=" * 60)
        exit(1)
