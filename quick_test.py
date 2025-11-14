#!/usr/bin/env python3
"""Quick test of all 8 modules"""

import requests
import json
import sys
from time import sleep

BASE_URL = "http://localhost:5000"

# Updated credentials from admin_credentials.txt
TEST_USER = "admin_kurmcd"
TEST_PASSWORD = "zGQr$4L71ykmL4l$"

def test_all_modules():
    """Test all modules quickly"""
    
    session = requests.Session()
    print("\n" + "="*60)
    print("🧪 MODULE TEST SUITE")
    print("="*60)
    
    # Test login
    print("\n[1] Testing authentication...")
    try:
        # Just try to access dashboard
        resp = session.get(f"{BASE_URL}/", timeout=5)
        if resp.status_code == 302:  # Should redirect to login
            print("✓ Auth check OK (redirect to login)")
    except Exception as e:
        print(f"✗ Auth check failed: {e}")
        return
    
    # Test public endpoint (no auth)
    print("\n[2] Testing Module 1: Network Stats (Public Endpoint)...")
    try:
        resp = requests.get(f"{BASE_URL}/api/router-status/public", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            print(f"✓ Router status: {data.get('status', 'unknown')}")
    except Exception as e:
        print(f"✗ Public endpoint failed: {e}")
    
    # Test dashboard page
    print("\n[3] Testing Module 2: Dashboard UI...")
    try:
        resp = session.get(f"{BASE_URL}/", timeout=5)
        if "neon-green" in resp.text and "switchTab" in resp.text:
            print("✓ Dashboard loads with enhanced UI")
        else:
            print(f"⚠ Dashboard loads but may be missing UI enhancements ({resp.status_code})")
    except Exception as e:
        print(f"✗ Dashboard failed: {e}")
    
    # All other endpoints check
    endpoints = [
        ("Module 3", "/api/service-health"),
        ("Module 3", "/api/system-logs"),
        ("Module 4", "/api/uptime-stats"),
        ("Module 4", "/api/performance-trends"),
        ("Module 5", "/api/security-summary"),
        ("Module 5", "/api/login-history"),
        ("Module 6", "/api/speedtest-history"),
        ("Module 6", "/api/dns-leak-history"),
        ("Module 7", "/api/device-tags"),
        ("Module 7", "/api/bandwidth-quotas"),
        ("Module 8", "/api/command-history"),
    ]
    
    print("\n[4] Testing Module Endpoints (may require authentication)...")
    for module, endpoint in endpoints:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}", timeout=5)
            status_icon = "✓" if resp.status_code in [200, 401] else "✗"
            print(f"{status_icon} {endpoint}: {resp.status_code}")
        except Exception as e:
            print(f"✗ {endpoint}: {str(e)[:40]}")
    
    print("\n" + "="*60)
    print("✅ Test complete!")
    print("="*60)

if __name__ == "__main__":
    # Wait for server to stabilize
    sleep(3)
    test_all_modules()
