#!/usr/bin/env python3
"""
Test script for Router Dashboard modules 1-8
Tests all API endpoints and functionality
"""

import requests
import json
from time import sleep

BASE_URL = "http://localhost:5000"
TEST_USER = "admin_test1"
TEST_PASSWORD = "test123!@#"

# Test results tracker
results = {
    "Module 1": [],
    "Module 2": [],
    "Module 3": [],
    "Module 4": [],
    "Module 5": [],
    "Module 6": [],
    "Module 7": [],
    "Module 8": []
}

def print_section(title):
    print(f"\n{'='*60}")
    print(f"🧪 {title}")
    print(f"{'='*60}")

def test_result(module, endpoint, status, message):
    results[module].append({
        "endpoint": endpoint,
        "status": "✓" if status else "✗",
        "message": message
    })
    print(f"{'✓' if status else '✗'} {endpoint}: {message}")

def login():
    """Test login and get session"""
    print_section("AUTHENTICATION")
    try:
        session = requests.Session()
        
        # Get login page to get CSRF token
        resp = session.get(f"{BASE_URL}/login")
        
        # Try to login (admin credentials should be in admin_credentials.txt)
        login_data = {
            "username": "admin_test",
            "password": "test123"
        }
        
        resp = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=False)
        
        if resp.status_code in [200, 302]:
            print("✓ Login successful or page loaded")
            return session
        else:
            print(f"⚠ Login response: {resp.status_code}")
            return session
    except Exception as e:
        print(f"✗ Login failed: {e}")
        return None

def test_module_1(session):
    """Test Module 1: Network Statistics APIs"""
    print_section("MODULE 1: Network Statistics")
    
    endpoints = [
        ("/api/router-status/public", "GET", "Router Status (Public)"),
        ("/api/router-status", "GET", "Router Status (Authenticated)"),
        ("/api/network-stats", "GET", "Network Stats"),
        ("/api/connected-devices", "GET", "Connected Devices"),
    ]
    
    for endpoint, method, desc in endpoints:
        try:
            if method == "GET":
                resp = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            data = resp.json() if resp.text else {}
            test_result("Module 1", endpoint, resp.status_code == 200, f"{resp.status_code} - {desc}")
        except Exception as e:
            test_result("Module 1", endpoint, False, str(e))

def test_module_2(session):
    """Test Module 2: Dashboard UI loads"""
    print_section("MODULE 2: Enhanced Dashboard UI")
    
    try:
        resp = session.get(f"{BASE_URL}/", timeout=10)
        has_neon = "neon-green" in resp.text
        has_tabs = "switchTab" in resp.text
        test_result("Module 2", "/dashboard", resp.status_code == 200 and has_neon and has_tabs,
                   f"Dashboard loads with enhanced UI ({resp.status_code})")
    except Exception as e:
        test_result("Module 2", "/dashboard", False, str(e))

def test_module_3(session):
    """Test Module 3: Advanced Monitoring"""
    print_section("MODULE 3: Advanced Monitoring")
    
    endpoints = [
        ("/api/service-health", "Service Health"),
        ("/api/system-logs", "System Logs"),
    ]
    
    for endpoint, desc in endpoints:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            test_result("Module 3", endpoint, resp.status_code == 200, f"{desc} ({resp.status_code})")
        except Exception as e:
            test_result("Module 3", endpoint, False, str(e))

def test_module_4(session):
    """Test Module 4: Historical Analytics"""
    print_section("MODULE 4: Historical Analytics")
    
    endpoints = [
        ("/api/uptime-stats", "Uptime Statistics"),
        ("/api/performance-trends", "Performance Trends"),
    ]
    
    for endpoint, desc in endpoints:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            test_result("Module 4", endpoint, resp.status_code == 200, f"{desc} ({resp.status_code})")
        except Exception as e:
            test_result("Module 4", endpoint, False, str(e))

def test_module_5(session):
    """Test Module 5: Security Features"""
    print_section("MODULE 5: Security Features")
    
    endpoints = [
        ("/api/security-summary", "Security Summary"),
        ("/api/login-history", "Login History"),
        ("/api/port-scan-alerts", "Port Scan Alerts"),
        ("/api/vpn-status", "VPN Status"),
    ]
    
    for endpoint, desc in endpoints:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            test_result("Module 5", endpoint, resp.status_code == 200, f"{desc} ({resp.status_code})")
        except Exception as e:
            test_result("Module 5", endpoint, False, str(e))

def test_module_6(session):
    """Test Module 6: Network Intelligence"""
    print_section("MODULE 6: Network Intelligence")
    
    # GET endpoints
    endpoints = [
        ("/api/speedtest-history", "GET", "Speedtest History"),
        ("/api/dns-leak-history", "GET", "DNS Leak History"),
    ]
    
    for endpoint, method, desc in endpoints:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            test_result("Module 6", endpoint, resp.status_code == 200, f"{desc} ({resp.status_code})")
        except Exception as e:
            test_result("Module 6", endpoint, False, str(e))

def test_module_7(session):
    """Test Module 7: Smart Features"""
    print_section("MODULE 7: Smart Features")
    
    endpoints = [
        ("/api/device-tags", "Device Tags"),
        ("/api/bandwidth-quotas", "Bandwidth Quotas"),
        ("/api/auto-alerts", "Auto Alerts"),
    ]
    
    for endpoint, desc in endpoints:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            test_result("Module 7", endpoint, resp.status_code == 200, f"{desc} ({resp.status_code})")
        except Exception as e:
            test_result("Module 7", endpoint, False, str(e))

def test_module_8(session):
    """Test Module 8: Terminal Commander"""
    print_section("MODULE 8: Terminal Commander")
    
    endpoints = [
        ("/api/command-history", "Command History"),
    ]
    
    for endpoint, desc in endpoints:
        try:
            resp = session.get(f"{BASE_URL}{endpoint}", timeout=10)
            test_result("Module 8", endpoint, resp.status_code == 200, f"{desc} ({resp.status_code})")
        except Exception as e:
            test_result("Module 8", endpoint, False, str(e))

def print_summary():
    """Print test summary"""
    print_section("TEST SUMMARY")
    
    total_passed = 0
    total_tests = 0
    
    for module in sorted(results.keys()):
        tests = results[module]
        passed = sum(1 for t in tests if t["status"] == "✓")
        total = len(tests)
        total_passed += passed
        total_tests += total
        
        print(f"{module}: {passed}/{total} tests passed")
    
    print(f"\nTotal: {total_passed}/{total_tests} tests passed ({int(total_passed/total_tests*100)}%)")
    
    if total_passed == total_tests:
        print("\n🎉 ALL TESTS PASSED!")
    else:
        print(f"\n⚠ {total_tests - total_passed} tests failed")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 Router Dashboard - Module Testing Suite")
    print("="*60)
    
    session = login()
    if not session:
        print("Cannot proceed without authentication")
        exit(1)
    
    # Wait for app to be ready
    sleep(2)
    
    # Test all modules
    test_module_1(session)
    test_module_2(session)
    test_module_3(session)
    test_module_4(session)
    test_module_5(session)
    test_module_6(session)
    test_module_7(session)
    test_module_8(session)
    
    # Print summary
    print_summary()
