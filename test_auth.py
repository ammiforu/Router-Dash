#!/usr/bin/env python3
"""Test authenticated access and check data"""
import sys
import os
os.environ['PYTHONIOENCODING'] = 'utf-8'
import requests
import json

BASE_URL = "http://localhost:5000"

# Read the auto-generated credentials
try:
    with open('admin_credentials.txt', 'r') as f:
        lines = f.readlines()
        username = lines[0].split(': ')[1].strip()
        password = lines[1].split(': ')[1].strip()
        print(f"Using credentials: {username}")
except:
    print("[FAIL] Could not read credentials file")
    sys.exit(1)

session = requests.Session()

print("\n" + "="*80)
print("ROUTER DASHBOARD - AUTHENTICATED ACCESS TEST")
print("="*80)

# Step 1: Get login page (to get CSRF token if needed)
print("\n[1] Getting login page...")
try:
    resp = session.get(f"{BASE_URL}/login", timeout=5)
    print(f"[OK] Login page: {resp.status_code}")
except Exception as e:
    print(f"[FAIL] {str(e)[:50]}")

# Step 2: Login
print("\n[2] Attempting login...")
try:
    login_data = {
        'username': username,
        'password': password
    }
    resp = session.post(f"{BASE_URL}/login", data=login_data, timeout=5, allow_redirects=False)
    print(f"[OK] Login response: {resp.status_code}")
    if resp.status_code == 302:
        print("    Redirected (expected after successful login)")
    elif resp.status_code == 200:
        print("    Login page still shown (check if login failed)")
except Exception as e:
    print(f"[FAIL] {str(e)[:50]}")

# Step 3: Try to access dashboard
print("\n[3] Accessing dashboard...")
try:
    resp = session.get(f"{BASE_URL}/", timeout=5, allow_redirects=True)
    print(f"[OK] Dashboard: {resp.status_code}")
    if resp.status_code == 200:
        has_overview = "Overview" in resp.text or "overview" in resp.text
        has_modules = "Connected Devices" in resp.text or "Network Intelligence" in resp.text
        print(f"    Has overview tab: {has_overview}")
        print(f"    Has module content: {has_modules}")
        print(f"    Page size: {len(resp.text)} bytes")
except Exception as e:
    print(f"[FAIL] {str(e)[:50]}")

# Step 4: Test protected endpoints
print("\n[4] Testing protected endpoints...")
test_endpoints = [
    ("/api/router-status", "Router Status"),
    ("/api/network-stats", "Network Stats"),
    ("/api/connected-devices", "Connected Devices"),
    ("/api/service-health", "Service Health"),
    ("/api/system-logs", "System Logs"),
    ("/api/uptime-stats", "Uptime Stats"),
    ("/api/security-summary", "Security Summary"),
]

passed = 0
failed = 0

for endpoint, name in test_endpoints:
    try:
        resp = session.get(f"{BASE_URL}{endpoint}", timeout=5)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict):
                    status_msg = f"Dict with keys: {list(data.keys())[:3]}"
                elif isinstance(data, list):
                    status_msg = f"List with {len(data)} items"
                else:
                    status_msg = f"Type: {type(data).__name__}"
                print(f"  [OK] {endpoint}: {status_msg}")
                passed += 1
            except:
                print(f"  [OK] {endpoint}: {len(resp.text)} bytes (non-JSON)")
                passed += 1
        else:
            print(f"  [FAIL] {endpoint}: {resp.status_code}")
            failed += 1
    except Exception as e:
        print(f"  [ERROR] {endpoint}: {str(e)[:40]}")
        failed += 1

print("\n" + "="*80)
print(f"Results: {passed} passed, {failed} failed")
print("="*80 + "\n")
