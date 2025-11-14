#!/usr/bin/env python3
"""Detailed diagnostic test of all endpoints"""
import sys
import os
os.environ['PYTHONIOENCODING'] = 'utf-8'
sys.stdout.reconfigure(encoding='utf-8')

import requests
import json

BASE_URL = "http://localhost:5000"

session = requests.Session()

print("\n" + "="*80)
print("ROUTER DASHBOARD - DETAILED DIAGNOSTIC TEST")
print("="*80)

# Test login
print("\n[AUTHENTICATION TEST]")
try:
    resp = session.get(f"{BASE_URL}/login")
    print(f"[OK] Login page loads: {resp.status_code}")
except Exception as e:
    print(f"[FAIL] Login failed: {str(e)[:50]}")

# Test public endpoint
print("\n[MODULE 1] NETWORK STATISTICS - PUBLIC ENDPOINT")
try:
    resp = requests.get(f"{BASE_URL}/api/router-status/public", timeout=5)
    if resp.status_code == 200:
        data = resp.json()
        print(f"[OK] Router Status: {resp.status_code}")
        print(f"  Data keys: {list(data.keys())}")
        print(f"  Sample: {json.dumps(data, indent=2)[:500]}")
    else:
        print(f"[FAIL] Status: {resp.status_code}")
except Exception as e:
    print(f"[ERROR] {str(e)[:50]}")

# Test dashboard page
print("\n[MODULE 2] DASHBOARD UI")
try:
    resp = session.get(f"{BASE_URL}/", allow_redirects=True, timeout=5)
    print(f"Status: {resp.status_code}")
    if "<!DOCTYPE" in resp.text or "<html" in resp.text:
        has_neon = "neon-green" in resp.text or "neon" in resp.text
        has_tabs = "switchTab" in resp.text or "tab" in resp.text.lower()
        has_charts = "Chart.js" in resp.text or "canvas" in resp.text
        print(f"  Has neon theme: {has_neon}")
        print(f"  Has tabs: {has_tabs}")
        print(f"  Has charts: {has_charts}")
        print(f"  Page size: {len(resp.text)} bytes")
    else:
        print(f"  Response: {resp.text[:200]}")
except Exception as e:
    print(f"[ERROR] {str(e)[:50]}")

# Test all protected endpoints
endpoints = [
    ("M1", "/api/network-stats", "Network Stats"),
    ("M1", "/api/connected-devices", "Connected Devices"),
    ("M1", "/api/diagnostics", "Diagnostics"),
    ("M3", "/api/service-health", "Service Health"),
    ("M3", "/api/system-logs", "System Logs"),
    ("M3", "/api/log-event", "Log Event"),
    ("M4", "/api/uptime-stats", "Uptime Stats"),
    ("M4", "/api/performance-trends", "Performance Trends"),
    ("M4", "/api/performance-snapshot", "Performance Snapshot"),
    ("M5", "/api/security-summary", "Security Summary"),
    ("M5", "/api/login-history", "Login History"),
    ("M5", "/api/port-scan-alerts", "Port Scan Alerts"),
    ("M5", "/api/vpn-status", "VPN Status"),
    ("M6", "/api/speedtest-history", "Speedtest History"),
    ("M6", "/api/dns-leak-history", "DNS Leak History"),
    ("M6", "/api/speedtest", "Speedtest (POST)"),
    ("M6", "/api/dns-leak-test", "DNS Leak Test (POST)"),
    ("M6", "/api/traceroute", "Traceroute (POST)"),
    ("M7", "/api/device-tags", "Device Tags"),
    ("M7", "/api/bandwidth-quotas", "Bandwidth Quotas"),
    ("M7", "/api/auto-alerts", "Auto Alerts"),
    ("M8", "/api/command-history", "Command History"),
    ("M8", "/api/command-execute", "Command Execute (POST)"),
]

print("\n[PROTECTED ENDPOINTS - CHECKING RESPONSES]")
for module, endpoint, name in endpoints:
    try:
        # Try GET first
        resp = session.get(f"{BASE_URL}{endpoint}", timeout=5)
        
        status_code = resp.status_code
        if status_code == 200:
            try:
                data = resp.json()
                data_type = type(data).__name__
                if isinstance(data, dict):
                    keys = list(data.keys())
                    print(f"[OK] [{module}] {endpoint}: 200 OK - Keys: {keys[:3]}")
                elif isinstance(data, list):
                    print(f"[OK] [{module}] {endpoint}: 200 OK - List with {len(data)} items")
                else:
                    print(f"[OK] [{module}] {endpoint}: 200 OK - {data_type}")
            except:
                print(f"[OK] [{module}] {endpoint}: 200 OK - Non-JSON response ({len(resp.text)} bytes)")
        elif status_code == 401:
            print(f"[AUTH] [{module}] {endpoint}: 401 UNAUTHORIZED - Auth required")
        elif status_code == 302:
            print(f"[REDIR] [{module}] {endpoint}: 302 REDIRECT - Needs auth redirect")
        else:
            print(f"[FAIL] [{module}] {endpoint}: {status_code} - {resp.text[:50]}")
    except Exception as e:
        print(f"[ERROR] [{module}] {endpoint}: {str(e)[:60]}")

print("\n" + "="*80)
print("DIAGNOSTIC TEST COMPLETE")
print("="*80 + "\n")

# Summary
print("\nSummary:")
print("- [OK] = Endpoint responding successfully (200)")
print("- [AUTH] = Endpoint exists but needs authentication (401)")
print("- [REDIR] = Endpoint redirects to login (302)")
print("- [FAIL] = Endpoint returned error")
print("- [ERROR] = Connection/network issue")
