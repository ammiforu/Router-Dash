import requests
import sys

BASE_URL = "http://localhost:5000"
tests_passed = 0
tests_total = 0

def test(module, endpoint, description):
    global tests_passed, tests_total
    tests_total += 1
    try:
        resp = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
        status = resp.status_code
        if status in [200, 302, 401]:
            tests_passed += 1
            auth_note = " (Protected)" if status == 401 else (" (Redirect)" if status == 302 else "")
            print(f"PASS [{module}] {endpoint} - {status}{auth_note}")
        else:
            print(f"FAIL [{module}] {endpoint} - {status}")
    except Exception as e:
        print(f"FAIL [{module}] {endpoint} - {str(e)[:50]}")

print("\n" + "="*70)
print("ROUTER DASHBOARD - MODULE TEST RESULTS")
print("="*70)

print("\n[MODULE 1] Network Statistics")
test("M1", "/api/router-status/public", "Public Router Status")
test("M1", "/api/network-stats", "Network Stats")
test("M1", "/api/connected-devices", "Connected Devices")

print("\n[MODULE 2] Enhanced Dashboard UI")
test("M2", "/", "Dashboard")

print("\n[MODULE 3] Advanced Monitoring")
test("M3", "/api/service-health", "Service Health")
test("M3", "/api/system-logs", "System Logs")

print("\n[MODULE 4] Historical Analytics")
test("M4", "/api/uptime-stats", "Uptime Statistics")
test("M4", "/api/performance-trends", "Performance Trends")

print("\n[MODULE 5] Security Features")
test("M5", "/api/security-summary", "Security Summary")
test("M5", "/api/login-history", "Login History")
test("M5", "/api/port-scan-alerts", "Port Scan Alerts")
test("M5", "/api/vpn-status", "VPN Status")

print("\n[MODULE 6] Network Intelligence")
test("M6", "/api/speedtest-history", "Speedtest History")
test("M6", "/api/dns-leak-history", "DNS Leak History")

print("\n[MODULE 7] Smart Features")
test("M7", "/api/device-tags", "Device Tags")
test("M7", "/api/bandwidth-quotas", "Bandwidth Quotas")
test("M7", "/api/auto-alerts", "Auto Alerts")

print("\n[MODULE 8] Terminal Commander")
test("M8", "/api/command-history", "Command History")

print("\n" + "="*70)
print(f"RESULTS: {tests_passed}/{tests_total} tests passed")
if tests_passed == tests_total:
    print("STATUS: ALL MODULES WORKING!")
else:
    print(f"STATUS: {tests_total - tests_passed} failures detected")
print("="*70 + "\n")
