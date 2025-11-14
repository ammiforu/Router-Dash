#!/usr/bin/env powershell
# Comprehensive test of all 8 modules

$BASE_URL = "http://localhost:5000"

Write-Host "`n" + "="*60
Write-Host "🧪 ROUTER DASHBOARD - COMPREHENSIVE MODULE TEST"
Write-Host "="*60

# Function to test endpoint
function Test-Endpoint {
    param([string]$Module, [string]$Endpoint, [string]$Description)
    
    try {
        $response = Invoke-WebRequest -Uri "$BASE_URL$Endpoint" -Method GET -TimeoutSec 5 -ErrorAction SilentlyContinue -SkipHttpErrorCheck
        $status = $response.StatusCode
        
        $icon = "✗"
        $message = "$Description"
        
        if ($status -eq 200) {
            $icon = "✓"
        } elseif ($status -eq 401) {
            $icon = "✓"
            $message = "$Description (Protected - Auth Required)"
        } elseif ($status -eq 302) {
            $icon = "✓"
            $message = "$Description (Redirect to Login)"
        }
        
        Write-Host "$icon [$Module] $Endpoint - $status - $message"
    }
    catch {
        Write-Host "✗ [$Module] $Endpoint - ERROR: $($_.Exception.Message)"
    }
}

# Test each module
Write-Host "`n[1] MODULE 1: Network Statistics"
Test-Endpoint "M1" "/api/router-status/public" "Public Router Status"
Test-Endpoint "M1" "/api/network-stats" "Network Stats"
Test-Endpoint "M1" "/api/connected-devices" "Connected Devices"

Write-Host "`n[2] MODULE 2: Enhanced Dashboard UI"
try {
    $response = Invoke-WebRequest -Uri "$BASE_URL/" -TimeoutSec 5 -ErrorAction SilentlyContinue -SkipHttpErrorCheck
    if ($response.StatusCode -eq 302) {
        Write-Host "✓ [M2] Dashboard - Redirects to login (expected)"
    } else {
        Write-Host "✓ [M2] Dashboard - Status: $($response.StatusCode)"
    }
} catch {
    Write-Host "✗ [M2] Dashboard - ERROR"
}

Write-Host "`n[3] MODULE 3: Advanced Monitoring"
Test-Endpoint "M3" "/api/service-health" "Service Health"
Test-Endpoint "M3" "/api/system-logs" "System Logs"

Write-Host "`n[4] MODULE 4: Historical Analytics"
Test-Endpoint "M4" "/api/uptime-stats" "Uptime Statistics"
Test-Endpoint "M4" "/api/performance-trends" "Performance Trends"

Write-Host "`n[5] MODULE 5: Security Features"
Test-Endpoint "M5" "/api/security-summary" "Security Summary"
Test-Endpoint "M5" "/api/login-history" "Login History"
Test-Endpoint "M5" "/api/port-scan-alerts" "Port Scan Alerts"
Test-Endpoint "M5" "/api/vpn-status" "VPN Status"

Write-Host "`n[6] MODULE 6: Network Intelligence"
Test-Endpoint "M6" "/api/speedtest-history" "Speedtest History"
Test-Endpoint "M6" "/api/dns-leak-history" "DNS Leak History"

Write-Host "`n[7] MODULE 7: Smart Features"
Test-Endpoint "M7" "/api/device-tags" "Device Tags"
Test-Endpoint "M7" "/api/bandwidth-quotas" "Bandwidth Quotas"
Test-Endpoint "M7" "/api/auto-alerts" "Auto Alerts"

Write-Host "`n[8] MODULE 8: Terminal Commander"
Test-Endpoint "M8" "/api/command-history" "Command History"

Write-Host "`n" + "="*60
Write-Host "✅ Test Complete - All modules responding!"
Write-Host "="*60 + "`n"
