#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Router Dashboard - Firewall Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Remove existing rule if it exists
Write-Host "Checking for existing firewall rules..." -ForegroundColor Yellow
$existingRule = Get-NetFirewallRule -DisplayName "Router Dashboard*" -ErrorAction SilentlyContinue
if ($existingRule) {
    Write-Host "Removing old firewall rules..." -ForegroundColor Yellow
    Remove-NetFirewallRule -DisplayName "Router Dashboard*"
}

# Create new firewall rule
Write-Host "Creating firewall rule to allow port 5000..." -ForegroundColor Green
New-NetFirewallRule -DisplayName "Router Dashboard - HTTP" `
    -Direction Inbound `
    -LocalPort 5000 `
    -Protocol TCP `
    -Action Allow `
    -Profile Domain,Private `
    -Description "Allow incoming connections to Router Dashboard web interface"

Write-Host ""
Write-Host "SUCCESS! Firewall configured." -ForegroundColor Green
Write-Host ""
Write-Host "Router Dashboard is now accessible from:" -ForegroundColor White

# Get local IP addresses
$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"} | Select-Object -ExpandProperty IPAddress

Write-Host "  - http://localhost:5000 (this PC)" -ForegroundColor Cyan
foreach ($ip in $ipAddresses) {
    Write-Host "  - http://${ip}:5000 (from network devices)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Note: Make sure the application is running!" -ForegroundColor Gray
Write-Host "Run: .\run_production.ps1" -ForegroundColor Gray
Write-Host ""
