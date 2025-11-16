# Migrate Router-Dash to C:\ and reinstall NSSM service.
# Run this script in Administrator PowerShell.

param(
    [string]$Source = "C:\Users\ammif\OneDrive\documents\Projects\Router-Dash",
    [string]$Target = "C:\Router-Dash",
    [string]$ServiceName = "RouterDashboard",
    [switch]$Force
)

Write-Host "=== Router Dashboard - Migrate to C:\ ===" -ForegroundColor Cyan
Write-Host "Source: $Source`nTarget: $Target`nServiceName: $ServiceName`n" -ForegroundColor Cyan

if (-not (Test-Path $Source)) {
    Write-Host "ERROR: Source path not found: $Source" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $Target)) {
    Write-Host "Creating target directory: $Target" -ForegroundColor Green
    New-Item -ItemType Directory -Path $Target | Out-Null
}

# Stop and remove service if exists
Write-Host "Stopping and removing existing service (if any)..." -ForegroundColor Yellow
C:\nssm\nssm.exe stop $ServiceName 2>$null | Out-Null
Start-Sleep -Seconds 1
C:\nssm\nssm.exe remove $ServiceName confirm 2>$null | Out-Null

# Copy files
Write-Host "Copying files (this may take a moment)..." -ForegroundColor Green
robocopy $Source $Target /MIR /XD .git .venv /NFL /NDL /NJH /NJS /NP /MT:8 | Out-Null

# Create venv if doesn't exist
if (-not (Test-Path "$Target\.venv")) {
    Write-Host "Creating virtualenv in target folder..." -ForegroundColor Green
    python -m venv "$Target\.venv"
}

# Activate and install requirements
Write-Host "Activating venv and installing dependencies..." -ForegroundColor Green
& "$Target\.venv\Scripts\Activate.ps1"
Set-Location $Target
pip install -q -r requirements.txt

# Ensure NSSM installed
if (-not (Test-Path "C:\nssm\nssm.exe")) {
    Write-Host "ERROR: NSSM is not installed. Please install it or re-run install_service.ps1" -ForegroundColor Red
    exit 1
}

# Reinstall service
Write-Host "Installing service with NSSM..." -ForegroundColor Green
C:\nssm\nssm.exe install $ServiceName "$Target\.venv\Scripts\python.exe" "$Target\service.py"
C:\nssm\nssm.exe set $ServiceName AppDirectory "$Target"
C:\nssm\nssm.exe set $ServiceName AppStdout "$Target\logs\service.log"
C:\nssm\nssm.exe set $ServiceName AppStderr "$Target\logs\service_error.log"
C:\nssm\nssm.exe set $ServiceName Start SERVICE_AUTO_START

Write-Host "Starting service..." -ForegroundColor Green
C:\nssm\nssm.exe start $ServiceName
Start-Sleep -Seconds 3
Get-Service $ServiceName | Format-List Status,DisplayName,StartType

Write-Host "If the service is Paused, check logs under $Target\logs and event viewer for NSSM errors." -ForegroundColor Yellow
