# Production deployment script for Router Dashboard
# Run this script to start the application in production mode

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Router Dashboard - Production Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path ".venv")) {
    Write-Host "ERROR: Virtual environment not found!" -ForegroundColor Red
    Write-Host "Please run: python -m venv .venv" -ForegroundColor Yellow
    exit 1
}

# Activate virtual environment
Write-Host "[1/5] Activating virtual environment..." -ForegroundColor Green
& .\.venv\Scripts\Activate.ps1

# Install production dependencies
Write-Host "[2/5] Installing/updating dependencies..." -ForegroundColor Green
pip install -q -r requirements.txt

# Check if waitress is installed (better than Flask dev server on Windows)
$waitressInstalled = pip show waitress 2>$null
if (-not $waitressInstalled) {
    Write-Host "Installing Waitress (production WSGI server for Windows)..." -ForegroundColor Yellow
    pip install -q waitress
}

# Create logs directory
Write-Host "[3/5] Setting up directories..." -ForegroundColor Green
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}

# Get local IP address
Write-Host "[4/5] Detecting network configuration..." -ForegroundColor Green
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -like "192.168.*"}).IPAddress | Select-Object -First 1

if (-not $localIP) {
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}).IPAddress | Select-Object -First 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Starting Router Dashboard" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Local Access:    http://localhost:5000" -ForegroundColor White
Write-Host "Network Access:  http://${localIP}:5000" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Set production environment
$env:FLASK_ENV = "production"

# Start application with Waitress (production WSGI server)
Write-Host "[5/5] Starting production server..." -ForegroundColor Green
python -c "from waitress import serve; from app import app; print('Server started successfully!'); serve(app, host='0.0.0.0', port=5000, threads=6)"
