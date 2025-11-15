#Requires -RunAsAdministrator

# Install Router Dashboard as a Windows Service using NSSM
# This allows the application to run automatically on system startup

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Router Dashboard - Service Installation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$serviceName = "RouterDashboard"
$currentPath = Get-Location
$pythonExe = Join-Path $currentPath ".venv\Scripts\python.exe"
$appScript = Join-Path $currentPath "app.py"

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

# Check if NSSM is installed
$nssmPath = "C:\nssm\nssm.exe"
if (-not (Test-Path $nssmPath)) {
    Write-Host "NSSM not found. Downloading..." -ForegroundColor Yellow
    
    # Create nssm directory
    New-Item -ItemType Directory -Path "C:\nssm" -Force | Out-Null
    
    # Download NSSM
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $nssmZip = "C:\nssm\nssm.zip"
    
    try {
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip
        Expand-Archive -Path $nssmZip -DestinationPath "C:\nssm" -Force
        
        # Copy the appropriate version
        $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
        Copy-Item "C:\nssm\nssm-2.24\$arch\nssm.exe" "C:\nssm\nssm.exe" -Force
        
        # Clean up
        Remove-Item $nssmZip -Force
        Remove-Item "C:\nssm\nssm-2.24" -Recurse -Force
        
        Write-Host "NSSM installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "ERROR: Failed to download NSSM: $_" -ForegroundColor Red
        Write-Host "Please download manually from https://nssm.cc/download" -ForegroundColor Yellow
        exit 1
    }
}

# Check if service already exists
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Service '$serviceName' already exists. Stopping and removing..." -ForegroundColor Yellow
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & $nssmPath remove $serviceName confirm
    Start-Sleep -Seconds 2
}

Write-Host "Installing Router Dashboard service..." -ForegroundColor Green

# Install service
& $nssmPath install $serviceName $pythonExe $appScript

# Configure service
& $nssmPath set $serviceName AppDirectory $currentPath
& $nssmPath set $serviceName DisplayName "Router Dashboard"
& $nssmPath set $serviceName Description "Network monitoring and management dashboard for routers"
& $nssmPath set $serviceName Start SERVICE_AUTO_START
& $nssmPath set $serviceName AppStdout "$currentPath\logs\service.log"
& $nssmPath set $serviceName AppStderr "$currentPath\logs\service_error.log"
& $nssmPath set $serviceName AppRotateFiles 1
& $nssmPath set $serviceName AppRotateBytes 10485760  # 10MB

# Set environment variables
& $nssmPath set $serviceName AppEnvironmentExtra "FLASK_ENV=production"

Write-Host ""
Write-Host "Service installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Starting service..." -ForegroundColor Green
Start-Service -Name $serviceName

Start-Sleep -Seconds 3

# Check service status
$service = Get-Service -Name $serviceName
if ($service.Status -eq "Running") {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "SUCCESS! Service is running" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Service Name:   $serviceName" -ForegroundColor White
    Write-Host "Status:         Running" -ForegroundColor Green
    Write-Host "Startup Type:   Automatic" -ForegroundColor White
    Write-Host ""
    Write-Host "Access your dashboard at:" -ForegroundColor Yellow
    Write-Host "  http://localhost:5000" -ForegroundColor Cyan
    Write-Host "  http://[Your-IP]:5000" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Useful commands:" -ForegroundColor White
    Write-Host "  Stop:    Stop-Service $serviceName" -ForegroundColor Gray
    Write-Host "  Start:   Start-Service $serviceName" -ForegroundColor Gray
    Write-Host "  Restart: Restart-Service $serviceName" -ForegroundColor Gray
    Write-Host "  Remove:  $nssmPath remove $serviceName confirm" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "ERROR: Service failed to start!" -ForegroundColor Red
    Write-Host "Check logs at: $currentPath\logs\service_error.log" -ForegroundColor Yellow
}
