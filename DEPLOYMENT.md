# Router Dashboard - Enterprise Deployment Guide

## Quick Start (Windows Production Deployment)

### Option 1: Run as Application (Simplest)

```powershell
# Run the production server
.\run_production.ps1
```

Access from any device on your network:
- From this PC: `http://localhost:5000`
- From other devices: `http://YOUR-PC-IP:5000`

### Option 2: Install as Windows Service (Recommended)

This makes the dashboard start automatically when Windows boots:

```powershell
# Run PowerShell as Administrator
.\install_service.ps1
```

Service management:
```powershell
# Stop service
Stop-Service RouterDashboard

# Start service
Start-Service RouterDashboard

# Restart service
Restart-Service RouterDashboard

# Check status
Get-Service RouterDashboard
```

## Firewall Configuration

Allow incoming connections on port 5000:

```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "Router Dashboard" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

## Network Access Setup

### Find Your PC's IP Address

```powershell
# Get your local IP
ipconfig | findstr IPv4
```

### Access from Other Devices

Once the server is running, access from any device on your network:

- **From Windows/Mac/Linux PC:** `http://192.168.x.x:5000`
- **From Phone/Tablet:** Open browser and go to `http://192.168.x.x:5000`
- **From Smart TV:** Use built-in browser

Replace `192.168.x.x` with your PC's actual IP address.

## Production Configuration

### Environment Variables (.env)

Update these for production use:

```env
SECRET_KEY=YOUR_SECURE_RANDOM_KEY_HERE_AT_LEAST_32_CHARS
FLASK_ENV=production
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
```

Generate a secure secret key:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

### Security Recommendations

1. **Change Default Password:**
   - Login and change the default admin credentials immediately

2. **Enable HTTPS (Optional but recommended):**
   - Use nginx reverse proxy with SSL certificate
   - Or use self-signed certificate for internal network

3. **Restrict Access:**
   - Use firewall rules to limit access to specific IP ranges
   - Consider VPN for external access

4. **Regular Backups:**
   ```powershell
   # Backup database
   Copy-Item instance\dashboard.db instance\dashboard.db.backup
   ```

## Performance Tuning

### For High-Traffic Environments

1. **Increase Workers (in run_production.ps1):**
   ```powershell
   # Increase threads for Waitress
   serve(app, host='0.0.0.0', port=5000, threads=10)
   ```

2. **Database Optimization:**
   - Monitor database size in `instance\dashboard.db`
   - Adjust retention days in `.env`: `LOG_RETENTION_DAYS=30`

3. **Memory Usage:**
   - Default traffic log buffer: 500 entries
   - Adjust in app.py if needed: `request_log = deque(maxlen=500)`

## Troubleshooting

### Cannot Access from Other Devices

1. **Check Firewall:**
   ```powershell
   Get-NetFirewallRule -DisplayName "Router Dashboard"
   ```

2. **Verify Server is Listening:**
   ```powershell
   netstat -an | findstr 5000
   ```
   Should show: `0.0.0.0:5000` (not `127.0.0.1:5000`)

3. **Test Connection:**
   ```powershell
   # From another device
   Test-NetConnection -ComputerName YOUR-PC-IP -Port 5000
   ```

### Service Won't Start

1. **Check Logs:**
   ```powershell
   Get-Content logs\service_error.log -Tail 50
   ```

2. **Check Service Status:**
   ```powershell
   Get-Service RouterDashboard | Format-List *
   ```

3. **Restart Service:**
   ```powershell
   Restart-Service RouterDashboard
   ```

### High CPU Usage

- Check number of connected devices refreshing dashboard
- Reduce polling frequency in frontend
- Increase snapshot interval in background tasks

## Advanced Deployment

### Using Nginx Reverse Proxy

1. Install nginx for Windows
2. Copy `nginx.conf` configuration
3. Update server name and paths
4. Run dashboard on localhost:5000
5. Access via nginx on port 80/443

### Docker Deployment (Alternative)

See separate Docker documentation for containerized deployment.

### Load Balancing (Multiple Instances)

For extremely high availability:
- Deploy multiple instances on different ports
- Use nginx to load balance between them
- Share database file via network storage

## Monitoring

### Application Logs

- **Access Log:** `logs\access.log`
- **Error Log:** `logs\error.log`
- **Service Log:** `logs\service.log`

### System Monitoring

Monitor the application itself:
- CPU usage via Task Manager
- Memory usage via Performance Monitor
- Network connections via Resource Monitor

## Updates and Maintenance

### Updating the Application

```powershell
# Stop service
Stop-Service RouterDashboard

# Backup database
Copy-Item instance\dashboard.db instance\dashboard.db.backup

# Pull updates (if using git)
git pull

# Update dependencies
.\.venv\Scripts\activate
pip install -r requirements.txt

# Start service
Start-Service RouterDashboard
```

### Database Maintenance

```powershell
# Compact database
python -c "from app import db, app; app.app_context().push(); db.engine.execute('VACUUM')"
```

## Support

For issues or questions:
- Check logs in `logs\` directory
- Review error messages in browser console
- Check application console output
