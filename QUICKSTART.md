# Router Dashboard - Quick Start Guide

## 🚀 Deploy in 3 Simple Steps

### Step 1: Configure Firewall (One-time setup)

Open PowerShell **as Administrator** and run:

```powershell
cd "c:\Users\ammif\OneDrive\documents\Projects\Router-Dash"
.\setup_firewall.ps1
```

This allows network devices to connect to your dashboard on port 5000.

### Step 2: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Choose Your Deployment Method

#### Option A: Quick Start (Development/Testing)
```powershell
.\.venv\Scripts\python.exe app.py
```

#### Option B: Production Server (Recommended)
```powershell
.\run_production.ps1
```
Better performance, automatic restarts, and production-ready.

#### Option C: Windows Service (Best for Always-On)
```powershell
# Run PowerShell as Administrator
.\install_service.ps1
```
Starts automatically with Windows. Perfect for 24/7 operation.

## 📱 Access Your Dashboard

### From This PC
```
http://localhost:5000
```

### From Other Devices on Your Network

First, find your PC's IP address:
```powershell
ipconfig | findstr IPv4
```

Then access from any device:
- **Phones/Tablets:** Open browser → `http://YOUR-PC-IP:5000`
- **Other PCs:** Open browser → `http://YOUR-PC-IP:5000`
- **Smart TVs:** Use built-in browser → `http://YOUR-PC-IP:5000`

Example: If your PC IP is `192.168.8.100`, use `http://192.168.8.100:5000`

## 🔧 Common Issues

### "Cannot access from other devices"
1. Check if firewall is configured:
   ```powershell
   Get-NetFirewallRule -DisplayName "Router Dashboard*"
   ```
2. Verify app is running and listening on 0.0.0.0 (not 127.0.0.1)
3. Try disabling Windows Firewall temporarily to test

### "Connection refused"
- Make sure the application is running
- Check that FLASK_HOST=0.0.0.0 in .env file
- Verify port 5000 isn't used by another application:
  ```powershell
  netstat -ano | findstr :5000
  ```

### "Slow performance"
- Use production server (Option B) instead of development server
- Consider installing as Windows Service (Option C)
- Increase thread count in run_production.ps1

## 📊 Service Management (if installed as service)

```powershell
# Start service
Start-Service RouterDashboard

# Stop service
Stop-Service RouterDashboard

# Restart service
Restart-Service RouterDashboard

# Check status
Get-Service RouterDashboard

# View logs
Get-Content logs\service.log -Tail 50
```

## 🔒 Security Tips

1. **Change Default Password**
   - Login and update admin credentials immediately

2. **Generate Secure Secret Key**
   ```powershell
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
   Update SECRET_KEY in .env file

3. **Restrict Access** (Optional)
   ```powershell
   # Allow only specific IP range
   Set-NetFirewallRule -DisplayName "Router Dashboard*" -RemoteAddress 192.168.8.0/24
   ```

## 📈 Monitoring

### Check Application Status
```powershell
# View recent logs
Get-Content logs\error.log -Tail 50

# Monitor in real-time
Get-Content logs\access.log -Wait
```

### Performance Metrics
- Memory usage: Check Task Manager → Details → python.exe
- Active connections: Dashboard shows in Traffic Monitor
- Database size: Check `instance\dashboard.db` file size

## 🎯 Next Steps

1. ✅ Configure firewall
2. ✅ Start production server
3. ✅ Test access from another device
4. ⬜ Change default password
5. ⬜ Update SECRET_KEY in .env
6. ⬜ Configure AdGuard credentials (if using)
7. ⬜ Install as service for automatic startup

## 📚 Full Documentation

See `DEPLOYMENT.md` for detailed enterprise deployment guide.

## ⚡ Pro Tips

- **Bookmark the dashboard** on all your devices for quick access
- **Pin to taskbar** on Windows for easy server management
- **Set static IP** for your PC so the address doesn't change
- **Use hostname** instead of IP: `http://YOUR-PC-NAME:5000`
- **Create desktop shortcut** to run_production.ps1 for one-click start
