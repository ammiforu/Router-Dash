# 🔧 QUICK REFERENCE & COMMANDS

## Installation & Setup

### 1. Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Generate SECRET_KEY
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Edit .env
```bash
# Windows - use any text editor
# Add/update:
SECRET_KEY=<paste_the_generated_key_here>
FLASK_ENV=production
FLASK_HOST=localhost
FLASK_PORT=5000
ROUTER_IP=192.168.1.1
```

### 5. First Run
```bash
python app.py
```

### 6. Save Credentials
```bash
# Note down admin credentials from admin_credentials.txt
# Delete the file when done
del admin_credentials.txt
```

---

## Running the Application

### Development Mode
```bash
# In .env set: FLASK_ENV=development
python app.py
```

### Production Mode
```bash
# In .env set: FLASK_ENV=production
python app.py
```

### With Gunicorn (Production)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Specify Port
```bash
# In .env: FLASK_PORT=8000
python app.py
```

---

## Database Operations

### Reset Database
```bash
# Stop the app first
# Delete database
del instance/router_dashboard.db

# Run app to create new database
python app.py
```

### View Database
```bash
# Using sqlite3
sqlite3 instance/router_dashboard.db

# Useful queries:
# .tables                    - list all tables
# SELECT * FROM user;       - list users
# SELECT * FROM router_status ORDER BY last_checked DESC LIMIT 10;
# .quit                      - exit
```

---

## Logging & Debugging

### View Application Logs
```bash
# Windows
type router_dashboard.log

# macOS/Linux - last 50 lines
tail -50 router_dashboard.log

# macOS/Linux - follow live
tail -f router_dashboard.log
```

### Clear Logs
```bash
# Windows
del router_dashboard.log

# macOS/Linux
rm router_dashboard.log
```

### Enable Debug Output
```bash
# In .env: FLASK_ENV=development
# Then run:
python app.py
```

---

## Security

### Regenerate SECRET_KEY
```bash
# Generate new key
python -c "import secrets; print(secrets.token_hex(32))"

# Update .env with new key
# Restart application
```

### Change Admin Credentials
```bash
# Delete database and log files
del instance/router_dashboard.db
del router_dashboard.log

# Run app to create new admin user
python app.py
```

### Check for Exposed Credentials
```bash
# Search for hardcoded passwords in code
grep -r "password" .
grep -r "secret" .
grep -r "credential" .
```

---

## Troubleshooting

### Port Already in Use
```bash
# Windows - find process on port 5000
netstat -ano | findstr :5000

# Kill process (replace PID)
taskkill /PID <PID> /F

# Or use different port
# Edit .env: FLASK_PORT=8000
```

### Module Not Found
```bash
# Update pip
python -m pip install --upgrade pip

# Reinstall requirements
pip install --upgrade -r requirements.txt
```

### Database Locked
```bash
# Stop the app
# Delete database
del instance/router_dashboard.db

# Restart app
python app.py
```

### Permission Denied
```bash
# Windows - run as Administrator
# macOS/Linux - use sudo (not recommended)
# Better: fix permissions
chmod 755 .
chmod 644 app.py
```

### Import Error: werkzeug.security
```bash
# Reinstall Flask-Login and werkzeug
pip install --upgrade Flask-Login werkzeug
```

---

## Configuration

### Change Router IP
```bash
# Edit .env
ROUTER_IP=192.168.1.1

# Verify ping works manually
ping 192.168.1.1
```

### Change Port
```bash
# Edit .env
FLASK_PORT=8000
FLASK_HOST=localhost

# Access at http://localhost:8000
```

### Development vs Production
```bash
# Development (debug ON)
FLASK_ENV=development
FLASK_HOST=localhost
FLASK_PORT=5000

# Production (debug OFF)
FLASK_ENV=production
FLASK_HOST=localhost        # Use reverse proxy for external access
FLASK_PORT=5000
```

---

## Testing

### Test Rate Limiting
```bash
# Manual test - go to login page
# Try wrong password 6 times
# Should get locked out for 5 minutes

# To reset:
del instance/router_dashboard.db
python app.py
```

### Test Router Status
```bash
# Login to dashboard
# Click "Refresh" button
# Should see status update

# Check if ping works manually
ping <ROUTER_IP>
```

### Test API Endpoint
```bash
# Using curl (Windows PowerShell):
$headers = @{"Cookie"="session=..."} 
Invoke-WebRequest -Uri "http://localhost:5000/api/router-status" -Headers $headers

# Using curl (bash):
curl -b "session=..." http://localhost:5000/api/router-status
```

---

## Maintenance

### Backup Database
```bash
# Windows
copy instance\router_dashboard.db router_dashboard_backup.db

# macOS/Linux
cp instance/router_dashboard.db router_dashboard_backup.db
```

### Backup Configuration
```bash
# Never backup .env (contains secrets)
# Backup .env.example only
copy .env.example .env.example.backup
```

### Archive Logs
```bash
# Windows
rename router_dashboard.log router_dashboard_%date%.log

# macOS/Linux
mv router_dashboard.log router_dashboard_$(date +%Y%m%d).log
```

### Check Disk Space
```bash
# Windows
dir /-s /b | find /c ":"

# macOS/Linux
du -sh .
ls -lh *.log *.db
```

---

## Deployment

### Prepare for Deployment
```bash
# 1. Generate strong SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# 2. Create production .env
# FLASK_ENV=production
# SECRET_KEY=<strong_key>
# ROUTER_IP=<your_router_ip>
# FLASK_HOST=localhost
# FLASK_PORT=5000

# 3. Test locally
python app.py

# 4. Check logs
type router_dashboard.log

# 5. Ready to deploy
```

### Deploy with Gunicorn
```bash
pip install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Run in background (Linux/macOS)
gunicorn -w 4 -b 0.0.0.0:5000 app:app &

# Run with Nginx reverse proxy (recommended)
# Edit /etc/nginx/sites-available/default
# proxy_pass http://127.0.0.1:5000;
```

---

## Advanced

### Increase Log Level
```python
# In app.py, change:
logging.basicConfig(
    level=logging.DEBUG,  # Changed from INFO
    ...
)
```

### Enable Profiling
```python
# In app.py, add before app.run():
from werkzeug.middleware.profiler import ProfilerMiddleware
app = ProfilerMiddleware(app, restrictions=[30])
```

### Monitor Application
```bash
# Python package
pip install flask-debugtoolbar

# Add to app.py
from flask_debugtoolbar import DebugToolbarExtension
toolbar = DebugToolbarExtension(app)
```

### Performance Monitoring
```bash
# Use built-in Python profiler
python -m cProfile -s cumulative app.py

# Check with psutil
pip install psutil
python -c "import psutil; print(psutil.Process().memory_info())"
```

---

## Git Commands

### Initialize Repository
```bash
git init
git config user.name "Your Name"
git config user.email "your@email.com"
```

### Commit Changes
```bash
git add .
git status
git commit -m "Initial commit: secure Flask app"
```

### Check What's Tracked
```bash
git ls-files
```

### View .gitignore
```bash
cat .gitignore
```

---

## Environment Variables

### View Current .env
```bash
# Windows
type .env

# macOS/Linux
cat .env
```

### List Set Variables
```bash
# Windows
set | grep FLASK

# macOS/Linux
env | grep FLASK
```

### Test .env Loading
```python
# Python script to test
from dotenv import load_dotenv
import os

load_dotenv()
print(f"SECRET_KEY: {os.environ.get('SECRET_KEY')}")
print(f"FLASK_ENV: {os.environ.get('FLASK_ENV')}")
print(f"ROUTER_IP: {os.environ.get('ROUTER_IP')}")
```

---

## File Management

### List Project Files
```bash
# Windows
dir /s

# macOS/Linux
find . -type f -not -path './.git/*' -not -path './__pycache__/*'
```

### Find Large Files
```bash
# Windows
dir /s | find "KB"

# macOS/Linux
find . -type f -size +10M
```

### Check Database Size
```bash
# Windows
dir instance\

# macOS/Linux
ls -lh instance/
```

---

## Python Virtual Environment

### List Installed Packages
```bash
pip list
```

### Freeze Requirements
```bash
pip freeze > requirements_full.txt
```

### Check Outdated Packages
```bash
pip list --outdated
```

### Update All Packages
```bash
# Windows
for /F "delims===" %i in ('pip list --outdated --format=json') do pip install --upgrade %i

# macOS/Linux (safer)
pip install --upgrade -r requirements.txt
```

---

## Health Checks

### Quick Health Check
```bash
# 1. Check Python
python --version

# 2. Check packages
pip list | grep -i flask

# 3. Check .env
type .env

# 4. Check database
dir instance\

# 5. Check logs
type router_dashboard.log

# 6. Test app
python app.py
# Press Ctrl+C after 5 seconds
```

### Complete Diagnostics
```bash
# Create diagnostic script
python -c "
import sys
import flask
import flask_sqlalchemy
import flask_login

print(f'Python: {sys.version}')
print(f'Flask: {flask.__version__}')
print(f'Flask-SQLAlchemy: {flask_sqlalchemy.__version__}')
print(f'Flask-Login: {flask_login.__version__}')
"
```

---

## Common Issues

### Issue: ModuleNotFoundError: No module named 'flask_wtf'
```bash
Solution: pip install Flask-WTF==1.1.1
```

### Issue: Address already in use
```bash
Solution: Change FLASK_PORT in .env or kill process on port 5000
```

### Issue: SECRET_KEY not set error
```bash
Solution: Add SECRET_KEY=... to .env and restart
```

### Issue: Cannot connect to router
```bash
Solution: 
1. Check ROUTER_IP in .env
2. Verify router is powered on
3. Test: ping <ROUTER_IP>
```

---

**Bookmark this page for quick reference! 🔖**
