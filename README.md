# Router Dashboard

A secure Flask-based web dashboard for monitoring router status with user authentication.

## Features

### Core Features
- ✅ User authentication with secure password hashing
- ✅ Real-time router status monitoring
- ✅ Response time tracking
- ✅ Login rate limiting
- ✅ CSRF protection
- ✅ Activity logging
- ✅ Session management

### 🆕 Device Management Features
- ✏️ **Edit Device Names** - Customize device names for easy identification
- 🆕 **New Device Detection** - Automatic badges for newly discovered devices
- 🔒 **Block/Unblock Devices** - Control device network access
- 📊 **Device Information** - MAC address, IP, connection time, bandwidth tracking
- 🎯 **Drag & Drop** - Intuitive interface for device management

## Security Improvements Made

1. **Removed Hardcoded Credentials** - Router config now uses environment variables
2. **Added CSRF Protection** - All forms now protected with Flask-WTF
3. **Implemented Rate Limiting** - Prevents brute force attacks on login
4. **Input Validation** - Form data validation and sanitization
5. **Error Handling** - Proper exception handling and logging
6. **Environment Variables** - Sensitive config moved to .env file
7. **Secure Session Storage** - Session timestamps properly tracked
8. **Logging** - All security events logged to file and console

## Prerequisites

- Python 3.8+
- pip
- Virtual environment (recommended)

## Setup Instructions

### 1. Clone or Setup the Project

```bash
cd Router-Dash
```

### 2. Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Edit `.env` and set:
- `SECRET_KEY` to a secure random string (use `python -c "import secrets; print(secrets.token_hex(32))"`)
- `ROUTER_IP` to your router's IP address
- `FLASK_ENV` to `development` for testing, `production` for deployment

### 5. Initialize Database

```bash
python app.py
```

This will:
- Create the SQLite database
- Generate random admin credentials
- Save credentials to `admin_credentials.txt`

### 6. Save Admin Credentials

The admin credentials will be saved to `admin_credentials.txt`. Save them securely (password manager), then delete the file.

### 7. Run the Application

```bash
python app.py
```

Access at `http://localhost:5000`

## Usage

1. Login with admin credentials from `admin_credentials.txt`
2. View real-time router status on dashboard
3. Click "Refresh" to manually check router status
4. Logout when finished

## Configuration

### Router IP Address

Edit `.env`:
```
ROUTER_IP=192.168.1.1
```

### Flask Settings

- `FLASK_ENV`: Set to `development` or `production`
- `FLASK_HOST`: Default is `localhost` (set to `0.0.0.0` for network access)
- `FLASK_PORT`: Default is `5000`

### Secret Key

Generate a new secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the output into `.env` as `SECRET_KEY`.

## Project Structure

```
Router-Dash/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── .env                      # Environment variables (local)
├── .env.example              # Environment template
├── .gitignore               # Git ignore rules
├── templates/
│   ├── login.html           # Login page
│   └── dashboard.html       # Dashboard page
├── instance/                # Instance-specific files
└── router_dashboard.log     # Application logs
```

## Logging

All application logs are saved to `router_dashboard.log` and also printed to console.

### View Logs

```bash
# Windows
type router_dashboard.log

# macOS/Linux
tail -f router_dashboard.log
```

## Database

The application uses SQLite. Database file: `router_dashboard.db`

### Models

- **User**: Stores user accounts and hashed passwords
- **RouterStatus**: Stores router status history with timestamps

## API Endpoints

### GET /api/router-status
Returns current router status.

**Authentication**: Required (login_required)

**Response:**
```json
{
  "status": "online|offline",
  "response_time": 12.34,
  "error_message": null
}
```

## Common Issues

### Router not responding
- Check if router IP is correct in `.env`
- Ensure router is powered on and connected
- Verify network connectivity

### Admin credentials file missing
- Run `python app.py` again to regenerate
- The credentials are only generated once on first run

### Port already in use
- Change `FLASK_PORT` in `.env`
- Or use: `netstat -ano | findstr :5000` (Windows) to find process using port

## Production Deployment

1. Generate strong SECRET_KEY
2. Set `FLASK_ENV=production`
3. Set `FLASK_HOST=localhost` (do not expose directly)
4. Use a production WSGI server (Gunicorn, uWSGI)
5. Set up HTTPS/SSL
6. Use environment-specific .env file
7. Implement database backups

Example with Gunicorn:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## Troubleshooting

### Virtual Environment Not Activating
```bash
# Windows
venv\Scripts\activate.bat

# macOS/Linux
source venv/bin/activate
```

### Import Errors
```bash
pip install --upgrade -r requirements.txt
```

### Database Locked
Delete `instance/router_dashboard.db` and restart:
```bash
rm instance/router_dashboard.db
python app.py
```

## 🚀 Quick Start - Device Management

The dashboard now includes powerful device management features:

### ✏️ Edit Device Names
1. Go to **Connected Devices** tab
2. Click **✏️ Edit** on any device
3. Change the device name
4. Click **Save Changes** - name persists automatically!

### 🆕 See New Devices
- Newly discovered devices show with a **🆕 NEW** badge
- A summary banner appears at the top listing all new devices
- Perfect for spotting unauthorized devices on your network

### 🔒 Block/Unblock Devices
1. Click **🔒 Lock** button to block device from network
2. Device appears faded - status is blocked
3. Click **🔓 Unlock** button to allow device back on network
4. Status persists across sessions

### 📚 Documentation
- **Quick Start Guide**: `DEVICE_MANAGEMENT_QUICK_START.md` - User-friendly walkthrough
- **Technical Docs**: `DEVICE_MANAGEMENT_FEATURES.md` - Full API and implementation details
- **Session Summary**: `SESSION_SUMMARY.md` - Complete implementation report

## Security Notes

- ⚠️ Never commit `.env` file to version control
- ⚠️ Use strong, unique SECRET_KEY for production
- ⚠️ Don't share `admin_credentials.txt` - delete after saving
- ⚠️ Enable HTTPS in production
- ⚠️ Keep Flask and dependencies updated
- ⚠️ Use environment-specific configurations

## License

© 2025 Router Dashboard

## Support

For issues or questions, check logs in `router_dashboard.log`.
