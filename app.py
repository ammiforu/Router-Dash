from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import random
import string
import os
from datetime import datetime, timedelta
import logging
from dotenv import load_dotenv
import subprocess
import platform
import socket
import time
import psutil
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
csrf = CSRFProtect(app)

# Validate required environment variables
if not app.secret_key:
    raise ValueError("SECRET_KEY environment variable is not set")

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///router_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('router_dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Rate limiting data
login_attempts = {}

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class RouterStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), nullable=False)  # 'online' or 'offline'
    response_time = db.Column(db.Float, nullable=True)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    error_message = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'status': self.status,
            'response_time': self.response_time,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None,
            'error_message': self.error_message
        }

class NetworkStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    bytes_sent = db.Column(db.BigInteger, nullable=True)
    bytes_recv = db.Column(db.BigInteger, nullable=True)
    packets_sent = db.Column(db.BigInteger, nullable=True)
    packets_recv = db.Column(db.BigInteger, nullable=True)
    cpu_usage = db.Column(db.Float, nullable=True)
    memory_usage = db.Column(db.Float, nullable=True)
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'bytes_sent': self.bytes_sent,
            'bytes_recv': self.bytes_recv,
            'packets_sent': self.packets_sent,
            'packets_recv': self.packets_recv,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage
        }

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)  # 'login_attempt', 'port_scan', 'rule_violation', etc
    severity = db.Column(db.String(20), nullable=False)  # 'info', 'warning', 'critical'
    message = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(15), nullable=True)
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'severity': self.severity,
            'message': self.message,
            'source_ip': self.source_ip
        }

class ServiceStatus(db.Model):
    """Track status of system services"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    service_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'running', 'stopped', 'error'
    uptime = db.Column(db.Float, nullable=True)  # in seconds
    memory_usage = db.Column(db.Float, nullable=True)  # in MB
    cpu_usage = db.Column(db.Float, nullable=True)  # percentage
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'service_name': self.service_name,
            'status': self.status,
            'uptime': self.uptime,
            'memory_usage': self.memory_usage,
            'cpu_usage': self.cpu_usage
        }

class SystemLog(db.Model):
    """Store system event logs for real-time monitoring"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    log_type = db.Column(db.String(50), nullable=False)  # 'system', 'network', 'application', 'security'
    level = db.Column(db.String(20), nullable=False)  # 'DEBUG', 'INFO', 'WARNING', 'ERROR'
    component = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'log_type': self.log_type,
            'level': self.level,
            'component': self.component,
            'message': self.message
        }

class UptimeRecord(db.Model):
    """Track router uptime and downtime events"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # 'online', 'offline'
    duration_seconds = db.Column(db.Integer, nullable=True)  # duration of the status
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'duration_seconds': self.duration_seconds
        }

class PerformanceSnapshot(db.Model):
    """Store performance snapshots for historical analysis"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_avg = db.Column(db.Float, nullable=False)  # average CPU for the period
    memory_avg = db.Column(db.Float, nullable=False)  # average memory for the period
    network_bytes_sent = db.Column(db.Integer, nullable=False)
    network_bytes_recv = db.Column(db.Integer, nullable=False)
    connected_devices_count = db.Column(db.Integer, nullable=False)
    period_minutes = db.Column(db.Integer, default=5)  # aggregation period in minutes
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'cpu_avg': self.cpu_avg,
            'memory_avg': self.memory_avg,
            'network_bytes_sent': self.network_bytes_sent,
            'network_bytes_recv': self.network_bytes_recv,
            'connected_devices_count': self.connected_devices_count,
            'period_minutes': self.period_minutes
        }

        return {
            'timestamp': self.timestamp.isoformat(),
            'log_type': self.log_type,
            'level': self.level,
            'component': self.component,
            'message': self.message
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_random_credentials():
    """Generate random username and password"""
    username = 'admin_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=16))
    return username, password

def rate_limit_check(username, max_attempts=5, lockout_time=300):
    """Check if user has exceeded login attempts"""
    now = datetime.now()
    
    if username not in login_attempts:
        login_attempts[username] = []
    
    # Remove old attempts outside lockout window
    login_attempts[username] = [
        attempt for attempt in login_attempts[username] 
        if (now - attempt).total_seconds() < lockout_time
    ]
    
    if len(login_attempts[username]) >= max_attempts:
        return False, f"Too many login attempts. Please try again in {lockout_time // 60} minutes."
    
    return True, None

def record_login_attempt(username):
    """Record a failed login attempt"""
    if username not in login_attempts:
        login_attempts[username] = []
    login_attempts[username].append(datetime.now())

def check_router_status():
    """Check if router is online and measure response time"""
    router_ip = os.environ.get('ROUTER_IP', '192.168.1.1')
    
    try:
        # Ping the router
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', router_ip]
        
        start_time = datetime.now()
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        end_time = datetime.now()
        
        response_time = (end_time - start_time).total_seconds() * 1000  # Convert to milliseconds
        
        if result.returncode == 0:
            return {
                'status': 'online',
                'response_time': round(response_time, 2),
                'error_message': None
            }
        else:
            return {
                'status': 'offline',
                'response_time': None,
                'error_message': 'Ping failed'
            }
            
    except subprocess.TimeoutExpired:
        return {
            'status': 'offline',
            'response_time': None,
            'error_message': 'Ping timeout'
        }
    except Exception as e:
        logger.error(f"Error checking router status: {str(e)}")
        return {
            'status': 'offline',
            'response_time': None,
            'error_message': 'Unable to check status'
        }

def get_network_stats():
    """Get system network statistics"""
    try:
        net_stats = psutil.net_io_counters()
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        
        return {
            'bytes_sent': net_stats.bytes_sent,
            'bytes_recv': net_stats.bytes_recv,
            'packets_sent': net_stats.packets_sent,
            'packets_recv': net_stats.packets_recv,
            'cpu_usage': cpu_usage,
            'memory_usage': memory_info.percent,
            'memory_total': memory_info.total,
            'memory_available': memory_info.available,
        }
    except Exception as e:
        logger.error(f"Error getting network stats: {str(e)}")
        return None

def get_connected_devices():
    """Get list of connected devices"""
    try:
        devices = []
        if platform.system() == 'Windows':
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            for line in lines:
                if '192.168' in line or '10.0' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        devices.append({
                            'ip': parts[0],
                            'mac': parts[1],
                            'type': parts[2] if len(parts) > 2 else 'dynamic'
                        })
        return devices[:50]
    except Exception as e:
        logger.error(f"Error getting connected devices: {str(e)}")
        return []

def get_service_health():
    """Get system service health status"""
    services = []
    try:
        # Get process information
        for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info', 'cpu_num']):
            try:
                if proc.name() in ['python.exe', 'nginx', 'mysql', 'dnsmasq', 'hostapd']:
                    services.append({
                        'name': proc.name(),
                        'status': 'running',
                        'pid': proc.pid,
                        'memory_mb': proc.memory_info().rss / 1024 / 1024,
                        'cpu_percent': proc.cpu_percent(interval=0.1)
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Add common services that might not be running
        for service_name in ['DNS', 'DHCP', 'Firewall']:
            if not any(s['name'] == service_name for s in services):
                services.append({
                    'name': service_name,
                    'status': 'unknown',
                    'pid': None,
                    'memory_mb': 0,
                    'cpu_percent': 0
                })
        
        return services
    except Exception as e:
        logger.error(f"Error getting service health: {str(e)}")
        return []

def get_system_logs(limit=100, log_type=None):
    """Get recent system logs"""
    try:
        query = SystemLog.query.order_by(SystemLog.timestamp.desc())
        if log_type:
            query = query.filter_by(log_type=log_type)
        return [log.to_dict() for log in query.limit(limit).all()]
    except Exception as e:
        logger.error(f"Error getting system logs: {str(e)}")
        return []

def add_system_log(log_type, level, component, message):
    """Add a new system log entry"""
    try:
        log = SystemLog(
            log_type=log_type,
            level=level,
            component=component,
            message=message
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error adding system log: {str(e)}")

def record_uptime_status(status):
    """Record uptime status for historical tracking"""
    try:
        record = UptimeRecord(status=status)
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error recording uptime status: {str(e)}")

def create_performance_snapshot():
    """Create a performance snapshot for historical analysis"""
    try:
        stats = get_network_stats()
        devices = get_connected_devices()
        
        snapshot = PerformanceSnapshot(
            cpu_avg=stats.get('cpu_usage', 0) if stats else 0,
            memory_avg=stats.get('memory_usage', 0) if stats else 0,
            network_bytes_sent=stats.get('bytes_sent', 0) if stats else 0,
            network_bytes_recv=stats.get('bytes_recv', 0) if stats else 0,
            connected_devices_count=len(devices)
        )
        db.session.add(snapshot)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error creating performance snapshot: {str(e)}")

def get_uptime_statistics(days=30):
    """Get uptime statistics for a period"""
    try:
        since = datetime.utcnow() - timedelta(days=days)
        records = UptimeRecord.query.filter(UptimeRecord.timestamp >= since).order_by(UptimeRecord.timestamp).all()
        
        total_online = 0
        total_offline = 0
        for record in records:
            if record.status == 'online':
                total_online += record.duration_seconds or 0
            else:
                total_offline += record.duration_seconds or 0
        
        total = total_online + total_offline
        uptime_percent = (total_online / total * 100) if total > 0 else 0
        
        return {
            'uptime_percent': round(uptime_percent, 2),
            'online_seconds': total_online,
            'offline_seconds': total_offline,
            'total_seconds': total
        }
    except Exception as e:
        logger.error(f"Error getting uptime statistics: {str(e)}")
        return None

def get_performance_trends(days=7):
    """Get performance trends for analysis"""
    try:
        since = datetime.utcnow() - timedelta(days=days)
        snapshots = PerformanceSnapshot.query.filter(PerformanceSnapshot.timestamp >= since).order_by(PerformanceSnapshot.timestamp).all()
        
        if not snapshots:
            return None
        
        cpu_values = [s.cpu_avg for s in snapshots]
        memory_values = [s.memory_avg for s in snapshots]
        
        return {
            'cpu_min': min(cpu_values) if cpu_values else 0,
            'cpu_max': max(cpu_values) if cpu_values else 0,
            'cpu_avg': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
            'memory_min': min(memory_values) if memory_values else 0,
            'memory_max': max(memory_values) if memory_values else 0,
            'memory_avg': sum(memory_values) / len(memory_values) if memory_values else 0,
            'snapshots': [s.to_dict() for s in snapshots]
        }
    except Exception as e:
        logger.error(f"Error getting performance trends: {str(e)}")
        return None

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            username, password = generate_random_credentials()
            admin_user = User(username=username)
            admin_user.set_password(password)
            db.session.add(admin_user)
            db.session.commit()
            
            logger.info(f"Created admin user: {username}")
            
            # Save credentials to a file for the user
            creds_file = 'admin_credentials.txt'
            with open(creds_file, 'w') as f:
                f.write(f"Admin Username: {username}\n")
                f.write(f"Admin Password: {password}\n")
                f.write("Please save these credentials securely and then delete this file!\n")
                f.write("Do not commit this file to version control.\n")
            
            logger.warning(f"Credentials saved to {creds_file} - DELETE AFTER NOTING THEM")

# Routes
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard_new.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation
        if not username or not password:
            flash('Username and password are required', 'error')
            logger.warning("Login attempt with missing credentials")
            return render_template('login.html')
        
        # Rate limiting check
        allowed, error_msg = rate_limit_check(username)
        if not allowed:
            flash(error_msg, 'error')
            logger.warning(f"Rate limit exceeded for user: {username}")
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            session['start_time'] = datetime.utcnow().isoformat()
            session.permanent = False
            logger.info(f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(username)
            flash('Invalid username or password', 'error')
            logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    logger.info("User logged out")
    return redirect(url_for('login'))

@app.route('/api/router-status/public')
def router_status_public():
    """Public API endpoint to get router status (no login required)"""
    try:
        status_data = check_router_status()
        
        # Validate response data
        if not all(key in status_data for key in ['status', 'response_time', 'error_message']):
            logger.error("Invalid status data returned")
            return jsonify({'error': 'Invalid status data'}), 500
        
        return jsonify(status_data)
        
    except Exception as e:
        logger.error(f"Error in public router_status endpoint: {str(e)}")
        return jsonify({'error': 'Failed to check router status'}), 500

@app.route('/api/router-status')
@login_required
def router_status():
    """API endpoint to get router status"""
    try:
        status_data = check_router_status()
        
        # Validate response data
        if not all(key in status_data for key in ['status', 'response_time', 'error_message']):
            logger.error("Invalid status data returned")
            return jsonify({'error': 'Invalid status data'}), 500
        
        # Save to database
        router_status_record = RouterStatus(
            status=status_data['status'],
            response_time=status_data['response_time'],
            error_message=status_data['error_message']
        )
        db.session.add(router_status_record)
        db.session.commit()
        
        return jsonify(status_data)
        
    except Exception as e:
        logger.error(f"Error in router_status endpoint: {str(e)}")
        return jsonify({'error': 'Failed to check router status'}), 500

@app.route('/api/network-stats')
@login_required
def network_stats():
    """Get network statistics"""
    try:
        stats = get_network_stats()
        if stats:
            # Save to database
            net_stat_record = NetworkStats(
                bytes_sent=stats['bytes_sent'],
                bytes_recv=stats['bytes_recv'],
                packets_sent=stats['packets_sent'],
                packets_recv=stats['packets_recv'],
                cpu_usage=stats['cpu_usage'],
                memory_usage=stats['memory_usage']
            )
            db.session.add(net_stat_record)
            db.session.commit()
            return jsonify(stats)
        return jsonify({'error': 'Unable to get stats'}), 500
    except Exception as e:
        logger.error(f"Error in network_stats: {str(e)}")
        return jsonify({'error': 'Failed to get network stats'}), 500

@app.route('/api/connected-devices')
@login_required
def connected_devices():
    """Get connected devices"""
    try:
        devices = get_connected_devices()
        return jsonify({'devices': devices, 'count': len(devices)})
    except Exception as e:
        logger.error(f"Error in connected_devices: {str(e)}")
        return jsonify({'error': 'Failed to get connected devices'}), 500

@app.route('/api/diagnostics', methods=['POST'])
@login_required
def run_diagnostics():
    """Run network diagnostics"""
    try:
        data = request.get_json()
        diag_type = data.get('type')  # ping, traceroute, nslookup
        target = data.get('target')
        
        if not diag_type or not target:
            return jsonify({'error': 'Missing type or target'}), 400
        
        result = run_network_diagnostic(diag_type, target)
        
        # Log the diagnostic
        logger.info(f"Diagnostic {diag_type} run on {target}")
        
        return jsonify({'type': diag_type, 'target': target, 'result': result})
    except Exception as e:
        logger.error(f"Error in diagnostics: {str(e)}")
        return jsonify({'error': 'Failed to run diagnostic'}), 500

@app.route('/api/security-logs')
@login_required
def security_logs():
    """Get security logs"""
    try:
        logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(50).all()
        return jsonify({'logs': [log.to_dict() for log in logs]})
    except Exception as e:
        logger.error(f"Error in security_logs: {str(e)}")
        return jsonify({'error': 'Failed to get security logs'}), 500

@app.route('/api/stats-history')
@login_required
def stats_history():
    """Get historical network statistics"""
    try:
        hours = request.args.get('hours', 24, type=int)
        since = datetime.utcnow() - timedelta(hours=hours)
        stats = NetworkStats.query.filter(NetworkStats.timestamp >= since).order_by(NetworkStats.timestamp).all()
        return jsonify({'stats': [s.to_dict() for s in stats]})
    except Exception as e:
        logger.error(f"Error in stats_history: {str(e)}")
        return jsonify({'error': 'Failed to get stats history'}), 500

@app.route('/api/service-health')
@login_required
def service_health():
    """Get service health status"""
    try:
        services = get_service_health()
        
        # Store service status in database
        for service in services:
            status = ServiceStatus(
                service_name=service['name'],
                status=service['status'],
                memory_usage=service.get('memory_mb', 0),
                cpu_usage=service.get('cpu_percent', 0),
                uptime=None
            )
            db.session.add(status)
        db.session.commit()
        
        return jsonify({'services': services})
    except Exception as e:
        logger.error(f"Error in service_health: {str(e)}")
        return jsonify({'error': 'Failed to get service health'}), 500

@app.route('/api/system-logs')
@login_required
def system_logs():
    """Get system logs"""
    try:
        limit = request.args.get('limit', 100, type=int)
        log_type = request.args.get('type', None)
        logs = get_system_logs(limit=limit, log_type=log_type)
        return jsonify({'logs': logs})
    except Exception as e:
        logger.error(f"Error in system_logs: {str(e)}")
        return jsonify({'error': 'Failed to get system logs'}), 500

@app.route('/api/log-event', methods=['POST'])
@login_required
def log_event():
    """Add a new log event"""
    try:
        data = request.json
        add_system_log(
            log_type=data.get('log_type', 'application'),
            level=data.get('level', 'INFO'),
            component=data.get('component', 'unknown'),
            message=data.get('message', '')
        )
        return jsonify({'status': 'logged'})
    except Exception as e:
        logger.error(f"Error in log_event: {str(e)}")
        return jsonify({'error': 'Failed to log event'}), 500

@app.route('/api/uptime-stats')
@login_required
def uptime_stats():
    """Get uptime statistics"""
    try:
        days = request.args.get('days', 30, type=int)
        stats = get_uptime_statistics(days=days)
        
        if stats:
            return jsonify(stats)
        else:
            return jsonify({'error': 'No uptime data'}), 404
    except Exception as e:
        logger.error(f"Error in uptime_stats: {str(e)}")
        return jsonify({'error': 'Failed to get uptime stats'}), 500

@app.route('/api/performance-trends')
@login_required
def performance_trends():
    """Get performance trend data"""
    try:
        days = request.args.get('days', 7, type=int)
        trends = get_performance_trends(days=days)
        
        if trends:
            return jsonify(trends)
        else:
            return jsonify({'error': 'No trend data'}), 404
    except Exception as e:
        logger.error(f"Error in performance_trends: {str(e)}")
        return jsonify({'error': 'Failed to get performance trends'}), 500

@app.route('/api/performance-snapshot', methods=['POST'])
@login_required
def create_snapshot():
    """Create a new performance snapshot"""
    try:
        create_performance_snapshot()
        return jsonify({'status': 'snapshot_created'})
    except Exception as e:
        logger.error(f"Error in create_snapshot: {str(e)}")
        return jsonify({'error': 'Failed to create snapshot'}), 500

def run_network_diagnostic(diagnostic_type, target):
    """Run network diagnostics"""
    try:
        if diagnostic_type == 'ping':
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            cmd = ['ping', param, '4', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout[:500]
        
        elif diagnostic_type == 'traceroute':
            cmd = ['tracert' if platform.system().lower() == 'windows' else 'traceroute', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout[:500]
        
        elif diagnostic_type == 'nslookup':
            try:
                ip = socket.gethostbyname(target)
                return f"Host: {target}\nIP Address: {ip}"
            except:
                return f"Could not resolve {target}"
        
        return "Unknown diagnostic type"
    except subprocess.TimeoutExpired:
        return "Diagnostic timed out"
    except Exception as e:
        return f"Error: {str(e)[:200]}"

@app.errorhandler(404)
def not_found(error):
    logger.warning(f"404 Not Found: {request.path}")
    return redirect(url_for('login'))

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 Internal Server Error: {str(error)}")
    db.session.rollback()
    return "Internal server error", 500

if __name__ == '__main__':
    init_db()
    
    # Debug mode should be False in production
    debug_mode = os.environ.get('FLASK_ENV', 'production') == 'development'
    
    if debug_mode:
        logger.warning("Running in DEBUG mode - DO NOT USE IN PRODUCTION")
    
    app.run(
        debug=debug_mode,
        host=os.environ.get('FLASK_HOST', 'localhost'),
        port=int(os.environ.get('FLASK_PORT', 5000))
    )
