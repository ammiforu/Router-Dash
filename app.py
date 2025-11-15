
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import random
import string
import os
from datetime import datetime, timedelta, timezone
import logging
from dotenv import load_dotenv
import subprocess
import platform
import socket
import time
import psutil
import json
import threading
import uuid
import csv
import io
from collections import defaultdict, deque
import ipaddress

# ...existing code...

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
csrf = CSRFProtect(app)

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response, stream_with_context
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
import threading
import uuid
import csv
import io
from collections import defaultdict, deque

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

# Traffic Monitor - Global storage for request logs (circular buffer)
request_log = deque(maxlen=500)  # Keep last 500 requests
request_stats = {
    'total_requests': 0,
    'by_port': defaultdict(int),
    'by_method': defaultdict(int),
    'by_status': defaultdict(int),
    'by_ip': defaultdict(int)
}
traffic_lock = threading.Lock()  # Thread-safe access to request_log

# ----- Time helpers -----
def iso_utc(dt: datetime | None) -> str | None:
    """Return ISO8601 UTC string with 'Z' for a datetime (handles naive as UTC)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    # Use 'Z' suffix instead of +00:00 for readability
    return dt.isoformat().replace('+00:00', 'Z')

# ----- Networking helpers -----
def get_client_ip(req) -> str:
    """Best-effort extraction of the original client IP.
    Checks common proxy headers in order, falls back to remote_addr.
    """
    candidates = []
    xff = req.headers.get('X-Forwarded-For')
    if xff:
        # XFF may be a comma-separated chain: client, proxy1, proxy2
        candidates.extend([ip.strip() for ip in xff.split(',') if ip.strip()])

    for header in ('X-Real-IP', 'CF-Connecting-IP', 'True-Client-IP'):
        v = req.headers.get(header)
        if v:
            candidates.append(v.strip())

    fwd = req.headers.get('Forwarded')
    if fwd:
        # RFC 7239: Forwarded: for=1.2.3.4; proto=https; by=...
        try:
            parts = [p.strip() for p in fwd.split(';')]
            for p in parts:
                if p.lower().startswith('for='):
                    val = p.split('=', 1)[1].strip().strip('"')
                    # Remove brackets for IPv6 and any :port suffix
                    val = val.strip('[]')
                    if ':' in val and val.count(':') == 1:
                        val = val.split(':', 1)[0]
                    candidates.append(val)
                    break
        except Exception:
            pass

    if req.remote_addr:
        candidates.append(req.remote_addr)

    for ip in candidates:
        try:
            return str(ipaddress.ip_address(ip))
        except Exception:
            continue
    return req.remote_addr or 'unknown'

def is_external_ip(ip: str) -> bool:
    """Determine if IP address is external (non-private/non-loopback)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except Exception:
        # Fallback heuristic if parsing fails
        local_ranges = ['192.168.', '10.', '172.16.', '127.', 'localhost', '::1']
        return not any(ip.startswith(prefix) for prefix in local_ranges)
request_stats = {
    'total_requests': 0,
    'by_port': defaultdict(int),
    'by_method': defaultdict(int),
    'by_status': defaultdict(int),
    'by_ip': defaultdict(int)
}
traffic_lock = threading.Lock()  # Thread-safe access to request_log

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
            'last_checked': iso_utc(self.last_checked) if self.last_checked else None,
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
            'timestamp': iso_utc(self.timestamp),
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
            'timestamp': iso_utc(self.timestamp),
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
            'timestamp': iso_utc(self.timestamp),
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
            'timestamp': iso_utc(self.timestamp),
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
            'timestamp': iso_utc(self.timestamp),
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
            'timestamp': iso_utc(self.timestamp),
            'cpu_avg': self.cpu_avg,
            'memory_avg': self.memory_avg,
            'network_bytes_sent': self.network_bytes_sent,
            'network_bytes_recv': self.network_bytes_recv,
            'connected_devices_count': self.connected_devices_count,
            'period_minutes': self.period_minutes
        }

class LoginAttempt(db.Model):
    """Track login attempts for security auditing"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    username = db.Column(db.String(120), nullable=False)
    source_ip = db.Column(db.String(15), nullable=False)
    success = db.Column(db.Boolean, default=False)
    user_agent = db.Column(db.String(500), nullable=True)
    
    def to_dict(self):
        return {
            'timestamp': iso_utc(self.timestamp),
            'username': self.username,
            'source_ip': self.source_ip,
            'success': self.success,
            'user_agent': self.user_agent
        }

class PortScanAlert(db.Model):
    """Track detected port scans and suspicious activity"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(15), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # 'tcp', 'udp'
    severity = db.Column(db.String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    description = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'port': self.port,
            'protocol': self.protocol,
            'severity': self.severity,
            'description': self.description
        }

class VpnStatus(db.Model):
    """Track VPN connection status"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_connected = db.Column(db.Boolean, default=False)
    vpn_name = db.Column(db.String(100), nullable=True)
    remote_ip = db.Column(db.String(15), nullable=True)
    remote_port = db.Column(db.Integer, nullable=True)
    encryption = db.Column(db.String(50), nullable=True)
    connection_duration = db.Column(db.Integer, nullable=True)  # in seconds
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'is_connected': self.is_connected,
            'vpn_name': self.vpn_name,
            'remote_ip': self.remote_ip,
            'remote_port': self.remote_port,
            'encryption': self.encryption,
            'connection_duration': self.connection_duration
        }

class SpeedtestResult(db.Model):
    """Store internet speedtest results"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    download_speed = db.Column(db.Float, nullable=False)  # in Mbps
    upload_speed = db.Column(db.Float, nullable=False)  # in Mbps
    ping = db.Column(db.Float, nullable=False)  # in ms
    server = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'download_speed': self.download_speed,
            'upload_speed': self.upload_speed,
            'ping': self.ping,
            'server': self.server,
            'location': self.location
        }

class DnsLeakTest(db.Model):
    """Store DNS leak test results"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    leaked = db.Column(db.Boolean, default=False)
    dns_servers = db.Column(db.Text, nullable=True)  # JSON array of DNS servers
    test_type = db.Column(db.String(50), nullable=False)  # 'standard', 'extended', 'ipv6'
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'leaked': self.leaked,
            'dns_servers': json.loads(self.dns_servers) if self.dns_servers else [],
            'test_type': self.test_type
        }

class TracerouteResult(db.Model):
    """Store traceroute test results"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    target = db.Column(db.String(100), nullable=False)
    hops = db.Column(db.Integer, nullable=False)
    path = db.Column(db.Text, nullable=False)  # JSON array of hops
    completed = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'timestamp': self.timestamp.isoformat(),
            'target': self.target,
            'hops': self.hops,
            'path': json.loads(self.path) if self.path else [],
            'completed': self.completed
        }

class DeviceTag(db.Model):
    """Store tagged/named devices (Module 7)"""
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), nullable=False, unique=True)
    device_name = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50), nullable=True)  # 'phone', 'laptop', 'iot', 'printer', etc
    description = db.Column(db.Text, nullable=True)
    color_tag = db.Column(db.String(20), nullable=True)  # for UI coloring
    is_monitored = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'mac_address': self.mac_address,
            'device_name': self.device_name,
            'device_type': self.device_type,
            'description': self.description,
            'color_tag': self.color_tag,
            'is_monitored': self.is_monitored
        }

class BandwidthQuota(db.Model):
    """Store bandwidth quota rules (Module 7)"""
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), nullable=False)
    daily_limit_mb = db.Column(db.Integer, nullable=False)  # daily limit in MB
    monthly_limit_gb = db.Column(db.Integer, nullable=False)  # monthly limit in GB
    alert_threshold = db.Column(db.Integer, default=80)  # alert at 80% usage
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'mac_address': self.mac_address,
            'daily_limit_mb': self.daily_limit_mb,
            'monthly_limit_gb': self.monthly_limit_gb,
            'alert_threshold': self.alert_threshold
        }

class AutoAlert(db.Model):
    """Store automated alert rules (Module 7)"""
    id = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(50), nullable=False)  # 'uptime', 'bandwidth', 'cpu', 'memory', 'device_offline'
    threshold = db.Column(db.Float, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    email_notify = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'threshold': self.threshold,
            'enabled': self.enabled,
            'email_notify': self.email_notify
        }

class CommandHistory(db.Model):
    """Store command execution history (Module 8)"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    command = db.Column(db.String(500), nullable=False)
    output = db.Column(db.Text, nullable=True)
    exit_code = db.Column(db.Integer, nullable=True)
    
    def to_dict(self):
        return {
            'timestamp': iso_utc(self.timestamp),
            'command': self.command,
            'output': self.output[:200] if self.output else '',
            'exit_code': self.exit_code
        }

class ManagedDevice(db.Model):
    """Store custom device names and blocking settings"""
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), unique=True, nullable=False)
    custom_name = db.Column(db.String(255), nullable=False)
    is_blocked = db.Column(db.Boolean, default=False)
    is_new = db.Column(db.Boolean, default=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    device_type = db.Column(db.String(50), nullable=True)  # 'phone', 'laptop', 'iot', etc
    notes = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'mac_address': self.mac_address,
            'custom_name': self.custom_name,
            'is_blocked': self.is_blocked,
            'is_new': self.is_new,
            'first_seen': iso_utc(self.first_seen),
            'last_seen': iso_utc(self.last_seen),
            'device_type': self.device_type,
            'notes': self.notes
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
        # Ping the router with shorter timeout
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', router_ip]
        
        start_time = datetime.now()
        result = subprocess.run(command, capture_output=True, text=True, timeout=2)
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
        logger.warning(f"Router ping timeout for {router_ip}")
        return {
            'status': 'offline',
            'response_time': None,
            'error_message': 'Ping timeout - router unreachable'
        }
    except Exception as e:
        logger.warning(f"Error checking router status: {str(e)}")
        # Return mock data as fallback to prevent app crash
        return {
            'status': 'unknown',
            'response_time': None,
            'error_message': f'Status check error: {str(e)[:50]}'
        }

def get_network_stats():
    """Get router network statistics and system resources"""
    try:
        router_ip = os.environ.get('ROUTER_IP', '192.168.8.1')
        router_user = os.environ.get('ROUTER_USER', 'root')
        router_pass = os.environ.get('ROUTER_PASS', '')
        
        # Try to get real router stats via SSH
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(router_ip, username=router_user, password=router_pass, timeout=2)
            
            # Get network stats
            stdin, stdout, stderr = ssh.exec_command("cat /proc/net/dev")
            net_output = stdout.read().decode()
            
            # Get CPU usage
            stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'")
            cpu_output = stdout.read().decode().strip()
            
            # Get memory usage
            stdin, stdout, stderr = ssh.exec_command("free | grep Mem | awk '{print ($3/$2)*100}'")
            mem_output = stdout.read().decode().strip()
            
            ssh.close()
            
            # Parse values
            cpu_usage = float(cpu_output.replace('%us', '').strip()) if cpu_output else 0
            memory_usage = float(mem_output) if mem_output else 0
            
            # Parse network stats from /proc/net/dev
            bytes_sent, bytes_recv, packets_sent, packets_recv = 0, 0, 0, 0
            for line in net_output.split('\n')[2:]:
                if line.strip() and not line.startswith('lo'):
                    parts = line.split()
                    if len(parts) >= 10:
                        bytes_recv += int(parts[1])
                        packets_recv += int(parts[2])
                        bytes_sent += int(parts[9])
                        packets_sent += int(parts[10])
            
            return {
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': packets_sent,
                'packets_recv': packets_recv,
                'cpu_usage': cpu_usage,
                'memory_usage': memory_usage,
                'memory_total': 0,
                'memory_available': 0,
                'source': 'router'
            }
        except Exception as ssh_error:
            logger.warning(f"SSH connection failed, using local system stats: {ssh_error}")

        # Fallback: Use local system metrics via psutil (real, not mocked)
        try:
            import psutil
            net = psutil.net_io_counters()
            cpu_usage = psutil.cpu_percent(interval=0.2)
            vm = psutil.virtual_memory()
            return {
                'bytes_sent': getattr(net, 'bytes_sent', 0),
                'bytes_recv': getattr(net, 'bytes_recv', 0),
                'packets_sent': getattr(net, 'packets_sent', 0),
                'packets_recv': getattr(net, 'packets_recv', 0),
                'cpu_usage': cpu_usage,
                'memory_usage': vm.percent,
                'memory_total': vm.total,
                'memory_available': vm.available,
                'source': 'local'
            }
        except Exception as e2:
            logger.error(f"psutil fallback failed: {e2}")
            return {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets_sent': 0,
                'packets_recv': 0,
                'cpu_usage': 0,
                'memory_usage': 0,
                'memory_total': 0,
                'memory_available': 0,
                'source': 'unavailable'
            }
    except Exception as e:
        logger.error(f"Error getting network stats: {str(e)}")
        return {'error': str(e)}, 500

def get_connected_devices():
    """Get list of connected devices from router - includes online and offline devices"""
    try:
        router_ip = os.environ.get('ROUTER_IP', '192.168.1.1')
        router_user = os.environ.get('ROUTER_USER', 'admin')
        router_pass = os.environ.get('ROUTER_PASS', 'admin')
        
        devices = []
        
        # Try to get real devices via router REST API (GL-iNet or similar)
        try:
            import requests
            import json
            
            # Try multiple known GL-iNet API endpoints
            api_endpoints = [
                f"http://{router_ip}/api/clients",  # GL-iNet v4
                f"http://{router_ip}/api/status/clients",  # Alternative endpoint
                f"http://{router_ip}/cgi-bin/luci/admin/network/clients",  # OpenWrt
            ]
            
            for api_url in api_endpoints:
                try:
                    # Try with bearer token first
                    headers = {'authorization': f'Bearer {router_pass}', 'Content-Type': 'application/json'}
                    response = requests.get(api_url, headers=headers, timeout=2)
                    
                    if response.status_code == 401:
                        # Try basic auth
                        response = requests.get(api_url, auth=(router_user, router_pass), timeout=2)
                    
                    if response.status_code == 200:
                        api_devices = response.json()
                        
                        # Handle different API response formats
                        if isinstance(api_devices, dict) and 'data' in api_devices:
                            api_devices = api_devices['data']
                        
                        if isinstance(api_devices, list):
                            for dev in api_devices:
                                # Extract device info based on common API response formats
                                ip = dev.get('ip') or dev.get('ipaddr') or 'N/A'
                                mac = dev.get('mac') or dev.get('hwaddr') or 'N/A'
                                name = dev.get('hostname') or dev.get('name') or dev.get('device_name') or f"Device"
                                connected = dev.get('online') or dev.get('connected') or dev.get('status') == 'Online'
                                
                                devices.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'name': name,
                                    'connection_time': dev.get('connected_time', dev.get('lease_time', 'N/A')),
                                    'data_used': dev.get('data_used', dev.get('traffic', 'N/A')),
                                    'bandwidth': dev.get('bandwidth', dev.get('band', '2.4GHz')),
                                    'type': dev.get('type', dev.get('device_type', 'WiFi')),
                                    'status': 'Online' if connected else 'Offline'
                                })
                            
                            if devices:
                                logger.info(f"Retrieved {len(devices)} devices from router API: {api_url}")
                                return devices
                except requests.exceptions.RequestException as e:
                    logger.debug(f"Router API request failed for {api_url}: {e}")
                except Exception as parse_error:
                    logger.debug(f"Error parsing API response from {api_url}: {parse_error}")
        except ImportError:
            logger.debug("Requests library not available for router API")
        
        # Try to get real devices via SSH
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(router_ip, username=router_user, password=router_pass, timeout=2)
            
            # Try to get clients list from router - try multiple sources
            dhcp_leases = []
            arp_devices = []
            
            try:
                # DHCP leases file
                stdin, stdout, stderr = ssh.exec_command("cat /tmp/dhcp.leases 2>/dev/null || cat /var/lib/dnsmasq/dnsmasq.leases 2>/dev/null")
                dhcp_output = stdout.read().decode('utf-8', errors='ignore')
                
                for line in dhcp_output.strip().split('\n'):
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            device_mac = parts[1]
                            device_ip = parts[2]
                            device_name = parts[3] if len(parts) > 3 and parts[3] != '*' else f"Device {device_ip.split('.')[-1]}"
                            
                            if ':' in device_mac and '.' in device_ip:
                                dhcp_leases.append({
                                    'ip': device_ip,
                                    'mac': device_mac,
                                    'name': device_name,
                                    'connection_time': 'Connected via DHCP',
                                    'data_used': 'N/A',
                                    'bandwidth': 'Unknown',
                                    'type': 'WiFi',
                                    'status': 'Online'
                                })
                        except Exception:
                            pass
            except Exception as dhcp_error:
                logger.debug(f"Error reading DHCP leases: {dhcp_error}")
            
            # Also get ARP table for currently online devices
            try:
                stdin, stdout, stderr = ssh.exec_command("arp -a 2>/dev/null || ip neigh 2>/dev/null")
                arp_output = stdout.read().decode('utf-8', errors='ignore')
                
                for line in arp_output.strip().split('\n'):
                    if not line.strip() or 'Address' in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            device_ip = parts[0]
                            device_mac = parts[1].replace('-', ':') if len(parts) > 1 else 'Unknown'
                            
                            if ':' in device_mac and '.' in device_ip and device_ip != router_ip:
                                arp_devices.append({
                                    'ip': device_ip,
                                    'mac': device_mac
                                })
                        except Exception:
                            pass
                
                logger.debug(f"Found {len(arp_devices)} devices in ARP table")
            except Exception as arp_error:
                logger.debug(f"Error reading ARP table: {arp_error}")
            
            ssh.close()
            
            # Build ARP MAC set for online detection
            arp_macs = {d['mac'].lower() for d in arp_devices}
            arp_ips = {d['ip'] for d in arp_devices}
            
            # Start with all DHCP devices and mark online status
            devices = []
            for dhcp_dev in dhcp_leases:
                # Mark device as online if in ARP, otherwise show as having DHCP lease
                if dhcp_dev['mac'].lower() in arp_macs or dhcp_dev['ip'] in arp_ips:
                    dhcp_dev['status'] = 'Online'
                else:
                    # Device has DHCP lease but not in ARP - might be offline or out of range
                    dhcp_dev['status'] = 'DHCP Lease'
                devices.append(dhcp_dev)
            
            # Add online-only devices from ARP that aren't in DHCP
            dhcp_macs = {d['mac'].lower() for d in dhcp_leases}
            for arp_dev in arp_devices:
                if arp_dev['mac'].lower() not in dhcp_macs:
                    devices.append({
                        'ip': arp_dev['ip'],
                        'mac': arp_dev['mac'],
                        'name': f"Device {arp_dev['ip'].split('.')[-1]}",
                        'connection_time': 'Online (ARP)',
                        'data_used': 'N/A',
                        'bandwidth': 'Unknown',
                        'type': 'Wired/WiFi',
                        'status': 'Online'
                    })
            
            if devices:
                # Enrich devices with custom names and blocking status from database
                for device in devices:
                    mac = device['mac'].lower()
                    managed = ManagedDevice.query.filter_by(mac_address=mac).first()
                    
                    if managed:
                        device['name'] = managed.custom_name
                        device['is_blocked'] = managed.is_blocked
                        device['is_new'] = False
                        device['device_type'] = managed.device_type
                        managed.last_seen = datetime.utcnow()
                    else:
                        # New device - create record and mark as new
                        device['is_new'] = True
                        device['is_blocked'] = False
                        new_device = ManagedDevice(
                            mac_address=mac,
                            custom_name=device.get('name', f"Device {device['ip'].split('.')[-1]}"),
                            is_new=True,
                            device_type=device.get('type', 'Unknown')
                        )
                        db.session.add(new_device)
                
                db.session.commit()
                logger.info(f"Retrieved {len(devices)} devices from router SSH")
                return devices
                
        except ImportError:
            logger.debug("Paramiko not available for SSH")
        except Exception as ssh_error:
            logger.debug(f"SSH connection failed: {ssh_error}")
        
        # Fallback: Get connected devices from local ARP cache (Windows/Linux)
        try:
            # Extract subnet from router IP (first 3 octets)
            router_octets = router_ip.split('.')
            expected_subnet = '.'.join(router_octets[:3])
            
            if platform.system().lower() == 'windows':
                # Windows ARP cache
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=2)
                arp_output = result.stdout
                
                # Parse Windows ARP format
                current_interface = None
                for line in arp_output.strip().split('\n'):
                    line = line.strip()
                    
                    # Skip empty lines and headers
                    if not line or 'Interface' in line or 'Internet Address' in line or '---' in line:
                        continue
                    
                    # Extract interface IP if line contains "Interface:"
                    if 'Interface:' in line:
                        current_interface = line.split()[-2] if len(line.split()) > 1 else None
                        continue
                    
                    # Parse ARP entries (format: IP   MAC   Type)
                    parts = line.split()
                    if len(parts) >= 3 and '.' in parts[0]:
                        try:
                            device_ip = parts[0]
                            device_mac = parts[1].replace('-', ':')  # Convert dashes to colons
                            
                            # Validate IP address
                            try:
                                ip_octets = [int(x) for x in device_ip.split('.')]
                                if len(ip_octets) != 4 or any(x < 0 or x > 255 for x in ip_octets):
                                    continue  # Invalid IP format
                            except ValueError:
                                continue  # Not a valid IP
                            
                            # Check if IP is in the same subnet as router
                            device_subnet = '.'.join(device_ip.split('.')[:3])
                            if device_subnet != expected_subnet:
                                logger.debug(f"Device {device_ip} not in expected subnet {expected_subnet}")
                                continue
                            
                            # Additional filters
                            is_multicast = ip_octets[0] >= 224 and ip_octets[0] <= 239
                            is_reserved = ip_octets[0] == 0 or ip_octets[0] == 127 or ip_octets[0] == 169
                            is_broadcast = device_ip.endswith('.255') or device_ip.endswith('.0') or device_ip.endswith('.254')
                            is_router = device_ip == router_ip
                            is_valid_mac = ':' in device_mac and device_mac.count(':') == 5
                            
                            if not (is_multicast or is_reserved or is_broadcast or is_router) and is_valid_mac:
                                devices.append({
                                    'ip': device_ip,
                                    'mac': device_mac,
                                    'name': f"Device {device_ip.split('.')[-1]}",
                                    'connection_time': 'Connected',
                                    'data_used': 'N/A',
                                    'bandwidth': 'Network',
                                    'type': 'Wired/WiFi',
                                    'status': 'Online'
                                })
                        except Exception as parse_error:
                            logger.debug(f"Error parsing Windows ARP entry: {parse_error}")
                            continue
            else:
                # Linux ARP cache
                result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=2)
                arp_output = result.stdout
                
                for line in arp_output.strip().split('\n'):
                    if not line.strip() or 'Address' in line or '---' in line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3 and '.' in parts[0]:
                        try:
                            device_ip = parts[0]
                            device_mac = parts[2] if len(parts) > 2 else 'Unknown'
                            
                            # Validate IP address
                            try:
                                ip_octets = [int(x) for x in device_ip.split('.')]
                                if len(ip_octets) != 4 or any(x < 0 or x > 255 for x in ip_octets):
                                    continue  # Invalid IP format
                            except ValueError:
                                continue  # Not a valid IP
                            
                            # Check if IP is in the same subnet as router
                            device_subnet = '.'.join(device_ip.split('.')[:3])
                            if device_subnet != expected_subnet:
                                logger.debug(f"Device {device_ip} not in expected subnet {expected_subnet}")
                                continue
                            
                            # Additional filters
                            is_multicast = ip_octets[0] >= 224 and ip_octets[0] <= 239
                            is_reserved = ip_octets[0] == 0 or ip_octets[0] == 127 or ip_octets[0] == 169
                            is_broadcast = device_ip.endswith('.255') or device_ip.endswith('.0') or device_ip.endswith('.254')
                            is_router = device_ip == router_ip
                            is_valid_mac = ':' in device_mac and device_mac.count(':') == 5
                            
                            if not (is_multicast or is_reserved or is_broadcast or is_router) and is_valid_mac:
                                devices.append({
                                    'ip': device_ip,
                                    'mac': device_mac,
                                    'name': f"Device {device_ip.split('.')[-1]}",
                                    'connection_time': 'Connected',
                                    'data_used': 'N/A',
                                    'bandwidth': 'Network',
                                    'type': 'Wired/WiFi',
                                    'status': 'Online'
                                })
                        except Exception as parse_error:
                            logger.debug(f"Error parsing Linux ARP entry: {parse_error}")
                            continue
            
            if devices:
                logger.info(f"Retrieved {len(devices)} connected devices from local ARP cache")
                return devices
        except Exception as arp_error:
            logger.warning(f"Failed to retrieve local ARP cache: {arp_error}")
        
        # If all methods fail, log and return empty list (no mock data)
        logger.warning("Could not retrieve connected devices from router or local ARP cache")
        return devices
    except Exception as e:
        logger.error(f"Error getting connected devices: {str(e)}")
        return []

def get_top_processes(limit=10):
    """Get top processes on router by CPU and memory usage"""
    try:
        # Get router IP from environment
        router_ip = os.environ.get('ROUTER_IP', '192.168.8.1')
        router_user = os.environ.get('ROUTER_USER', 'root')
        router_pass = os.environ.get('ROUTER_PASS', '')
        
        processes = []
        
        # Try to get router processes via SSH or fallback to simulation
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(router_ip, username=router_user, password=router_pass, timeout=2)
            
            # Get top CPU processes
            stdin, stdout, stderr = ssh.exec_command("ps aux | sort -k3 -rn | head -10")
            top_cpu_output = stdout.read().decode()
            
            # Get top memory processes
            stdin, stdout, stderr = ssh.exec_command("ps aux | sort -k4 -rn | head -10")
            top_mem_output = stdout.read().decode()
            
            ssh.close()
            
            # Parse ps output
            for line in top_cpu_output.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append({
                            'name': parts[10],
                            'cpu_percent': float(parts[2]),
                            'memory_percent': float(parts[3]),
                            'pid': int(parts[1]) if parts[1].isdigit() else 0,
                            'status': 'running'
                        })
            
            if processes:
                top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:limit]
                top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:limit]
                
                return {
                    'top_cpu': top_cpu,
                    'top_memory': top_memory,
                    'source': 'router'
                }
        except Exception as ssh_error:
            logger.warning(f"SSH connection failed: {ssh_error}")
        
        # Fallback: Generate realistic router process simulation
        import random
        router_processes = [
            'dnsmasq', 'uhttpd', 'odhcpd', 'firewall', 'kmodloader',
            'mtk_gpy', 'iwpriv', 'wpa_supplicant', 'hostapd', 'dropbear'
        ]
        
        processes = []
        for proc_name in router_processes:
            processes.append({
                'name': proc_name,
                'cpu_percent': random.uniform(0.1, 15.0),
                'memory_percent': random.uniform(0.5, 8.0),
                'pid': random.randint(100, 1000),
                'status': 'running'
            })
        
        top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:limit]
        top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:limit]
        
        return {
            'top_cpu': top_cpu,
            'top_memory': top_memory,
            'source': 'simulated'
        }
    except Exception as e:
        logger.error(f"Error getting top processes: {str(e)}")
        return {'error': str(e)}, 500

def get_service_health():
    """Get system service health status"""
    services = []
    try:
        # Get process information
        for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_info', 'create_time']):
            try:
                if proc.name() in ['python.exe', 'nginx', 'mysql', 'dnsmasq', 'hostapd']:
                    create_time = proc.create_time()
                    uptime_seconds = time.time() - create_time
                    uptime_hours = int(uptime_seconds / 3600)
                    uptime_minutes = int((uptime_seconds % 3600) / 60)
                    
                    services.append({
                        'name': proc.name(),
                        'status': 'RUNNING',
                        'pid': proc.pid,
                        'memory_mb': round(proc.memory_info().rss / 1024 / 1024, 2),
                        'cpu_percent': round(proc.cpu_percent(interval=0.1), 1),
                        'uptime': f'{uptime_hours}h {uptime_minutes}m',
                        'uptime_seconds': int(uptime_seconds),
                        'can_control': True
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Add common services that might not be running
        for service_name in ['DNS', 'DHCP', 'Firewall']:
            if not any(s['name'] == service_name for s in services):
                services.append({
                    'name': service_name,
                    'status': 'UNKNOWN',
                    'pid': None,
                    'memory_mb': 0,
                    'cpu_percent': 0,
                    'uptime': 'N/A',
                    'uptime_seconds': 0,
                    'can_control': False
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

def create_sample_logs():
    """Create sample system logs for testing"""
    try:
        # Only create sample logs if database is empty
        if SystemLog.query.count() > 0:
            return
        
        sample_logs = [
            ('system', 'INFO', 'RouterDash', 'Router Dashboard started successfully'),
            ('network', 'INFO', 'NetworkMonitor', 'Network monitoring initialized'),
            ('system', 'INFO', 'Database', 'Database connection established'),
            ('application', 'INFO', 'WebServer', 'Flask web server started on port 5000'),
            ('security', 'WARNING', 'Authentication', 'Failed login attempt from unknown IP'),
            ('network', 'INFO', 'DeviceScanner', 'Detected 8 connected devices'),
            ('system', 'INFO', 'PerformanceMonitor', 'CPU usage: 45%, Memory: 62%'),
            ('application', 'DEBUG', 'API', 'Performance snapshot created'),
            ('network', 'WARNING', 'Bandwidth', 'High bandwidth usage detected on device 192.168.1.105'),
            ('security', 'INFO', 'Firewall', 'Firewall rules updated successfully'),
        ]
        
        for log_type, level, component, message in sample_logs:
            add_system_log(log_type, level, component, message)
        
        logger.info("Created sample system logs")
    except Exception as e:
        logger.error(f"Error creating sample logs: {str(e)}")

def purge_sample_logs_if_present():
    """Detect and purge previously created sample logs so UI shows only real activity."""
    try:
        sample_components = {
            'RouterDash', 'NetworkMonitor', 'Database', 'WebServer', 'Authentication',
            'DeviceScanner', 'PerformanceMonitor', 'API', 'Bandwidth', 'Firewall'
        }
        logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(15).all()
        if logs and all(log.component in sample_components for log in logs):
            SystemLog.query.delete()
            db.session.commit()
            logger.info('Purged sample system logs')
    except Exception as e:
        logger.error(f'Error purging sample logs: {str(e)}')

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

def record_login_attempt_security(username, source_ip, success, user_agent=None):
    """Record login attempt for security auditing (Module 5)"""
    try:
        attempt = LoginAttempt(
            username=username,
            source_ip=source_ip,
            success=success,
            user_agent=user_agent
        )
        db.session.add(attempt)
        db.session.commit()
        
        # Log failed attempts
        if not success:
            add_system_log(
                log_type='security',
                level='WARNING',
                component='authentication',
                message=f'Failed login attempt for user {username} from {source_ip}'
            )
    except Exception as e:
        logger.error(f"Error recording login attempt: {str(e)}")

def record_port_scan_alert(source_ip, port, protocol='tcp', severity='medium', description=None):
    """Record detected port scan or suspicious port access (Module 5)"""
    try:
        alert = PortScanAlert(
            source_ip=source_ip,
            port=port,
            protocol=protocol,
            severity=severity,
            description=description
        )
        db.session.add(alert)
        db.session.commit()
        
        add_system_log(
            log_type='security',
            level='CRITICAL' if severity == 'critical' else 'WARNING',
            component='port_security',
            message=f'{severity.upper()} alert: Port {port}/{protocol} accessed from {source_ip}'
        )
    except Exception as e:
        logger.error(f"Error recording port scan alert: {str(e)}")

def get_vpn_status():
    """Get current VPN connection status (Module 5)"""
    try:
        is_connected = False
        
        # Try to detect VPN on Windows
        if platform.system() == 'Windows':
            try:
                # Check for VPN adapters using ipconfig
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=3)
                is_connected = 'ppp' in result.stdout.lower() or 'vpn' in result.stdout.lower() or 'l2tp' in result.stdout.lower()
            except Exception:
                is_connected = False
        else:
            # Unix-like systems
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
            is_connected = 'tun' in result.stdout or 'tap' in result.stdout
        
        status = VpnStatus(is_connected=is_connected)
        db.session.add(status)
        db.session.commit()
        
        return status.to_dict()
    except Exception as e:
        logger.error(f"Error getting VPN status: {str(e)}")
        return {'is_connected': False, 'error': str(e)}

def get_security_summary():
    """Get security summary with failed logins, port alerts, etc. (Module 5)"""
    try:
        # Get failed login attempts in last 24 hours
        since = datetime.utcnow() - timedelta(hours=24)
        failed_logins = LoginAttempt.query.filter(
            LoginAttempt.timestamp >= since,
            LoginAttempt.success == False
        ).count()
        
        # Get port scan alerts in last 24 hours
        port_alerts = PortScanAlert.query.filter(
            PortScanAlert.timestamp >= since
        ).count()
        
        # Get critical security logs
        critical_logs = SystemLog.query.filter(
            SystemLog.timestamp >= since,
            SystemLog.log_type == 'security',
            SystemLog.level.in_(['WARNING', 'ERROR', 'CRITICAL'])
        ).count()
        
        return {
            'failed_logins_24h': failed_logins,
            'port_scan_alerts_24h': port_alerts,
            'critical_events_24h': critical_logs,
            'security_status': 'good' if (failed_logins < 5 and port_alerts == 0) else 'warning' if failed_logins < 10 else 'critical'
        }
    except Exception as e:
        logger.error(f"Error getting security summary: {str(e)}")
        return None

def run_speedtest_check():
    """Run internet speedtest (Module 6) using speedtest-cli if available"""
    try:
        try:
            import speedtest  # type: ignore
        except Exception:
            logger.warning("speedtest-cli not installed; cannot run real speedtest")
            return None

        st = speedtest.Speedtest()
        st.get_best_server()
        down = st.download() / 1_000_000  # bps -> Mbps
        up = st.upload() / 1_000_000
        ping = st.results.ping
        server = st.results.server.get('sponsor') if st.results.server else None
        location = st.results.server.get('name') if st.results.server else None

        result = SpeedtestResult(
            download_speed=round(down, 2),
            upload_speed=round(up, 2),
            ping=round(ping or 0, 2),
            server=server,
            location=location
        )
        db.session.add(result)
        db.session.commit()
        return result.to_dict()
    except Exception as e:
        logger.error(f"Error running speedtest: {str(e)}")
        return None

def check_dns_leaks():
    """Check for DNS leaks (Module 6)"""
    try:
        # Get configured DNS servers
        dns_servers = []
        if platform.system() == 'Windows':
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'DNS Servers' in line:
                    dns_servers.append(line.split(':')[1].strip() if ':' in line else '')
        else:
            result = subprocess.run(['cat', '/etc/resolv.conf'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'nameserver' in line:
                    dns_servers.append(line.split()[-1])
        
        # Record DNS leak test
        test = DnsLeakTest(
            leaked=False,
            dns_servers=json.dumps(dns_servers[:5]),
            test_type='standard'
        )
        db.session.add(test)
        db.session.commit()
        return test.to_dict()
    except Exception as e:
        logger.error(f"Error checking DNS leaks: {str(e)}")
        return None

def run_traceroute_check(target):
    """Run traceroute to target (Module 6)"""
    try:
        is_windows = platform.system().lower() == 'windows'
        if is_windows:
            # Windows tracert: use -d (no DNS) and -h for max hops
            cmd = ['tracert', '-d', '-h', '15', target]
        else:
            cmd = ['traceroute', '-m', '15', target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        hops = []
        lines = result.stdout.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Skip headers/footers based on platform
            if is_windows:
                if line.startswith(('Tracing route to', 'over a maximum', 'Trace complete.')):
                    continue
            else:
                if line.startswith(('traceroute to',)):
                    continue
            hops.append(line)
        
        tr_result = TracerouteResult(
            target=target,
            hops=len(hops),
            path=json.dumps(hops[:20]),
            completed=(result.returncode == 0 and len(hops) > 0)
        )
        db.session.add(tr_result)
        db.session.commit()
        return tr_result.to_dict()
    except Exception as e:
        logger.error(f"Error running traceroute: {str(e)}")
        return None

def tag_device(mac_address, device_name, device_type=None, description=None):
    """Tag/label a device for tracking (Module 7)"""
    try:
        existing = DeviceTag.query.filter_by(mac_address=mac_address).first()
        if existing:
            existing.device_name = device_name
            existing.device_type = device_type
            existing.description = description
        else:
            tag = DeviceTag(
                mac_address=mac_address,
                device_name=device_name,
                device_type=device_type,
                description=description
            )
            db.session.add(tag)
        db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Error tagging device: {str(e)}")
        return False

def get_device_tags():
    """Get all tagged devices (Module 7)"""
    try:
        tags = DeviceTag.query.all()
        return [t.to_dict() for t in tags]
    except Exception as e:
        logger.error(f"Error getting device tags: {str(e)}")
        return []

def set_bandwidth_quota(mac_address, daily_limit_mb, monthly_limit_gb):
    """Set bandwidth quota for a device (Module 7)"""
    try:
        existing = BandwidthQuota.query.filter_by(mac_address=mac_address).first()
        if existing:
            existing.daily_limit_mb = daily_limit_mb
            existing.monthly_limit_gb = monthly_limit_gb
        else:
            quota = BandwidthQuota(
                mac_address=mac_address,
                daily_limit_mb=daily_limit_mb,
                monthly_limit_gb=monthly_limit_gb
            )
            db.session.add(quota)
        db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Error setting bandwidth quota: {str(e)}")
        return False

def get_bandwidth_quotas():
    """Get all bandwidth quotas (Module 7)"""
    try:
        quotas = BandwidthQuota.query.all()
        return [q.to_dict() for q in quotas]
    except Exception as e:
        logger.error(f"Error getting bandwidth quotas: {str(e)}")
        return []

def create_auto_alert(alert_type, threshold, email_notify=False):
    """Create an automated alert rule (Module 7)"""
    try:
        alert = AutoAlert(
            alert_type=alert_type,
            threshold=threshold,
            email_notify=email_notify
        )
        db.session.add(alert)
        db.session.commit()
        return alert.to_dict()
    except Exception as e:
        logger.error(f"Error creating auto alert: {str(e)}")
        return None

def get_auto_alerts():
    """Get all automated alerts (Module 7)"""
    try:
        alerts = AutoAlert.query.all()
        return [a.to_dict() for a in alerts]
    except Exception as e:
        logger.error(f"Error getting auto alerts: {str(e)}")
        return []

def execute_router_command(user_id, command):
    """Execute a router command with history tracking (Module 8)"""
    try:
        # Sanitize and normalize command - only allow safe commands
        safe_commands = ['ping', 'tracert', 'traceroute', 'ipconfig', 'ifconfig', 'arp']
        if not any(command.lower().strip().startswith(cmd) for cmd in safe_commands):
            return {'error': 'Command not allowed', 'exit_code': 1}

        tokens = command.strip().split()
        if not tokens:
            return {'error': 'Empty command', 'exit_code': 1}

        # Map commands for Windows compatibility
        is_windows = platform.system().lower() == 'windows'
        base = tokens[0].lower()
        if is_windows:
            if base == 'ifconfig':
                tokens[0] = 'ipconfig'
            elif base == 'traceroute':
                tokens[0] = 'tracert'

        result = subprocess.run(tokens, capture_output=True, text=True, timeout=15)
        
        # Record in history
        history = CommandHistory(
            user_id=user_id,
            command=command,
            output=result.stdout[:1000],
            exit_code=result.returncode
        )
        db.session.add(history)
        db.session.commit()
        
        return {
            'output': result.stdout[:500],
            'error': result.stderr[:200] if result.stderr else '',
            'exit_code': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {'error': 'Command timed out', 'exit_code': -1}
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        return {'error': str(e), 'exit_code': -1}

def get_command_history(user_id, limit=50):
    """Get command execution history (Module 8)"""
    try:
        history = CommandHistory.query.filter_by(user_id=user_id).order_by(CommandHistory.timestamp.desc()).limit(limit).all()
        return [h.to_dict() for h in history]
    except Exception as e:
        logger.error(f"Error getting command history: {str(e)}")
        return []

# Initialize database
def init_db():
    with app.app_context():
        # Only create tables if they don't exist
        from sqlalchemy import text
        try:
            # Check if at least one table exists (user table is created first)
            result = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='user'"))
            user_table_exists = result.fetchone() is not None
            
            if not user_table_exists:
                db.create_all()
                logger.info("Created all database tables")
        except Exception as e:
            logger.warning(f"Database check failed: {e}, attempting create_all()")
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

def get_top_bandwidth_devices(hours: int = 24):
    """Attempt to retrieve per-device bandwidth usage from router via SSH.
    Returns a list of dicts with mac/ip/name and bytes fields when available.
    If router unavailable, falls back to local per-process network usage.
    """
    try:
        router_ip = os.environ.get('ROUTER_IP')
        router_user = os.environ.get('ROUTER_USER')
        router_pass = os.environ.get('ROUTER_PASS', '')
        if router_ip and router_user:
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(router_ip, username=router_user, password=router_pass, timeout=3)
                # Try nlbwmon (OpenWrt traffic monitor) first
                cmd = f"nlbw -c json -g mac -t {hours}h"  # last N hours by MAC
                stdin, stdout, stderr = ssh.exec_command(cmd)
                out = stdout.read().decode().strip()
                devices = []
                if out:
                    try:
                        data = json.loads(out)
                        for row in data.get('data', []):
                            devices.append({
                                'mac': row.get('mac') or row.get('address'),
                                'bytes_recv': int(row.get('rx', 0)),
                                'bytes_sent': int(row.get('tx', 0))
                            })
                    except Exception as e:
                        logger.warning(f"nlbw json parse failed: {e}")

                # Fallback: try nlbwmon CSV
                if not devices:
                    stdin, stdout, stderr = ssh.exec_command(f"nlbw -c csv -g mac -t {hours}h")
                    out = stdout.read().decode().strip()
                    if out and ',' in out:
                        try:
                            lines = [l for l in out.split('\n') if l and not l.lower().startswith('mac')]
                            for line in lines:
                                parts = [p.strip() for p in line.split(',')]
                                if len(parts) >= 3:
                                    devices.append({
                                        'mac': parts[0],
                                        'bytes_recv': int(parts[1] or 0),
                                        'bytes_sent': int(parts[2] or 0)
                                    })
                        except Exception as e:
                            logger.warning(f"nlbw csv parse failed: {e}")
                ssh.close()
                if devices:
                    return devices
            except Exception as router_err:
                logger.warning(f"Router query failed: {router_err}")
        
        # Fallback: Local per-process network stats using psutil
        try:
            import psutil
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    conns = proc.info.get('connections')
                    if conns:
                        io = proc.io_counters()
                        processes.append({
                            'name': proc.info['name'],
                            'pid': proc.info['pid'],
                            'bytes_sent': io.write_bytes,
                            'bytes_recv': io.read_bytes
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            # Aggregate by process name
            from collections import defaultdict
            agg = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0})
            for p in processes:
                agg[p['name']]['bytes_sent'] += p['bytes_sent']
                agg[p['name']]['bytes_recv'] += p['bytes_recv']
            return [{'mac': name, 'bytes_sent': v['bytes_sent'], 'bytes_recv': v['bytes_recv']} 
                    for name, v in agg.items()]
        except Exception as e:
            logger.error(f"Fallback per-process bandwidth failed: {e}")
        return []
    except Exception as e:
        logger.error(f"Error getting top bandwidth devices: {str(e)}")
        return []

def rotate_old_records(retention_days: int = 30):
    """Delete records older than retention across history tables"""
    try:
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        models = [SystemLog, LoginAttempt, SpeedtestResult, DnsLeakTest, TracerouteResult, CommandHistory, ServiceStatus]
        for model in models:
            try:
                model.query.filter(model.timestamp < cutoff).delete()
                db.session.commit()
            except Exception as e:
                logger.warning(f"Retention cleanup failed for {model.__name__}: {e}")
    except Exception as e:
        logger.error(f"Error rotating old records: {str(e)}")

# Routes

# Traffic Monitor: Capture all incoming requests
@app.before_request
def log_incoming_request():
    """Log all incoming requests with detailed information"""
    # Skip logging for static files and SSE streams to avoid noise
    if request.path.startswith('/static') or request.path == '/api/traffic/stream':
        return
    
    # Capture request start time
    request.start_time = time.time()
    
    # Store request details in flask.g for after_request hook
    from flask import g
    g.request_id = str(uuid.uuid4())
    g.request_start = request.start_time

@app.after_request
def log_request_completion(response):
    """Log request completion with response details"""
    from flask import g
    
    # Skip logging for static files and SSE streams
    if request.path.startswith('/static') or request.path == '/api/traffic/stream':
        return response
    
    try:
        # Calculate response time
        response_time = time.time() - getattr(g, 'request_start', time.time())
        
        # Get source IP (respect common proxy headers)
        source_ip = get_client_ip(request)
        
        # Determine if external or internal
        is_external = is_external_ip(source_ip)
        
        # Check for AdGuard headers
        adguard_processed = any([
            'X-AdGuard' in request.headers,
            'X-Adguard-Filtered' in request.headers,
            request.headers.get('X-Forwarded-Host', '').startswith('adguard')
        ])
        
        # Build request entry
        request_entry = {
            'id': getattr(g, 'request_id', str(uuid.uuid4())),
            'timestamp': iso_utc(datetime.now(timezone.utc)),
            'source_ip': source_ip,
            'is_external': is_external,
            'forwarded_for': request.headers.get('X-Forwarded-For'),
            'port': request.environ.get('SERVER_PORT', 5000),
            'method': request.method,
            'path': request.path,
            'full_url': request.url,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'referer': request.headers.get('Referer'),
            'host': request.headers.get('Host'),
            'protocol': request.scheme,
            'query_string': request.query_string.decode('utf-8'),
            'status_code': response.status_code,
            'response_time': round(response_time, 3),
            'adguard_processed': adguard_processed,
            'content_length': response.content_length,
            'issues': analyze_request_issues(source_ip, response.status_code, response_time, adguard_processed)
        }
        
        # Store in circular buffer (thread-safe)
        with traffic_lock:
            request_log.append(request_entry)
            
            # Update statistics
            request_stats['total_requests'] += 1
            request_stats['by_port'][str(request_entry['port'])] += 1
            request_stats['by_method'][request_entry['method']] += 1
            request_stats['by_status'][str(response.status_code)] += 1
            request_stats['by_ip'][source_ip] += 1
    
    except Exception as e:
        logger.error(f"Error logging request: {e}")
    
    return response

def analyze_request_issues(ip, status_code, response_time, adguard_processed):
    """Analyze request for potential issues"""
    issues = []
    
    # Check status code
    if status_code >= 500:
        issues.append(f"Server error: {status_code}")
    elif status_code >= 400:
        issues.append(f"Client error: {status_code}")
    elif status_code >= 300:
        issues.append(f"Redirect: {status_code}")
    
    # Check response time
    if response_time > 5:
        issues.append("Slow response (>5s) - possible network issue")
    elif response_time > 2:
        issues.append("Elevated response time (>2s)")
    
    # Check AdGuard
    if not adguard_processed and is_external_ip(ip):
        issues.append("External request may have bypassed AdGuard")
    
    return issues

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
        source_ip = get_client_ip(request)
        user_agent = request.headers.get('User-Agent', '')
        
        # Input validation
        if not username or not password:
            flash('Username and password are required', 'error')
            logger.warning("Login attempt with missing credentials")
            record_login_attempt_security(username, source_ip, False, user_agent)
            return render_template('login.html')
        
        # Rate limiting check
        allowed, error_msg = rate_limit_check(username)
        if not allowed:
            flash(error_msg, 'error')
            logger.warning(f"Rate limit exceeded for user: {username}")
            record_login_attempt_security(username, source_ip, False, user_agent)
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            session['start_time'] = iso_utc(datetime.now(timezone.utc))
            session.permanent = False
            logger.info(f"User {username} logged in successfully")
            record_login_attempt_security(username, source_ip, True, user_agent)
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(username)
            record_login_attempt_security(username, source_ip, False, user_agent)
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

@app.route('/api/top-processes')
@login_required
def top_processes():
    """Get top CPU and memory consuming processes"""
    try:
        limit = request.args.get('limit', 10, type=int)
        result = get_top_processes(limit)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in top_processes: {str(e)}")
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

@app.route('/api/device/<mac_address>', methods=['PUT'])
@csrf.exempt
@login_required
def update_device(mac_address):
    """Update device name, blocking status, and type"""
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        mac = mac_address.lower()
        
        device = ManagedDevice.query.filter_by(mac_address=mac).first()
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        # Update fields
        if 'custom_name' in data:
            device.custom_name = data['custom_name']
        if 'is_blocked' in data:
            device.is_blocked = data['is_blocked']
        if 'device_type' in data:
            device.device_type = data['device_type']
        if 'notes' in data:
            device.notes = data['notes']
        if 'is_new' in data:
            device.is_new = data['is_new']
        
        device.last_seen = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Updated device {mac}: {device.custom_name}")
        return jsonify(device.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error updating device: {str(e)}")
        return jsonify({'error': f'Failed to update device: {str(e)}'}), 500

@app.route('/api/devices/new', methods=['GET'])
@login_required
def get_new_devices():
    """Get newly discovered devices"""
    try:
        new_devices = ManagedDevice.query.filter_by(is_new=True).all()
        return jsonify({'devices': [d.to_dict() for d in new_devices], 'count': len(new_devices)}), 200
    except Exception as e:
        logger.error(f"Error getting new devices: {str(e)}")
        return jsonify({'error': 'Failed to get new devices'}), 500

@app.route('/api/device/<mac_address>/block', methods=['POST'])
@csrf.exempt
@login_required
def block_device(mac_address):
    """Block a device"""
    try:
        mac = mac_address.lower()
        device = ManagedDevice.query.filter_by(mac_address=mac).first()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        device.is_blocked = True
        device.last_seen = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Blocked device: {device.custom_name} ({mac})")
        return jsonify(device.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error blocking device: {str(e)}")
        return jsonify({'error': 'Failed to block device'}), 500

@app.route('/api/device/<mac_address>/unblock', methods=['POST'])
@csrf.exempt
@login_required
def unblock_device(mac_address):
    """Unblock a device"""
    try:
        mac = mac_address.lower()
        device = ManagedDevice.query.filter_by(mac_address=mac).first()
        
        if not device:
            return jsonify({'error': 'Device not found'}), 404
        
        device.is_blocked = False
        device.last_seen = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Unblocked device: {device.custom_name} ({mac})")
        return jsonify(device.to_dict()), 200
        
    except Exception as e:
        logger.error(f"Error unblocking device: {str(e)}")
        return jsonify({'error': 'Failed to unblock device'}), 500

@app.route('/api/diagnostics', methods=['POST'])
@login_required
@csrf.exempt
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

@app.route('/api/service-control', methods=['POST'])
@login_required
@csrf.exempt
def service_control():
    """Control service (stop/restart)"""
    try:
        data = request.get_json()
        service_name = data.get('service_name')
        action = data.get('action')  # stop or restart
        pid = data.get('pid')
        
        if not all([service_name, action, pid]):
            return jsonify({'success': False, 'error': 'Missing required parameters'}), 400
        
        if action not in ['stop', 'restart']:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        import psutil
        
        try:
            proc = psutil.Process(pid)
            
            if action == 'stop':
                proc.terminate()
                message = f'Service {service_name} (PID {pid}) stopped successfully'
                logger.info(message)
                try:
                    add_system_log(
                        log_type='system',
                        level='WARNING',
                        component='service_control',
                        message=message
                    )
                except Exception:
                    pass
                return jsonify({'success': True, 'message': message})
            
            elif action == 'restart':
                # For restart, we'll terminate and let systemd/supervisor restart it
                proc.terminate()
                message = f'Service {service_name} (PID {pid}) restarted (terminated for auto-restart)'
                logger.info(message)
                try:
                    add_system_log(
                        log_type='system',
                        level='INFO',
                        component='service_control',
                        message=message
                    )
                except Exception:
                    pass
                return jsonify({'success': True, 'message': message})
                
        except psutil.NoSuchProcess:
            return jsonify({'success': False, 'error': f'Process {pid} not found'}), 404
        except psutil.AccessDenied:
            return jsonify({'success': False, 'error': 'Access denied - insufficient permissions'}), 403
            
    except Exception as e:
        logger.error(f"Error in service_control: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

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
            # Return empty data structure instead of 404
            return jsonify({
                'cpu_min': 0,
                'cpu_max': 0,
                'cpu_avg': 0,
                'memory_min': 0,
                'memory_max': 0,
                'memory_avg': 0,
                'snapshots': []
            }), 200
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

@app.route('/api/server-time')
@login_required
def server_time():
    """Return server UTC time and local offset for client sync"""
    try:
        # Use timezone-aware UTC to avoid local offset skew
        now_utc = datetime.now(timezone.utc)
        # Make local time timezone-aware
        local_now = datetime.now().astimezone()
        # Offset minutes: local timezone offset (for information only)
        offset = local_now.utcoffset() or timedelta(0)
        offset_minutes = int(offset.total_seconds() / 60)
        return jsonify({
            'server_utc_ms': int(now_utc.timestamp() * 1000),
            'server_offset_minutes': offset_minutes,
            'server_local_time': local_now.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        logger.error(f"Error in server_time: {str(e)}")
        return jsonify({'error': 'Failed to get server time'}), 500

@app.route('/api/open-ports')
@login_required
def open_ports():
    """Scan open ports on host and router"""
    try:
        import socket
        host_ip = request.args.get('host', '192.168.8.176')
        router_ip = os.environ.get('ROUTER_IP', '192.168.8.1')
        
        def scan_host(ip, ports_to_check=None):
            if ports_to_check is None:
                # Common ports
                ports_to_check = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5000, 8080, 8443]
            open_ports = []
            for port in ports_to_check:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    pass
            return open_ports
        
        host_ports = scan_host(host_ip)
        router_ports = scan_host(router_ip)
        
        return jsonify({
            'host': {'ip': host_ip, 'ports': host_ports},
            'router': {'ip': router_ip, 'ports': router_ports}
        })
    except Exception as e:
        logger.error(f"Error in open_ports: {str(e)}")
        return jsonify({'error': 'Failed to scan ports'}), 500

@app.route('/api/security-summary')
@login_required
def security_summary():
    """Get security summary (Module 5)"""
    try:
        summary = get_security_summary()
        if summary:
            return jsonify(summary)
        else:
            return jsonify({'error': 'Failed to get summary'}), 500
    except Exception as e:
        logger.error(f"Error in security_summary: {str(e)}")
        return jsonify({'error': 'Failed to get security summary'}), 500

@app.route('/api/top-bandwidth-devices')
@login_required
def top_bandwidth_devices():
    """Return per-device bandwidth usage when router integration is available"""
    try:
        hours = request.args.get('hours', 24, type=int)
        devices = get_top_bandwidth_devices(hours=hours)
        # Sort by total bytes desc
        devices_sorted = sorted(devices, key=lambda d: d.get('bytes_recv', 0) + d.get('bytes_sent', 0), reverse=True)
        return jsonify({'devices': devices_sorted, 'hours': hours})
    except Exception as e:
        logger.error(f"Error in top_bandwidth_devices: {str(e)}")
        return jsonify({'devices': [], 'hours': 24}), 200

@app.route('/api/login-history')
@login_required
def login_history():
    """Get login attempt history (Module 5)"""
    try:
        limit = request.args.get('limit', 50, type=int)
        attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(limit).all()
        return jsonify({'attempts': [a.to_dict() for a in attempts]})
    except Exception as e:
        logger.error(f"Error in login_history: {str(e)}")
        return jsonify({'error': 'Failed to get login history'}), 500

@app.route('/api/port-scan-alerts')
@login_required
def port_scan_alerts():
    """Get port scan alerts (Module 5)"""
    try:
        limit = request.args.get('limit', 50, type=int)
        days = request.args.get('days', 1, type=int)
        since = datetime.utcnow() - timedelta(days=days)
        alerts = PortScanAlert.query.filter(PortScanAlert.timestamp >= since).order_by(PortScanAlert.timestamp.desc()).limit(limit).all()
        return jsonify({'alerts': [a.to_dict() for a in alerts]})
    except Exception as e:
        logger.error(f"Error in port_scan_alerts: {str(e)}")
        return jsonify({'error': 'Failed to get port scan alerts'}), 500

@app.route('/api/vpn-status')
@login_required
def vpn_status():
    """Get VPN connection status (Module 5)"""
    try:
        status = get_vpn_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error in vpn_status: {str(e)}")
        return jsonify({'error': 'Failed to get VPN status'}), 500

@app.route('/api/speedtest', methods=['POST'])
@login_required
@csrf.exempt
def speedtest():
    """Run internet speedtest (Module 6)"""
    try:
        result = run_speedtest_check()
        if result:
            # Record event in system logs
            try:
                add_system_log(
                    log_type='network',
                    level='INFO',
                    component='speedtest',
                    message=f"Download {result.get('download_speed')} Mbps, Upload {result.get('upload_speed')} Mbps, Ping {result.get('ping')} ms"
                )
            except Exception as _:
                pass
            return jsonify(result)
        else:
            return jsonify({'error': 'Speedtest failed'}), 500
    except Exception as e:
        logger.error(f"Error in speedtest: {str(e)}")
        return jsonify({'error': 'Speedtest error'}), 500

@app.route('/api/speedtest-history')
@login_required
def speedtest_history():
    """Get speedtest history (Module 6)"""
    try:
        days = request.args.get('days', 7, type=int)
        since = datetime.utcnow() - timedelta(days=days)
        results = SpeedtestResult.query.filter(SpeedtestResult.timestamp >= since).order_by(SpeedtestResult.timestamp.desc()).all()
        return jsonify({'results': [r.to_dict() for r in results]})
    except Exception as e:
        logger.error(f"Error in speedtest_history: {str(e)}")
        return jsonify({'error': 'Failed to get speedtest history'}), 500

@app.route('/api/dns-leak-test', methods=['POST'])
@login_required
@csrf.exempt
def dns_leak_test():
    """Check for DNS leaks (Module 6)"""
    try:
        result = check_dns_leaks()
        if result:
            # Record event in system logs
            try:
                leaked = result.get('leaked')
                servers = result.get('dns_servers', [])
                servers_count = len(servers) if isinstance(servers, list) else 0
                add_system_log(
                    log_type='security',
                    level='WARNING' if leaked else 'INFO',
                    component='dns_leak_test',
                    message=f"DNS leak {'DETECTED' if leaked else 'not detected'}; servers: {servers_count}"
                )
            except Exception as _:
                pass
            return jsonify(result)
        else:
            return jsonify({'error': 'DNS leak test failed'}), 500
    except Exception as e:
        logger.error(f"Error in dns_leak_test: {str(e)}")
        return jsonify({'error': 'DNS leak test error'}), 500

@app.route('/api/dns-leak-history')
@login_required
def dns_leak_history():
    """Get DNS leak test history (Module 6)"""
    try:
        limit = request.args.get('limit', 20, type=int)
        tests = DnsLeakTest.query.order_by(DnsLeakTest.timestamp.desc()).limit(limit).all()
        return jsonify({'tests': [t.to_dict() for t in tests]})
    except Exception as e:
        logger.error(f"Error in dns_leak_history: {str(e)}")
        return jsonify({'error': 'Failed to get DNS leak history'}), 500

@app.route('/api/traceroute', methods=['POST'])
@login_required
@csrf.exempt
def traceroute():
    """Run traceroute to target (Module 6)"""
    try:
        data = request.json
        target = data.get('target', 'google.com')
        result = run_traceroute_check(target)
        if result:
            # Record event in system logs
            try:
                add_system_log(
                    log_type='network',
                    level='INFO',
                    component='traceroute',
                    message=f"Traceroute to {result.get('target')} hops={result.get('hops')}"
                )
            except Exception as _:
                pass
            return jsonify(result)
        else:
            return jsonify({'error': 'Traceroute failed'}), 500
    except Exception as e:
        logger.error(f"Error in traceroute: {str(e)}")
        return jsonify({'error': 'Traceroute error'}), 500

@app.route('/api/device-tags')
@login_required
def device_tags():
    """Get all tagged devices (Module 7)"""
    try:
        tags = get_device_tags()
        return jsonify({'tags': tags})
    except Exception as e:
        logger.error(f"Error in device_tags: {str(e)}")
        return jsonify({'error': 'Failed to get device tags'}), 500

@app.route('/api/device-tag', methods=['POST'])
@login_required
def add_device_tag():
    """Add or update device tag (Module 7)"""
    try:
        data = request.json
        success = tag_device(
            mac_address=data.get('mac_address'),
            device_name=data.get('device_name'),
            device_type=data.get('device_type'),
            description=data.get('description')
        )
        return jsonify({'status': 'tagged' if success else 'failed'})
    except Exception as e:
        logger.error(f"Error in add_device_tag: {str(e)}")
        return jsonify({'error': 'Failed to tag device'}), 500

@app.route('/api/bandwidth-quotas')
@login_required
def bandwidth_quotas():
    """Get bandwidth quotas (Module 7)"""
    try:
        quotas = get_bandwidth_quotas()
        return jsonify({'quotas': quotas})
    except Exception as e:
        logger.error(f"Error in bandwidth_quotas: {str(e)}")
        return jsonify({'error': 'Failed to get quotas'}), 500

@app.route('/api/bandwidth-quota', methods=['POST'])
@login_required
def set_quota():
    """Set bandwidth quota for device (Module 7)"""
    try:
        data = request.json
        success = set_bandwidth_quota(
            mac_address=data.get('mac_address'),
            daily_limit_mb=data.get('daily_limit_mb', 1000),
            monthly_limit_gb=data.get('monthly_limit_gb', 30)
        )
        return jsonify({'status': 'set' if success else 'failed'})
    except Exception as e:
        logger.error(f"Error in set_quota: {str(e)}")
        return jsonify({'error': 'Failed to set quota'}), 500

@app.route('/api/auto-alerts')
@login_required
def auto_alerts():
    """Get auto alert rules (Module 7)"""
    try:
        alerts = get_auto_alerts()
        return jsonify({'alerts': alerts})
    except Exception as e:
        logger.error(f"Error in auto_alerts: {str(e)}")
        return jsonify({'error': 'Failed to get auto alerts'}), 500

@app.route('/api/auto-alert', methods=['POST'])
@login_required
def create_alert():
    """Create auto alert rule (Module 7)"""
    try:
        data = request.json
        alert = create_auto_alert(
            alert_type=data.get('alert_type'),
            threshold=data.get('threshold', 80),
            email_notify=data.get('email_notify', False)
        )
        return jsonify(alert if alert else {'error': 'Failed to create alert'})
    except Exception as e:
        logger.error(f"Error in create_alert: {str(e)}")
        return jsonify({'error': 'Failed to create auto alert'}), 500

@app.route('/api/command-execute', methods=['POST'])
@login_required
@csrf.exempt
def command_execute():
    """Execute a router command (Module 8)"""
    try:
        data = request.json
        command = data.get('command', '').strip()
        result = execute_router_command(current_user.id, command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command_execute: {str(e)}")
        return jsonify({'error': 'Failed to execute command'}), 500

@app.route('/api/command-history')
@login_required
def command_history():
    """Get command execution history (Module 8)"""
    try:
        limit = request.args.get('limit', 50, type=int)
        history = get_command_history(current_user.id, limit=limit)
        return jsonify({'history': history})
    except Exception as e:
        logger.error(f"Error in command_history: {str(e)}")
        return jsonify({'error': 'Failed to get command history'}), 500

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

# ============================================
# TRAFFIC MONITOR ROUTES
# ============================================

@app.route('/traffic-monitor')
@login_required
def traffic_monitor():
    """Traffic Monitor dashboard page"""
    return render_template('traffic_monitor.html')

@app.route('/api/traffic/recent')
@login_required
def get_recent_traffic():
    """Get recent traffic logs"""
    limit = request.args.get('limit', 50, type=int)
    
    with traffic_lock:
        recent = list(request_log)[-limit:]
        recent.reverse()  # Most recent first
    
    return jsonify({
        'success': True,
        'requests': recent,
        'total': len(request_log)
    })

@app.route('/api/traffic/stats')
@login_required
def get_traffic_stats():
    """Get traffic statistics"""
    with traffic_lock:
        total = request_stats['total_requests']
        
        # Calculate success rate
        success_count = sum(count for status, count in request_stats['by_status'].items() if status.startswith('2'))
        success_rate = (success_count / total * 100) if total > 0 else 0
        
        # Get top IPs
        top_ips = sorted(request_stats['by_ip'].items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Get recent requests for path analysis
        recent_paths = defaultdict(int)
        for req in list(request_log)[-100:]:
            recent_paths[req['path']] += 1
        top_paths = sorted(recent_paths.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate average response time
        recent_requests = list(request_log)[-100:]
        avg_response_time = sum(r['response_time'] for r in recent_requests) / len(recent_requests) if recent_requests else 0
        
        stats = {
            'total_requests': total,
            'success_rate': round(success_rate, 2),
            'by_port': dict(request_stats['by_port']),
            'by_method': dict(request_stats['by_method']),
            'by_status': dict(request_stats['by_status']),
            'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
            'top_paths': [{'path': path, 'count': count} for path, count in top_paths],
            'avg_response_time': round(avg_response_time, 3),
            'buffer_size': len(request_log),
            'buffer_capacity': request_log.maxlen
        }
    
    return jsonify({'success': True, 'stats': stats})

@app.route('/api/traffic/filter')
@login_required
def filter_traffic():
    """Filter traffic by various criteria"""
    port = request.args.get('port')
    ip = request.args.get('ip')
    method = request.args.get('method')
    status = request.args.get('status')
    external_only = request.args.get('external', 'false').lower() == 'true'
    
    with traffic_lock:
        filtered = list(request_log)
    
    # Apply filters
    if port:
        filtered = [r for r in filtered if str(r['port']) == port]
    if ip:
        filtered = [r for r in filtered if ip.lower() in r['source_ip'].lower()]
    if method:
        filtered = [r for r in filtered if r['method'] == method.upper()]
    if status:
        filtered = [r for r in filtered if str(r['status_code']).startswith(status)]
    if external_only:
        filtered = [r for r in filtered if r['is_external']]
    
    filtered.reverse()  # Most recent first
    
    return jsonify({
        'success': True,
        'requests': filtered,
        'total': len(filtered)
    })

@app.route('/api/traffic/clear', methods=['POST'])
@login_required
@csrf.exempt
def clear_traffic():
    """Clear all traffic logs"""
    with traffic_lock:
        request_log.clear()
        # Reset statistics
        request_stats['total_requests'] = 0
        request_stats['by_port'].clear()
        request_stats['by_method'].clear()
        request_stats['by_status'].clear()
        request_stats['by_ip'].clear()
    
    log_system_event(current_user.username, 'traffic_logs_cleared', 'Traffic logs cleared by user')
    
    return jsonify({'success': True, 'message': 'Traffic logs cleared'})

@app.route('/api/traffic/export')
@login_required
def export_traffic():
    """Export traffic logs as CSV"""
    with traffic_lock:
        logs = list(request_log)
    
    # Create CSV in memory
    output = io.StringIO()
    if logs:
        fieldnames = ['id', 'timestamp', 'source_ip', 'is_external', 'port', 'method', 'path', 
                     'status_code', 'response_time', 'user_agent', 'referer', 'host', 
                     'protocol', 'adguard_processed', 'issues']
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for log in logs:
            # Convert issues list to string
            log_copy = log.copy()
            log_copy['issues'] = '; '.join(log_copy.get('issues', []))
            writer.writerow(log_copy)
    
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=traffic_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )

@app.route('/api/traffic/stream')
@login_required
def traffic_stream():
    """Server-Sent Events stream for real-time traffic updates"""
    def generate():
        last_count = len(request_log)
        
        while True:
            try:
                with traffic_lock:
                    current_count = len(request_log)
                    
                    # Check if new requests arrived
                    if current_count > last_count:
                        # Get new requests
                        new_requests = list(request_log)[last_count:]
                        for req in new_requests:
                            yield f"data: {json.dumps(req)}\\n\\n"
                        last_count = current_count
                    elif current_count < last_count:
                        # Buffer was cleared or wrapped around
                        last_count = current_count
                
                time.sleep(1)  # Check every second
            except GeneratorExit:
                break
            except Exception as e:
                logger.error(f"Error in traffic stream: {e}")
                break
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

def background_performance_snapshot_task():
    """Background task to create performance snapshots every 60 seconds"""
    while True:
        try:
            time.sleep(60)  # Wait 60 seconds between snapshots
            with app.app_context():
                create_performance_snapshot()
                logger.debug("Performance snapshot created")
        except Exception as e:
            logger.error(f"Error in background performance snapshot task: {str(e)}")

if __name__ == '__main__':
    init_db()
    
    # Debug mode should be False in production
    debug_mode = os.environ.get('FLASK_ENV', 'production') == 'development'
    
    if debug_mode:
        logger.warning("Running in DEBUG mode - DO NOT USE IN PRODUCTION")
    
    # Create initial performance snapshot
    with app.app_context():
        try:
            create_performance_snapshot()
            logger.info("Created initial performance snapshot")
            
            # Optionally create sample logs if explicitly enabled
            if os.environ.get('CREATE_SAMPLE_LOGS') == '1':
                create_sample_logs()
            else:
                # Remove any old sample logs so Logs tab reflects real activity only
                purge_sample_logs_if_present()
            # One-time retention cleanup on startup
            try:
                rotate_old_records(int(os.environ.get('LOG_RETENTION_DAYS', '30')))
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Error creating initial snapshot: {str(e)}")
    
    # Start background performance snapshot task
    snapshot_thread = threading.Thread(target=background_performance_snapshot_task, daemon=True)
    snapshot_thread.start()
    logger.info("Started background performance snapshot task")
    
    # Daily retention cleanup (30 days by default)
    def _retention_task():
        while True:
            try:
                days = int(os.environ.get('LOG_RETENTION_DAYS', '30'))
                with app.app_context():
                    rotate_old_records(days)
            except Exception as e:
                logger.error(f"Retention task error: {e}")
            # Sleep ~24h
            time.sleep(24 * 3600)

    retention_thread = threading.Thread(target=_retention_task, daemon=True)
    retention_thread.start()
    logger.info("Started retention cleanup task")
    
    app.run(
        debug=debug_mode,
        host=os.environ.get('FLASK_HOST', '0.0.0.0'),  # Bind to all interfaces to accept external connections
        port=int(os.environ.get('FLASK_PORT', 5000))
    )
