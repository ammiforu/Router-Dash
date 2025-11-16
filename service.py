"""
Windows Service entry point for Router Dashboard
This script runs the application using Waitress WSGI server
"""
import os
import sys
from pathlib import Path

# Set working directory to script location
os.chdir(Path(__file__).parent)

# Import the Flask app
from app import app

if __name__ == '__main__':
    # Use Waitress for production serving
    try:
        from waitress import serve
        
        # Get configuration from environment
        host = os.getenv('FLASK_HOST', '0.0.0.0')
        port = int(os.getenv('FLASK_PORT', '5000'))
        threads = 6
        
        print(f"Starting Router Dashboard on {host}:{port}")
        print(f"Using Waitress WSGI Server with {threads} threads")
        
        # Start the server
        serve(
            app,
            host=host,
            port=port,
            threads=threads,
            channel_timeout=120,
            connection_limit=1000,
            cleanup_interval=30,
            backlog=2048
        )
    except ImportError:
        print("ERROR: Waitress not installed. Installing...")
        import subprocess
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'waitress'])
        print("Please restart the service.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start server: {e}")
        sys.exit(1)
