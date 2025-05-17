"""
Run script for MCP Auth Platform.
This script starts the backend server and serves the frontend.
"""

import os
import sys
import subprocess
import threading
import time
import webbrowser
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def run_backend():
    """Run the backend Flask server."""
    print("Starting backend server...")
    os.chdir('backend')
    os.environ['FLASK_ENV'] = 'development'
    subprocess.run([sys.executable, 'app.py'])

def run_frontend():
    """Run a simple HTTP server for the frontend."""
    print("Starting frontend server...")
    os.chdir('frontend')
    subprocess.run([sys.executable, '-m', 'http.server', '8000'])

def open_browser():
    """Open the browser to the frontend."""
    print("Opening browser...")
    time.sleep(2)  # Wait for servers to start
    webbrowser.open('http://localhost:8000')

if __name__ == '__main__':
    # First, check if we need to set up the database
    if not os.path.exists('backend/mcp_auth_dev.db'):
        print("Database not found. Running setup...")
        subprocess.run([sys.executable, 'setup.py'])
    
    # Start the backend in a separate thread
    backend_thread = threading.Thread(target=run_backend)
    backend_thread.daemon = True
    backend_thread.start()
    
    # Open the browser
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    # Run the frontend (this will block until terminated)
    run_frontend()
