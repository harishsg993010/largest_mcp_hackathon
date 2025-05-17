"""
Run script for MCP Auth Platform.
This script starts the backend server and optionally serves the frontend.
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
    backend_dir = os.path.join(os.path.dirname(__file__), 'backend')
    os.chdir(backend_dir)
    os.environ['FLASK_ENV'] = 'development'
    
    # Set a default port if not specified
    port = os.getenv('PORT', '8001')
    print(f"Backend server running on http://localhost:{port}")
    
    # Simply run app.py directly - it has its own if __name__ == '__main__' block
    cmd = [sys.executable, 'app.py']
    
    # Run the command in the backend directory
    subprocess.run(cmd, cwd=backend_dir)

def run_frontend():
    """Run a simple HTTP server for the frontend if the directory exists."""
    frontend_dir = os.path.join(os.path.dirname(__file__), 'frontend')
    if not os.path.exists(frontend_dir):
        print("Frontend directory not found. Running in backend-only mode.")
        return
        
    print("Starting frontend server...")
    try:
        # Run the HTTP server in the frontend directory
        subprocess.run(
            [sys.executable, '-m', 'http.server', '8000'],
            cwd=frontend_dir
        )
    except Exception as e:
        print(f"Error starting frontend server: {e}")

def open_browser():
    """Open the browser to the frontend."""
    print("Opening browser...")
    time.sleep(2)  # Wait for servers to start
    webbrowser.open('http://localhost:8000')

if __name__ == '__main__':
    # First, check if we need to set up the database
    db_path = os.path.join('backend', 'mcp_auth_dev.db')
    if not os.path.exists(db_path):
        print("Database not found. Running setup...")
        subprocess.run([sys.executable, 'setup.py'])
    
    # Start the backend in a separate thread
    backend_thread = threading.Thread(target=run_backend)
    backend_thread.daemon = True
    backend_thread.start()
    
    # Start the frontend in a separate thread
    frontend_thread = threading.Thread(target=run_frontend)
    frontend_thread.daemon = True
    frontend_thread.start()
    
    # Open the browser after a short delay
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
