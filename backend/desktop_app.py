"""
HMACFR Standalone Native Desktop Application Launcher.

Launches the backend FastAPI service and opens the HMACFR Forensic Vault
inside a dedicated native desktop application window.
"""

import sys
import os
import time
import subprocess
import threading
import uvicorn

# Apply bcrypt compatibility patch for passlib before loading app
import bcrypt
if not hasattr(bcrypt, "__about__"):
    class BcryptAbout:
        __version__ = getattr(bcrypt, "__version__", "4.0.1")
    bcrypt.__about__ = BcryptAbout

# Add backend directory to sys.path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app

def get_local_ip():
    """Resolves local Wi-Fi IP address for network sharing."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def run_server():
    """Runs FastAPI uvicorn backend server on 0.0.0.0:8000 for local Wi-Fi network sharing."""
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error")

if __name__ == "__main__":
    local_ip = get_local_ip()
    wifi_url = f"http://{local_ip}:8000/ui/"

    print("==================================================================")
    print("  Sherlock AI Application Server Running")
    print("  Local Desktop App : http://127.0.0.1:8000/ui/")
    print(f"  Wi-Fi Laptop Link : {wifi_url}")
    print("  Press Ctrl+C in this window to stop the server.")
    print("==================================================================")

    # Launch browser automatically
    try:
        import webbrowser
        webbrowser.open("http://127.0.0.1:8000/ui/")
    except Exception:
        pass

    # Run Uvicorn server synchronously on main thread
    uvicorn.run(app, host="0.0.0.0", port=8000)
