"""
Sherlock AI Standalone Native Desktop Application Launcher.

Launches the backend FastAPI service and opens the Sherlock AI Forensic Vault
inside a dedicated native desktop application window (No address bar, no tabs).
"""

import sys
import os
import time
import subprocess
import threading
import uvicorn
import shutil

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

def start_backend():
    """Runs FastAPI uvicorn backend server on 0.0.0.0:8000."""
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="error")

def launch_native_app_window(url):
    """Launches the URL in a dedicated Desktop App Window (App Mode)."""
    # 1. Try PyWebView if installed
    try:
        import webview
        print("-> Launching Native GUI Window via PyWebView...")
        webview.create_window("Sherlock AI Forensic Vault", url, width=1366, height=868, resizable=True)
        webview.start()
        return
    except ImportError:
        pass
    except Exception as e:
        print(f"PyWebView warning: {e}")

    # 2. Try Edge App Mode (Built-in on Windows 10/11)
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        shutil.which("msedge")
    ]
    for edge in edge_paths:
        if edge and os.path.exists(edge):
            print(f"-> Launching Desktop Application Window via Edge App Mode...")
            subprocess.Popen([edge, f"--app={url}", "--name=Sherlock AI Forensic Vault", "--window-size=1366,868"])
            return

    # 3. Try Chrome App Mode
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        shutil.which("chrome")
    ]
    for chrome in chrome_paths:
        if chrome and os.path.exists(chrome):
            print(f"-> Launching Desktop Application Window via Chrome App Mode...")
            subprocess.Popen([chrome, f"--app={url}", "--name=Sherlock AI Forensic Vault", "--window-size=1366,868"])
            return

    # Fallback: Open standard browser
    import webbrowser
    webbrowser.open(url)

if __name__ == "__main__":
    local_ip = get_local_ip()
    target_url = "http://127.0.0.1:8000/ui/"

    print("==================================================================")
    print("  Sherlock AI Native Desktop Application Launcher")
    print(f"  Desktop App URL : {target_url}")
    print(f"  Network Share   : http://{local_ip}:8000/ui/")
    print("==================================================================")

    # Start FastAPI server in a daemon thread
    server_thread = threading.Thread(target=start_backend, daemon=True)
    server_thread.start()

    # Give uvicorn a moment to bind port 8000
    time.sleep(1.5)

    # Launch native desktop application window
    launch_native_app_window(target_url)

    # Keep main thread alive so daemon server stays running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nSherlock AI Desktop Application closed.")

