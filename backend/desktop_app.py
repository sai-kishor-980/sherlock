"""
Sherlock AI Standalone Native Desktop Application Launcher.

Launches the backend FastAPI service and opens the Sherlock AI Forensic Platform
inside a dedicated native desktop application window (No address bar, no tabs).
"""

import sys
import os
import time
import subprocess
import threading
import socket
import shutil
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

# PyInstaller frozen bundle support
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    sys.path.insert(0, sys._MEIPASS)

from main import app

def find_available_port(preferred_port=8000):
    """Finds an available TCP port starting from preferred_port."""
    port = preferred_port
    while port < preferred_port + 100:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
        port += 1
    return preferred_port

def wait_for_server(port, timeout=10):
    """Waits until the server is listening on port."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) == 0:
                return True
        time.sleep(0.2)
    return False

def start_backend(port):
    """Runs FastAPI uvicorn backend server on 127.0.0.1."""
    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False
    )
    server = uvicorn.Server(config)
    server.run()

def launch_native_app_window(url, port):
    """Launches the URL in a dedicated native Desktop Window."""
    window_title = "Sherlock AI — Enterprise Digital Forensics & Preservation Platform"

    # 1. Try PyWebView (True native desktop window with Edge WebView2 engine)
    try:
        import webview
        print(f"-> Launching native desktop window via PyWebView on port {port}...")
        window = webview.create_window(
            title=window_title,
            url=url,
            width=1400,
            height=900,
            min_size=(1024, 700),
            resizable=True,
            confirm_close=False,
            background_color='#ffffff'
        )
        webview.start(debug=False)
        return True
    except Exception as e:
        print(f"PyWebView note: {e}")

    # 2. Fallback: Edge App Mode (Frameless dedicated window on Windows 10/11)
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        shutil.which("msedge")
    ]
    for edge in edge_paths:
        if edge and os.path.exists(edge):
            print(f"-> Launching desktop application window via Edge App Mode...")
            proc = subprocess.Popen([edge, f"--app={url}", f"--name={window_title}", "--window-size=1400,900"])
            proc.wait()
            return True

    # 3. Fallback: Chrome App Mode
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        shutil.which("chrome")
    ]
    for chrome in chrome_paths:
        if chrome and os.path.exists(chrome):
            print(f"-> Launching desktop application window via Chrome App Mode...")
            proc = subprocess.Popen([chrome, f"--app={url}", f"--name={window_title}", "--window-size=1400,900"])
            proc.wait()
            return True

    # 4. Fallback: Open standard web browser
    import webbrowser
    webbrowser.open(url)
    return False

if __name__ == "__main__":
    port = find_available_port(8000)
    target_url = f"http://127.0.0.1:{port}/ui/"

    print("==================================================================")
    print("  Sherlock AI Native Desktop Application")
    print(f"  Target Endpoint : {target_url}")
    print("==================================================================")

    # Start FastAPI server in a background daemon thread
    server_thread = threading.Thread(target=start_backend, args=(port,), daemon=True)
    server_thread.start()

    # Wait for the backend to be ready
    wait_for_server(port, timeout=8)

    # Launch native desktop application window (blocks until user closes the window)
    launch_native_app_window(target_url, port)

    # Clean shutdown on window close
    print("\nSherlock AI Desktop Application closed.")
    sys.exit(0)
