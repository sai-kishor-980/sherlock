"""
Build Script to compile Sherlock AI into a standalone Windows .exe desktop application.
Uses PyInstaller to bundle the Python backend, FastAPI engine, and Frontend assets into a single executable.
"""

import os
import sys
import subprocess
import shutil

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    frontend_dir = os.path.join(root_dir, "frontend")
    icon_path = os.path.join(root_dir, "app_icon.ico")
    entry_point = os.path.join(backend_dir, "desktop_app.py")

    print("==================================================================")
    print("  Sherlock AI Standalone Executable (.exe) Builder")
    print("==================================================================")
    print(f"Root Directory   : {root_dir}")
    print(f"Backend Entry    : {entry_point}")
    print(f"Frontend Directory: {frontend_dir}")
    print(f"App Icon         : {icon_path}")

    # Hidden imports required for Uvicorn, FastAPI, PyWebView, and cryptographic tools
    hidden_imports = [
        "uvicorn",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "fastapi",
        "starlette",
        "starlette.routing",
        "fastapi.staticfiles",
        "webview",
        "webview.platforms.winforms",
        "pythonnet",
        "clr",
        "sqlite3",
        "passlib",
        "passlib.handlers.bcrypt",
        "bcrypt",
        "pydantic",
        "pydantic_settings",
        "email_validator",
        "multipart",
        "websockets",
        "jose",
        "python_jose",
        "app.core.config",
        "app.api.api",
        "app.db.database",
    ]

    # Data folders to embed into the executable
    # format: SOURCE_PATH;DEST_FOLDER on Windows
    add_data = [
        f"{frontend_dir};frontend",
        f"{backend_dir};backend"
    ]

    # PyInstaller arguments
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",                       # --onedir creates a fast, reliable desktop app bundle
        "--windowed",                     # Hide console window
        "--name=SherlockAI",
        f"--icon={icon_path}" if os.path.exists(icon_path) else "",
        f"--paths={backend_dir}",
    ]

    for hi in hidden_imports:
        cmd.extend(["--hidden-import", hi])

    for ad in add_data:
        cmd.extend(["--add-data", ad])

    cmd.append(entry_point)

    # Filter out empty arguments
    cmd = [arg for arg in cmd if arg]

    print("\nRunning PyInstaller command:")
    print(" ".join(cmd[:10]), "...")

    result = subprocess.run(cmd, cwd=root_dir)
    if result.returncode == 0:
        exe_path = os.path.join(root_dir, "dist", "SherlockAI", "SherlockAI.exe")
        print("\n==================================================================")
        print("  BUILD SUCCESSFUL!")
        print(f"  Standalone Executable created at:")
        print(f"  --> {exe_path}")
        print("==================================================================")
    else:
        print("\nBuild failed with exit code:", result.returncode)

if __name__ == "__main__":
    main()
