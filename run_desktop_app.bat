@echo off
title Sherlock AI — Desktop Application Launcher
echo ==================================================================
echo   Starting Sherlock AI Desktop Application...
echo ==================================================================

cd /d "%~dp0backend"
python desktop_app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Backend exited with code %ERRORLEVEL%.
    pause
)

