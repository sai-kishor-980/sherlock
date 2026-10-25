@echo off
title Sherlock AI — Build Standalone Desktop Executable (.exe)
echo ==================================================================
echo   Building Sherlock AI Standalone Desktop Application (.exe)
echo ==================================================================
cd /d "%~dp0"
python build_desktop_app.py
pause
