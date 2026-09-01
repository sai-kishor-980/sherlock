@echo off
echo Cleaning up unnecessary temporary files...

powershell -ExecutionPolicy Bypass -File "%~dp0clean.ps1"

echo Done.
pause
