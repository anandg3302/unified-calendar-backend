@echo off
echo Starting Unified Calendar Backend Server...
echo.
cd /d "%~dp0"
python start_server.py
pause
