@echo off
title TriageMind — Setup
color 0A

echo.
echo ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗███╗   ███╗██╗███╗   ██╗██████╗
echo ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝████╗ ████║██║████╗  ██║██╔══██╗
echo    ██║   ██████╔╝██║███████║██║  ███╗█████╗  ██╔████╔██║██║██╔██╗ ██║██║  ██║
echo    ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝  ██║╚██╔╝██║██║██║╚██╗██║██║  ██║
echo    ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝
echo    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝
echo.
echo =========================================================
echo  TriageMind Setup — Installing dependencies
echo =========================================================
echo.

REM Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
echo [OK] Python found
echo.

REM Install Python dependencies
echo [1/2] Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install Python dependencies.
    echo Try running: pip install -r requirements.txt manually
    pause
    exit /b 1
)
echo [OK] Python dependencies installed
echo.

REM Install Playwright browsers
echo [2/2] Installing Playwright Chromium browser...
playwright install chromium
if errorlevel 1 (
    echo [ERROR] Failed to install Playwright browser.
    echo Try running: playwright install chromium manually
    pause
    exit /b 1
)
echo [OK] Playwright Chromium installed
echo.

echo =========================================================
echo  Setup complete! TriageMind is ready to use.
echo =========================================================
echo.
echo  To run TriageMind:
echo    python main.py
echo.
echo  Read README.md for full usage instructions.
echo.
pause
