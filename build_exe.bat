@echo off
title TriageMind — Build EXE
color 0A

echo.
echo =========================================================
echo  TriageMind — Building Executable
echo =========================================================
echo.

REM Check PyInstaller is installed
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building TriageMind.exe...
echo This will take 1-3 minutes.
echo.

pyinstaller ^
    --onedir ^
    --name TriageMind ^
    --console ^
    --clean ^
    main.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed.
    echo Check the output above for errors.
    pause
    exit /b 1
)

echo.
echo =========================================================
echo  Build complete!
echo =========================================================
echo.
echo Output folder: dist\TriageMind\
echo.
echo IMPORTANT: After building you must also:
echo   1. Copy your requirements.txt to dist\TriageMind\
echo   2. Run: playwright install chromium
echo      (Playwright browsers cannot be bundled in the exe)
echo   3. Zip the entire dist\TriageMind\ folder for distribution
echo.
echo The person receiving the zip must:
echo   1. Extract the zip
echo   2. Run setup.bat (or: playwright install chromium)
echo   3. Run TriageMind.exe
echo.
pause
