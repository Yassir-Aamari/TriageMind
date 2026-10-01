@echo off
title TriageMind — Security Pipeline
color 0A
python main.py
if errorlevel 1 (
    echo.
    echo [ERROR] TriageMind exited with an error.
    echo Make sure you ran setup.bat first.
    echo See README.md for troubleshooting.
    pause
)
