@echo off
title BIOS Patching For Beginners - Master Tool
cd /d "%~dp0"

echo Starting Master BIOS Patcher...
python master_patcher.py %*

if %errorlevel% neq 0 (
    echo.
    echo [!] Python returned an error code %errorlevel%.
    pause
)
