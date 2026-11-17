@echo off
title BruteForce Attack Detector - Cyberpunk Terminal
cd /d "%~dp0"

echo ========================================================
echo   BRUTEFORCE ATTACK DETECTOR // CYBERPUNK TERMINAL
echo   DSA Project: Queue (FIFO) + Stack (LIFO) in C11
echo ========================================================
echo.

:: 1. Check for Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    where py >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Python was not found in PATH!
        echo Please ensure Python 3 is installed.
        pause
        exit /b 1
    )
    set PY_CMD=py
) else (
    set PY_CMD=python
)

:: 2. Launch the Tkinter GUI (app.py handles C verification & compilation automatically)
echo [*] Launching Python Tkinter Cyberpunk GUI...
%PY_CMD% gui\app.py

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Application closed with exit code %ERRORLEVEL%.
    pause
)
