@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
    where python >nul 2>&1
    if errorlevel 1 (
        echo Nainstaluj Python 3.10 nebo novejsi z python.org.
        pause
        exit /b 1
    )
    python -X utf8 app.py
) else (
    py -3 -X utf8 app.py
)
if errorlevel 1 pause
