@echo off
REM ##########################################################################
REM Canary-Net Deployment Script for Windows
REM Automated setup with Python 3.11+ validation
REM ##########################################################################

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo ========================================
echo   Canary-Net Setup Script (Windows)
echo ========================================
echo.

REM Check Python version
echo [*] Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11+ and try again.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [+] Python %PYTHON_VERSION% found.
echo.

REM Extract major and minor version
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set PYTHON_MAJOR=%%a
    set PYTHON_MINOR=%%b
)

if %PYTHON_MAJOR% LSS 3 (
    echo [ERROR] Python 3.11 or higher is required.
    echo Found: Python %PYTHON_VERSION%
    pause
    exit /b 1
)

if %PYTHON_MAJOR% EQU 3 if %PYTHON_MINOR% LSS 11 (
    echo [ERROR] Python 3.11 or higher is required.
    echo Found: Python %PYTHON_VERSION%
    pause
    exit /b 1
)

echo.

REM Create virtual environment
echo [*] Creating virtual environment...
if exist venv (
    echo [!] venv already exists. Skipping.
) else (
    python -m venv venv
    echo [+] Virtual environment created.
)
echo.

REM Activate virtual environment
echo [*] Activating virtual environment...
call venv\Scripts\activate.bat
echo [+] Virtual environment activated.
echo.

REM Install dependencies
echo [*] Installing dependencies from requirements.txt...
pip install -q -r requirements.txt
echo [+] Dependencies installed successfully.
echo.

REM Generate encryption key
echo [*] Generating encryption key...
python main.py --generate-key >nul 2>&1
if exist canary.key (
    echo [+] Encryption key generated.
) else (
    echo [ERROR] Failed to generate encryption key.
    pause
    exit /b 1
)
echo.

REM Setup complete
echo ========================================
echo [+] Setup complete!
echo ========================================
echo.
echo Next steps:
echo   1. Activate the virtual environment:
echo      venv\Scripts\activate.bat
echo.
echo   2. Run the application:
echo      python main.py
echo.
echo   3. Run tests:
echo      pytest tests/ -v
echo.
echo   4. To deactivate venv later:
echo      deactivate
echo.
pause
