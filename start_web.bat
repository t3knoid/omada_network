@echo off
REM Start the Omada Network Documentation Generator web UI.
REM Usage: start_web.bat [--host 0.0.0.0] [--port 5000]

cd /d "%~dp0"

set VENV_DIR=.venv

if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo Creating virtual environment in %VENV_DIR%...
    python -m venv "%VENV_DIR%"
)

call "%VENV_DIR%\Scripts\activate.bat"

echo Installing dependencies...
pip install -q -r requirements.txt

REM Determine host and port from arguments (defaults match cli.py serve)
set HOST=127.0.0.1
set PORT=5000
set ARGS=%*

REM Parse --host and --port from arguments
set REMAINING=
:parse
if "%~1"=="" goto endparse
if /i "%~1"=="--host" (
    set HOST=%~2
    shift
    shift
    goto parse
)
if /i "%~1"=="--port" (
    set PORT=%~2
    shift
    shift
    goto parse
)
set REMAINING=%REMAINING% %1
shift
goto parse
:endparse

set URL=http://%HOST%:%PORT%
echo.
echo ==^> Omada Network Documentation Generator
echo ==^> Web UI will be available at: %URL%
echo.

REM Open the browser after a short delay so the server has time to start
start "" cmd /c "timeout /t 2 /nobreak >nul & start %URL%"

python cli.py serve --host %HOST% --port %PORT% %REMAINING%
