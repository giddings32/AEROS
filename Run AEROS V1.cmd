@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo AEROS V1
echo ============================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo [!] Python was not found in PATH.
  echo     Install Python 3, then run this launcher again.
  pause
  exit /b 1
)

python -c "from importlib.metadata import version; import docx, pypdf; assert tuple(map(int, version('python-docx').split('.')[:3])) >= (1,2,0); assert tuple(map(int, version('pypdf').split('.')[:3])) >= (6,14,2)" >nul 2>&1
if errorlevel 1 (
  echo [*] Installing or updating required Python packages...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo [!] Failed to install requirements.
    pause
    exit /b 1
  )
)

echo [*] Starting AEROS V1 at http://127.0.0.1:8765/index.html
echo [*] Leave this window open while using the application.
python server.py

echo.
echo [*] AEROS V1 stopped.
pause
