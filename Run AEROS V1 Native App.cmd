@echo off
setlocal
cd /d "%~dp0"

if exist "AEROS V1.exe" (
  start "" "%~dp0AEROS V1.exe"
  exit /b
)

echo AEROS V1.exe was not found.
echo Running desktop_app.py directly instead.
echo.
python "%~dp0desktop_app.py"
