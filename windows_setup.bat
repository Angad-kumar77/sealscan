@echo off
REM One-click setup for Windows: creates a virtual environment and installs sealscan.
cd /d "%~dp0"
python -m venv .venv
if errorlevel 1 (
  echo Could not create the virtual environment. Is Python installed and on PATH?
  pause
  exit /b 1
)
call .venv\Scripts\activate.bat
pip install -e .
if errorlevel 1 (
  echo Install failed. See the error above.
  pause
  exit /b 1
)
echo.
sealscan --version
echo.
echo Done. Open a terminal in this folder and run:
echo     .venv\Scripts\activate.bat
echo     sealscan .
echo.
pause
