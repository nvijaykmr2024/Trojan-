@echo off
setlocal
cd /d "%~dp0"
echo Installing/updating required Python packages...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Dependency installation failed. Check your Python/Anaconda environment and Internet connection.
  pause
  exit /b 1
)
echo.
echo Starting Trojan Defense dashboard...
start "Trojan Defense Dashboard" http://127.0.0.1:8080/
python -m trojan_defense.main server --port 8080
pause
