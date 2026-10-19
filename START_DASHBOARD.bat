@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

echo ==============================================
echo   Trojan Defense - Security Operations Center
echo ==============================================
echo.

echo Checking port 8080...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080" ^| findstr "LISTENING"') do (
  echo Stopping old dashboard process %%a...
  taskkill /PID %%a /F >nul 2>&1
)

echo Starting backend...
start "Trojan Defense Backend" /min cmd /c "cd /d "%~dp0" && python -m trojan_defense.main server --host 127.0.0.1 --port 8080"

echo Waiting for backend...
for /l %%i in (1,1,20) do (
  powershell -NoProfile -Command "try { $r=Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/api/health -TimeoutSec 1; if($r.StatusCode -eq 200){exit 0}else{exit 1} } catch { exit 1 }" >nul 2>&1
  if not errorlevel 1 goto READY
  timeout /t 1 /nobreak >nul
)

echo.
echo ERROR: Backend did not start on port 8080.
echo Run this command manually to see the error:
echo python -m trojan_defense.main server --host 127.0.0.1 --port 8080
pause
exit /b 1

:READY
echo Backend is ready.
start "Trojan Defense Dashboard" http://127.0.0.1:8080/
echo.
echo Dashboard: http://127.0.0.1:8080/
echo Keep this window open while using the dashboard.
echo Close the backend window to stop the server.
pause
