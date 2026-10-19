@echo off
setlocal
cd /d "%~dp0"
echo Trojan Defense dashboard self-check
echo.
powershell -NoProfile -Command "$b='http://127.0.0.1:8080'; foreach($p in '/api/health','/api/events?limit=1','/api/alerts?limit=1','/api/incidents?limit=1','/api/responses?limit=1'){try{$r=Invoke-RestMethod ($b+$p) -TimeoutSec 3; Write-Host ('OK  '+$p) -ForegroundColor Green}catch{Write-Host ('FAIL '+$p+'  '+$_.Exception.Message) -ForegroundColor Red}}"
echo.
pause
