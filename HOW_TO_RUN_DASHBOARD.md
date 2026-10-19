# Trojan Defense Dashboard - Windows run guide

## Recommended
1. Open this folder in VS Code.
2. Make sure the required packages are installed:
   `python -m pip install -r requirements.txt`
3. Double-click `START_DASHBOARD.bat`.
4. Wait until it says `Backend is ready.`
5. The browser opens at `http://127.0.0.1:8080/`.

## Manual
```powershell
python -m pip install -r requirements.txt
python -m trojan_defense.main server --host 127.0.0.1 --port 8080
```
Then open `http://127.0.0.1:8080/`.

## If buttons say "Failed to fetch"
Keep the Python backend window open. Run `CHECK_DASHBOARD.bat` to verify all API endpoints.
If you already had an older Trojan Defense server on port 8080, close it before starting this version. `START_DASHBOARD.bat` automatically stops the old listener on port 8080.

## Dashboard demo
- Deception -> Test detection: creates a fresh event and alert every click.
- Events -> Refresh events: reloads events only.
- Alerts -> Refresh (top-right): reloads alerts and health.
- Incidents -> Create incident: opens a form and creates a persistent incident.
- Response -> Request response: opens a form and creates a persistent requested action.
- Response -> Authorize -> Execute -> Rollback: exercises the controlled response lifecycle.

All dashboard API calls use the same origin as the backend, so no separate web server or CORS configuration is required.
