# Troubleshooting

### `127.0.0.1:8080` refused to connect
The server is not running. Start it with:

```powershell
python -m trojan_defense.main server --port 8080
```

### `No module named watchdog`
Install the dependencies in the same Python environment used by VS Code:

```powershell
python -m pip install -r requirements.txt
```

### Response error: `ISOLATE_ENDPOINT is not a valid ResponseActionType`
This version accepts old UI aliases and normalizes them to the canonical response types. Refresh the browser with `Ctrl+F5` after starting the updated server.

### Test Detection says an event already exists
The demo endpoint now creates a server-side UUID for every test, so repeated clicks use new event IDs. If an old browser script is cached, press `Ctrl+F5`.

### Port 8080 is already in use
Use another port:

```powershell
python -m trojan_defense.main server --port 8081
```

Then open `http://127.0.0.1:8081/`.
