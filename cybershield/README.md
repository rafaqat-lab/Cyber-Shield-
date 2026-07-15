# CyberShield AI — Payload & Network Threat Scanner

A simple full-stack demo app: a Flask backend that inspects uploaded files and
target URLs using heuristic rules, and an HTML/JS frontend to interact with it.

> ⚠️ **Note:** This is an educational / demo heuristic scanner. It does **not**
> perform real antivirus scanning or genuine intrusion detection — the checks
> (magic-byte header check, double-extension check, keyword matching) are
> simplified illustrations of how such systems work, not production security.

## Project Structure

```
cybershield/
├── back.py           # Flask backend (API + serves the frontend)
├── front.html        # Frontend UI (fetches from the backend)
├── requirements.txt  # Python dependencies
├── blacklist.json    # Persisted list of blocked IPs / strings
├── entries.json      # Persisted log of every scan performed
├── uploads/          # Temp storage used while a file is being scanned
└── README.md
```

## Features

- **File Integrity Scan** (`POST /api/upload`)
  - Checks real file signature ("magic bytes") vs. the claimed extension
  - Flags disguised executables (e.g. `photo.jpg.exe`)
  - Flags tiny suspicious script/binary files
  - Rejects files over 25MB
- **Network URL Inspector** (`POST /api/scan-url`)
  - Blocks anything matching the persistent IP/keyword blacklist
  - Detects attack-pattern keywords (`nmap`, `ddos`, `reverse shell`, …) and
    auto-adds the offending string to the blacklist
  - Detects common phishing keywords (`login`, `verify`, `wp-admin`, …)
  - Flags plain `http://` (unencrypted) links
- Every scan (file or URL) is logged with a timestamp + UUID into `entries.json`
- The frontend is served directly by the backend, so one process = one URL

## Setup

**Requirements:** Python 3.8+

```bash
# 1. (Recommended) create a virtual environment
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the server
python back.py
```

You should see:

```
🚀 CyberShield Network-IDPS Hardened Engine online on Port 8000
 * Running on http://127.0.0.1:8000
```

## Usage

Open your browser at:

```
http://127.0.0.1:8000/
```

The backend now serves `front.html` directly at that address — no need to
open the HTML file separately. Use the two forms on the page:

- **File Integrity Scan** — pick any file and click *Execute Threat Scan*
- **Network URL Inspector** — type a URL/string and click *Inspect Endpoint*

Results (verdict, hash, probability, logs) appear in the panel below.

## API Reference

### `POST /api/upload`
`multipart/form-data` with a field named `cyberFile`.

```json
{
  "success": true,
  "fileDetails": {
    "originalName": "photo.jpg",
    "size": "482.10 KB",
    "hash": "…sha256…",
    "fakeProbability": "0%",
    "verdict": "GENUINE / SAFE",
    "statusColor": "#10b981",
    "logs": ["..."]
  }
}
```

### `POST /api/scan-url`
JSON body: `{ "targetUrl": "http://example.com/login" }`

```json
{
  "success": true,
  "details": {
    "target": "http://example.com/login",
    "hash": "NET::…",
    "fakeProbability": "85%",
    "verdict": "PHISHING DOMAIN INTERDICTED",
    "statusColor": "#ef4444",
    "logs": ["..."]
  }
}
```

## Troubleshooting

- **"Not Found" at `http://127.0.0.1:8000/`** — make sure you're running the
  updated `back.py` from this project (it includes a `/` route). Older
  versions only had `/api/...` routes and had no root page.
- **Bridge / connection errors in the browser** — the Flask server isn't
  running, or something else is using port 8000. Check the terminal running
  `back.py` for errors, and confirm no other process is bound to that port.
- **CORS errors** — shouldn't happen since `flask-cors` is enabled for all
  origins, but if you changed the port, update `PORT` in `back.py` too.
