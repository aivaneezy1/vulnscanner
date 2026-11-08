# Self-Hosted, Browser-Based Vulnerability Scanner

A Docker-packaged, authentication-aware web vulnerability scanner with a browser UI
(no CLI). Supports unauthenticated scans and two authenticated-scan modes:
Playwright-driven form login, and manual session import (cookie header / JSON
cookie export / bearer token).

> ⚠️ **Only scan systems you own or have explicit written permission to test.**
> Unauthorized scanning of third-party systems may be illegal in your jurisdiction.

---

## What it checks

- **SQL Injection** — injects `'`, `"`, `')--`, and boolean-based payloads into every
  discovered query parameter, looking for database error signatures.
- **Reflected XSS** — injects `<script>alert(1)</script>` and checks for unescaped
  reflection in the response body.
- **Sensitive file / directory exposure** — probes `.env`, `.git/config`,
  `backup.zip`, `/admin`, `/phpinfo.php`, `/server-status`.
- **Security headers** — flags missing CSP, X-Frame-Options, HSTS, and
  X-Content-Type-Options.
- **Authentication bypass / broken access control** (authenticated scans only) —
  re-requests every scanned URL *without* the session; if the page is still fully
  accessible, it's flagged as a bypass.

---

## Project layout

```
vulnscan/
├── app/
│   ├── main.py              FastAPI app + routes
│   ├── scanner.py            crawler + vulnerability checks
│   ├── auth.py                Playwright login + manual session parsing
│   ├── templates/
│   │   └── index.html        the web UI
│   └── static/
│       ├── style.css
│       └── app.js
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── run.sh                    helper: auto-picks a free host port
├── .dockerignore
└── README.md
```

---

## Running it

Everything happens in the browser after you start the container. There is no
CLI interaction with the scanner itself.

### Method 1 — plain docker compose (tries port 8000)

```bash
git clone <this-repo-url>
cd vulnscan
docker compose up --build
```

Then open: **http://localhost:8000**

### Method 2 — pick a specific host port

If 8000 is already taken on your machine, override it:

```bash
HOST_PORT=9000 docker compose up --build
```

Then open: **http://localhost:9000**

### Method 3 (recommended) — auto-pick a free port

```bash
./run.sh
```

`run.sh` checks whether port 8000 (or `HOST_PORT` if you've set it) is free on
your host. If it's taken, it scans upward through 8000–8100 for the next free
port, exports `HOST_PORT` accordingly, prints a banner with the URL to open,
and then runs `docker compose up --build` for you.

Example output:

```
============================================================
👉 Open your browser at http://localhost:8002
============================================================
```

The app inside the container always listens on `$PORT` (default `8000`) on
`0.0.0.0`; `docker-compose.yml` maps `${HOST_PORT:-8000}:${PORT:-8000}` so the
two are independent — you can change the host-side port without touching
anything inside the container. The frontend only ever calls relative URLs
(e.g. `fetch('/scan/start')`), so it works correctly no matter which host port
you land on.

---

## Using the UI

1. **Choose a scan mode:**
   - *Unauthenticated scan* — plain HTTP requests, no session.
   - *Authenticated scan* — expands a login panel:
     - **Form Login** (default): give it a Login URL, username, and password.
       Optionally override the CSS selectors for the username/password fields
       and the submit button for tricky login forms, and add extra fields
       (e.g. CSRF tokens) as `name=value` lines. Click **Test Login** to
       verify credentials and selectors before running a full scan.
     - **Manual Session Import**: paste a raw `Cookie:` header, a JSON cookie
       export (as produced by most browser devtools "export cookies"
       extensions), or an `Authorization: Bearer <token>` line.
2. **List the URLs to scan** — paste the specific protected pages you want
   tested, one per line. Optionally check **"Also crawl links from the target
   URL"** to let the scanner discover same-origin links automatically (capped
   at 25 pages).
3. Click **Start Scan**. The status panel polls `/scan/{id}/status` once per
   second and shows:
   - the current stage (`Logging in` → `Crawling` → `Scanning URL 3/12` → `Done`),
   - a progress bar,
   - any errors (e.g. a failed login, or a session that expired mid-scan —
     the scanner stops immediately rather than continuing with stale/invalid
     auth),
   - a live-updating findings table: Severity | Vulnerability Type | URL |
     Parameter | Payload | Evidence, with color-coded severity badges.

---

## API (used internally by the UI, documented for completeness)

| Method | Path                  | Description                                   |
|--------|-----------------------|------------------------------------------------|
| GET    | `/`                   | Serves the web UI                              |
| POST   | `/login/test`         | Tries a form login, returns `{ok, message}`    |
| POST   | `/scan/start`         | Starts a background scan, returns `{scan_id}`  |
| GET    | `/scan/{id}/status`   | Returns `{stage, progress, results[], errors[], finished}` |

---

## Notes & limitations

- Scan state is kept in memory, keyed by `scan_id` — it resets if the
  container restarts.
- The crawler is intentionally capped at 25 pages per scan to keep scans fast
  and avoid runaway loops.
- `verify=False` is used for HTTPS requests so the scanner can test targets
  with self-signed certificates (typical in staging/lab environments). Don't
  point this at production systems you don't control.
- This tool is meant for authorized security testing and educational use — it
  is not a replacement for a full commercial DAST tool, but demonstrates the
  same authenticated-scanning architecture.
