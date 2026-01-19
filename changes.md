# Changes

## Combined app structure
- Created a single FastAPI app in `server.py` that serves both challenges.
- Added a landing page at `/` that links to SSRF and SSTI sections.
- Namespaced SSRF endpoints under `/ssrf` to avoid collisions with SSTI routes.
- Namespaced SSTI endpoints under `/ssti` for the same reason.
- Added clean startup/shutdown hooks to manage the SSRF target service lifecycle.

## SSRF behavior
- Moved the SSRF UI to `/ssrf` and the fetch handler to `/ssrf/fetch`.
- Embedded the SSRF target server (HTTP on `127.0.0.1:9000`) inside the same process.
- Kept the original response text and behavior from the old `target_server.py`.

## SSTI behavior
- Moved auth and profile routes under `/ssti/*` to keep them grouped and conflict-free.
- Updated templates to point to the new `/ssti` endpoints (login/register/profile, comments, logout).
- Preserved the SSTI rendering logic with `jinja2.Template` and the existing secret key string.

## Templates and static assets
- Split SSRF templates into `templates/ssrf/index.html` and `templates/ssrf/result.html`.
- Split SSTI templates into `templates/ssti/login.html`, `templates/ssti/register.html`, and `templates/ssti/profile.html`.
- Added a new landing page template at `templates/home.html`.
- Consolidated styles into a single `static/styles.css` used by all pages.

## Dependencies
- Created root `requirements.txt` that includes both apps' dependencies.
- Added `httpx` for SSRF fetch logic (not in the original SSTI requirements).

## Docker
- Added a root `Dockerfile` to build and run the combined app.
- Runs as a non-root `ctf` user and keeps the SSTI flag at `/home/flag.txt` with read-only perms.
- Uses `uvicorn` to serve `server:app` on port 8000.

## Documentation
- Added `README.md` with routes, local run steps, and Docker usage.
