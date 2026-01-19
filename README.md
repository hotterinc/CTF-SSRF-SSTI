# CTF Multi-App (SSRF + SSTI)

This repo combines two CTF challenges into a single FastAPI app:
- **SSRF**: URL fetcher with an internal target service on `127.0.0.1:9000`.
- **SSTI**: simple profile/comments app with template injection.

## Routes
- `/` - landing page
- `/ssrf` - SSRF challenge
- `/ssti` - SSTI challenge
- `/flags` - flag checker

The SSRF target service is started automatically inside the app and listens on `127.0.0.1:9000`.

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn server:app --reload
```

Open: http://127.0.0.1:8000

## Docker
```bash
docker build -t ctf .
docker run -p 8000:8000 ctf
```

## Notes
- The SSTI flag is stored at `/home/flag.txt` in the container (read-only).
- User data is persisted to `users.csv` in the working directory.
