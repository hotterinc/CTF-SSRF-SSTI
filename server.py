import csv
import hashlib
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Template

app = FastAPI(title="CTF Multi-App")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- SSRF target server ---
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 9000
SSRF_FLAG = "CTF{ssrf_0nly_l0calh0st_9000_7c2b3f}"
SSTI_FLAG = "CTF{ssti_templ4te_escape_is_0pt1c4l_54d91b}"

FLAG_HASHES = {
    "ssrf": hashlib.sha256(SSRF_FLAG.encode()).hexdigest(),
    "ssti": hashlib.sha256(SSTI_FLAG.encode()).hexdigest(),
}


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/secret":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(SSRF_FLAG.encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"admin, now go to secret")


def start_target_server() -> HTTPServer:
    server = HTTPServer((TARGET_HOST, TARGET_PORT), TargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@app.on_event("startup")
def startup() -> None:
    # Run the SSRF target server in-process on localhost:9000.
    app.state.target_server = start_target_server()


@app.on_event("shutdown")
def shutdown() -> None:
    server = getattr(app.state, "target_server", None)
    if server:
        server.shutdown()
        server.server_close()


# --- Common pages ---
@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})


@app.get("/flags", response_class=HTMLResponse)
async def flags_page(request: Request, result: str | None = None):
    return templates.TemplateResponse(
        "flags.html",
        {"request": request, "result": result},
    )


@app.post("/flags", response_class=HTMLResponse)
async def flags_check(request: Request, flag: str = Form(...)):
    submitted_hash = hashlib.sha256(flag.strip().encode()).hexdigest()
    matched = next((name for name, digest in FLAG_HASHES.items() if digest == submitted_hash), None)
    if matched:
        result = f"Valid flag for: {matched.upper()}"
    else:
        result = "Invalid flag"
    return templates.TemplateResponse(
        "flags.html",
        {"request": request, "result": result},
    )


# --- SSRF pages ---
@app.get("/ssrf", response_class=HTMLResponse)
async def ssrf_home(request: Request):
    return templates.TemplateResponse("ssrf/index.html", {"request": request})


@app.post("/ssrf/fetch", response_class=HTMLResponse)
async def fetch_url(request: Request, url: str = Form(...)):
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5)
            content = response.text
            return templates.TemplateResponse(
                "ssrf/result.html",
                {"request": request, "url": url, "content": content},
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=400, detail=f"Error fetching URL: {exc}")


# --- SSTI pages ---
DB_FILE = "users.csv"
users = {}
sessions = {}


def load_users() -> None:
    if not os.path.exists(DB_FILE):
        return

    with open(DB_FILE, mode="r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            try:
                comments_list = json.loads(row["comments"])
            except json.JSONDecodeError:
                comments_list = []

            users[row["username"]] = {
                "password_hash": row["password_hash"],
                "comments": comments_list,
            }


def save_users() -> None:
    with open(DB_FILE, mode="w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["username", "password_hash", "comments"])
        writer.writeheader()
        for username, data in users.items():
            writer.writerow(
                {
                    "username": username,
                    "password_hash": data["password_hash"],
                    "comments": json.dumps(data["comments"]),
                }
            )


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


load_users()


@app.get("/ssti", response_class=HTMLResponse)
async def ssti_home(request: Request):
    session_id = request.cookies.get("session_id")
    if username := sessions.get(session_id):
        return RedirectResponse(f"/ssti/user/{username}", status_code=303)
    return RedirectResponse("/ssti/login", status_code=303)


@app.get("/ssti/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("ssti/register.html", {"request": request})


@app.post("/ssti/register")
async def register(response: Response, username: str = Form(...), password: str = Form(...)):
    if username in users:
        return HTMLResponse("Username already exists", status_code=400)

    users[username] = {"password_hash": hash_password(password), "comments": []}
    save_users()

    session_id = secrets.token_hex(16)
    sessions[session_id] = username

    response = RedirectResponse("/ssti/login", status_code=303)
    response.set_cookie("session_id", session_id)
    return response


@app.get("/ssti/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("ssti/login.html", {"request": request})


@app.post("/ssti/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or user["password_hash"] != hash_password(password):
        return HTMLResponse("Invalid username or password", status_code=401)

    session_id = secrets.token_hex(16)
    sessions[session_id] = username

    response = RedirectResponse(f"/ssti/user/{username}", status_code=303)
    response.set_cookie("session_id", session_id)
    response.set_cookie("login", username)
    response.set_cookie("password", password)
    return response


@app.get("/ssti/user/{profile_username}", response_class=HTMLResponse)
async def profile_page(request: Request, profile_username: str):
    session_id = request.cookies.get("session_id")
    current_user = sessions.get(session_id)

    if not current_user:
        return RedirectResponse("/ssti/login", status_code=303)

    if profile_username not in users:
        return HTMLResponse("User not found", status_code=404)

    can_comment = profile_username != current_user

    raw_comments = users[profile_username]["comments"]
    processed_comments = []

    for comment in raw_comments:
        try:
            tmpl = Template(comment)
            rendered = tmpl.render(
                current_user=current_user,
                users=users,
                secret_key=SSTI_FLAG,
            )
            processed_comments.append(rendered)
        except Exception:
            processed_comments.append(comment)

    return templates.TemplateResponse(
        "ssti/profile.html",
        {
            "request": request,
            "current_user": current_user,
            "profile_username": profile_username,
            "comments": processed_comments,
            "user_list": list(users.keys()),
            "can_comment": can_comment,
        },
    )


@app.post("/ssti/comment/{profile_username}")
async def add_comment(request: Request, profile_username: str):
    session_id = request.cookies.get("session_id")
    current_user = sessions.get(session_id)

    if not current_user or profile_username not in users or profile_username == current_user:
        return {"status": "error", "message": "Cannot comment"}

    data = await request.json()
    text = data.get("text", "")

    if text:
        users[profile_username]["comments"].append(text)
        save_users()

    return {"status": "ok"}


@app.post("/ssti/logout")
async def logout(response: Response, request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        del sessions[session_id]
    response = RedirectResponse("/ssti/login", status_code=303)
    response.delete_cookie("session_id")
    return response
