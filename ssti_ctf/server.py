import csv
import json
import os
from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
import hashlib
import secrets
from jinja2 import Template  # Для SSTI

app = FastAPI(title="SSTI App with CSV Storage")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Файл базы данных
DB_FILE = "users.csv"

# In-memory caches
users = {}
sessions = {}


def load_users():
    """Загружает пользователей из CSV файла при старте."""
    if not os.path.exists(DB_FILE):
        return

    with open(DB_FILE, mode='r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                # Комментарии храним как JSON строку внутри CSV поля,
                # чтобы не ломать структуру из-за запятых в тексте.
                comments_list = json.loads(row['comments'])
            except json.JSONDecodeError:
                comments_list = []

            users[row['username']] = {
                "password_hash": row['password_hash'],
                "comments": comments_list
            }
    print(f"[*] Загружено {len(users)} пользователей из {DB_FILE}")


def save_users():
    """Сохраняет текущее состояние пользователей в CSV."""
    with open(DB_FILE, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["username", "password_hash", "comments"])
        writer.writeheader()
        for username, data in users.items():
            writer.writerow({
                "username": username,
                "password_hash": data["password_hash"],
                # Сериализуем список в JSON, чтобы экранировать кавычки и переносы строк
                "comments": json.dumps(data["comments"])
            })


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ЗАГРУЗКА ПРИ СТАРТЕ
load_users()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session_id = request.cookies.get("session_id")
    if username := sessions.get(session_id):
        return RedirectResponse(f"/user/{username}", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register(response: Response, username: str = Form(...), password: str = Form(...)):
    if username in users:
        return HTMLResponse("Username already exists", status_code=400)

    users[username] = {"password_hash": hash_password(password), "comments": []}

    # СОХРАНЯЕМ В CSV
    save_users()

    session_id = secrets.token_hex(16)
    sessions[session_id] = username

    response = RedirectResponse("/login", status_code=303)
    response.set_cookie("session_id", session_id)
    return response


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or user["password_hash"] != hash_password(password):
        return HTMLResponse("Invalid username or password", status_code=401)

    session_id = secrets.token_hex(16)
    sessions[session_id] = username

    response = RedirectResponse(f"/user/{username}", status_code=303)
    response.set_cookie("session_id", session_id)
    response.set_cookie("login", username)
    response.set_cookie("password", password)
    return response


@app.get("/user/{profile_username}", response_class=HTMLResponse)
async def profile_page(request: Request, profile_username: str):
    session_id = request.cookies.get("session_id")
    current_user = sessions.get(session_id)

    if not current_user:
        return RedirectResponse("/login", status_code=303)

    if profile_username not in users:
        return HTMLResponse("User not found", status_code=404)

    can_comment = profile_username != current_user

    # --- SSTI LOGIC ---
    raw_comments = users[profile_username]["comments"]
    processed_comments = []

    for comment in raw_comments:
        try:
            # Рендерим шаблон (SSTI)
            tmpl = Template(comment)
            rendered = tmpl.render(
                current_user=current_user,
                users=users,
                secret_key="SECRET_FLAG_CSV_EDITION"
            )
            processed_comments.append(rendered)
        except Exception:
            processed_comments.append(comment)

    return templates.TemplateResponse("profile.html", {
        "request": request,
        "current_user": current_user,
        "profile_username": profile_username,
        "comments": processed_comments,
        "user_list": list(users.keys()),
        "can_comment": can_comment
    })


@app.post("/comment/{profile_username}")
async def add_comment(request: Request, profile_username: str):
    session_id = request.cookies.get("session_id")
    current_user = sessions.get(session_id)

    if not current_user or profile_username not in users or profile_username == current_user:
        return {"status": "error", "message": "Cannot comment"}

    data = await request.json()
    text = data.get("text", "")

    if text:
        users[profile_username]["comments"].append(text)
        # СОХРАНЯЕМ В CSV ПОСЛЕ КОММЕНТАРИЯ
        save_users()

    return {"status": "ok"}


@app.post("/logout")
async def logout(response: Response, request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        del sessions[session_id]
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("session_id")
    return response


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)