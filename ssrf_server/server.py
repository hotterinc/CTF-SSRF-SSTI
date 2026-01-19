from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import httpx
import uvicorn

app = FastAPI(title="SSRF Vulnerable App")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the main page with a form to submit a URL."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/fetch", response_class=HTMLResponse)
async def fetch_url(request: Request, url: str = Form(...)):
    """Fetch the provided URL and return its content (vulnerable to SSRF)."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5)
            content = response.text
            return templates.TemplateResponse("result.html", {
                "request": request,
                "url": url,
                "content": content
            })
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Error fetching URL: {str(e)}")

if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)