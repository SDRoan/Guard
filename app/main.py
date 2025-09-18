from __future__ import annotations
from fastapi import FastAPI
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from app.analyzer import analyze_url

app = FastAPI(title="Guard", version="0.1.0")

# serve the simple frontend we'll add next
app.mount("/static", StaticFiles(directory="static"), name="static")

class AnalyzeBody(BaseModel):
    artifact_type: str  # "url" for MVP
    value: str

@app.get("/", response_class=HTMLResponse)
def home():
    return FileResponse("static/index.html")

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/analyze")
async def analyze(body: AnalyzeBody):
    if body.artifact_type != "url":
        return JSONResponse(status_code=400, content={"error": "Only artifact_type='url' supported in MVP."})
    try:
        return analyze_url(body.value)
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
