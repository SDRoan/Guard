# Guard — Link Risk Check

FastAPI app that scores a URL with an ML model, explains why, and safely fetches page content (HTTP/HTTPS) to summarize **what the link is** and **what's inside now**.

## Quick start
```bash
python -m venv .venv311
source .venv311/bin/activate        # Windows: .venv311\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
