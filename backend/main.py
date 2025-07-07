
from fastapi import FastAPI
from scanner import scan_url, scan_repo

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the SecureCode Scanner API"}

@app.post("/scan/url")
def api_scan_url(url: str):
    return scan_url(url)

@app.post("/scan/repo")
def api_scan_repo(repo_url: str):
    return scan_repo(repo_url)
