from fastapi import FastAPI
from .scanner import get_security_headers

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/scan-url/")
def scan_url(url: str):
    headers = get_security_headers(url)
    return {"url": url, "security_headers": headers}