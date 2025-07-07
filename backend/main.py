from fastapi import FastAPI
from scanner import get_security_headers, scan_github_repo, generate_ai_report, calculate_risk_score, generate_pdf_report, run_nuclei_scan

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/scan-url/")
def scan_url(url: str):
    headers = get_security_headers(url)
    return {"url": url, "security_headers": headers}

@app.get("/scan-url-full/")
def scan_url_full(url: str):
    headers = get_security_headers(url)
    nuclei_results = run_nuclei_scan(url)
    
    scan_results = {
        "url": url,
        "security_headers": headers,
        "nuclei_scan": nuclei_results
    }
    ai_summary = generate_ai_report(scan_results)
    risk_score = calculate_risk_score(scan_results)
    
    # For URL scans, we'll use the domain as the report name
    repo_name = url.replace("http://", "").replace("https://", "").split("/")[0]
    pdf_report_path = generate_pdf_report(scan_results, ai_summary, risk_score, repo_name)

    return {
        "url": url,
        "scan_results": scan_results,
        "ai_summary": ai_summary,
        "risk_score": risk_score,
        "pdf_report_path": pdf_report_path
    }

@app.get("/scan-github/")
def scan_github(repo_url: str):
    scan_results = scan_github_repo(repo_url)
    ai_summary = generate_ai_report(scan_results)
    risk_score = calculate_risk_score(scan_results)
    repo_name = repo_url.split('/')[-1].replace(".git", "")
    pdf_report_path = generate_pdf_report(scan_results, ai_summary, risk_score, repo_name)
    return {
        "repo_url": repo_url,
        "scan_results": scan_results,
        "ai_summary": ai_summary,
        "risk_score": risk_score,
        "pdf_report_path": pdf_report_path
    }