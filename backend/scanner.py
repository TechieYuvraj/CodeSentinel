
import requests
import git
import os
import subprocess
import shutil
import json
from openai import OpenAI
from weasyprint import HTML
from dotenv import load_dotenv

load_dotenv()

# Initialize OpenAI client (replace with your API key or environment variable setup)
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

def get_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = {
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
        }
        return security_headers
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def run_nuclei_scan(url):
    try:
        print(f"Running Nuclei scan on {url}...")
        nuclei_output = subprocess.run(
            ["nuclei", "-u", url, "-json"],
            capture_output=True,
            text=True,
            check=True
        )
        print("Nuclei scan complete.")
        # Nuclei outputs one JSON object per line, so we need to parse each line
        results = [json.loads(line) for line in nuclei_output.stdout.strip().split('\n') if line.strip()]
        return results
    except FileNotFoundError:
        return {"error": "Nuclei not found. Please install Nuclei and ensure it's in your PATH."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Nuclei error: {e.stderr}"}
    except json.JSONDecodeError as e:
        return {"error": f"Error parsing Nuclei JSON output: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred during Nuclei scan: {e}"}

def run_retirejs_scan(directory):
    try:
        print(f"Running Retire.js scan on {directory}...")
        # Ensure npm is available and install retire if not already
        subprocess.run(["npm", "install", "-g", "retire"], capture_output=True, check=True)
        
        retirejs_output = subprocess.run(
            ["retire", "--path", directory, "--outputformat", "json", "--outputpath", "retirejs_output.json"],
            capture_output=True,
            text=True,
            check=True
        )
        print("Retire.js scan complete.")
        with open("retirejs_output.json", 'r') as f:
            results = json.load(f)
        os.remove("retirejs_output.json") # Clean up the output file
        return results
    except FileNotFoundError:
        return {"error": "npm or Retire.js not found. Please install Node.js/npm and Retire.js globally."}
    except subprocess.CalledProcessError as e:
        return {"error": f"Retire.js error: {e.stderr}"}
    except json.JSONDecodeError as e:
        return {"error": f"Error parsing Retire.js JSON output: {e}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred during Retire.js scan: {e}"}

def scan_github_repo(repo_url):
    repo_name = repo_url.split('/')[-1].replace(".git", "")
    temp_dir = f"temp_repo_{repo_name}"
    results = {}
    try:
        print(f"Cloning {repo_url} into {temp_dir}...")
        git.Repo.clone_from(repo_url, temp_dir)
        print("Cloning complete. Running Bandit scan...")

        # Run Bandit
        bandit_output = subprocess.run(
            ["bandit", "-r", temp_dir, "-f", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        results["bandit_scan"] = json.loads(bandit_output.stdout)
        print("Bandit scan complete.")

        # Run Retire.js
        retirejs_results = run_retirejs_scan(temp_dir)
        results["retirejs_scan"] = retirejs_results

    except git.exc.GitCommandError as e:
        results["error"] = f"Git error: {e}"
    except subprocess.CalledProcessError as e:
        results["error"] = f"Bandit error: {e.stderr}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred: {e}"
    finally:
        if os.path.exists(temp_dir):
            print(f"Cleaning up temporary directory {temp_dir}...")
            shutil.rmtree(temp_dir)
            print("Cleanup complete.")
    return results

def generate_ai_report(scan_results):
    bandit_findings = scan_results.get("bandit_scan", {}).get("results", [])
    nuclei_findings = scan_results.get("nuclei_scan", [])
    retirejs_findings = scan_results.get("retirejs_scan", {}).get("data", [])

    if not bandit_findings and not nuclei_findings and not retirejs_findings:
        return "No security vulnerabilities found."

    prompt = "Summarize the following security vulnerabilities and suggest remediation steps:\n\n"
    for finding in bandit_findings:
        prompt += f"- Issue: {finding['issue_text']} at {finding['filename']}:{finding['lineno']}. Severity: {finding['issue_severity']}. Confidence: {finding['issue_confidence']}.\n"
    for finding in nuclei_findings:
        prompt += f"- Nuclei Issue: {finding.get('info', {}).get('name', 'N/A')} - {finding.get('info', {}).get('description', 'N/A')} at {finding.get('host', 'N/A')}. Severity: {finding.get('info', {}).get('severity', 'N/A')}.\n"
    for finding in retirejs_findings:
        for vulnerability in finding.get("vulnerabilities", []):
            prompt += f"- Retire.js Issue: {vulnerability.get("identifiers", {}).get("CVE", "N/A")} - {vulnerability.get("info", "N/A")} in {finding.get("component", "N/A")}:{finding.get("version", "N/A")}. Severity: {vulnerability.get("severity", "N/A")}.\n"

    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model="gpt-3.5-turbo",
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        return f"Error generating AI report: {e}"

def calculate_risk_score(scan_results):
    bandit_findings = scan_results.get("bandit_scan", {}).get("results", [])
    nuclei_findings = scan_results.get("nuclei_scan", [])
    retirejs_findings = scan_results.get("retirejs_scan", {}).get("data", [])
    score = 0
    severity_map = {
        "LOW": 1,
        "MEDIUM": 3,
        "HIGH": 5,
        "CRITICAL": 10 # For Nuclei and Retire.js
    }
    for finding in bandit_findings:
        score += severity_map.get(finding['issue_severity'].upper(), 0)
    for finding in nuclei_findings:
        score += severity_map.get(finding.get('info', {}).get('severity', '').upper(), 0)
    for finding in retirejs_findings:
        for vulnerability in finding.get("vulnerabilities", []):
            score += severity_map.get(vulnerability.get("severity", '').upper(), 0)
    return score

def generate_pdf_report(scan_results, ai_summary, risk_score, repo_name="report"):
    html_content = f"""
    <html>
    <head><title>Security Report for {repo_name}</title></head>
    <body>
        <h1>Security Report for {repo_name}</h1>
        <h2>Risk Score: {risk_score}</h2>
        <h2>AI Summary:</h2>
        <p>{ai_summary}</p>
        <h2>Bandit Scan Results:</h2>
        <pre>{json.dumps(scan_results.get("bandit_scan", {}), indent=2)}</pre>
        <h2>Nuclei Scan Results:</h2>
        <pre>{json.dumps(scan_results.get("nuclei_scan", []), indent=2)}</pre>
        <h2>Retire.js Scan Results:</h2>
        <pre>{json.dumps(scan_results.get("retirejs_scan", {}), indent=2)}</pre>
    </body>
    </html>
    """
    pdf_path = f"./reports/{repo_name}_security_report.pdf"
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    HTML(string=html_content).write_pdf(pdf_path)
    return pdf_path
