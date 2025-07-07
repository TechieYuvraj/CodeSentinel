
import subprocess
import os
import shutil
import json
import tempfile
from git import Repo

# This file will contain the core logic for the vulnerability scanner.

def scan_url(url: str):
    # Placeholder for URL scanning logic
    return {"message": f"Scanning {url} for vulnerabilities..."}

def scan_repo(repo_url: str):
    """
    Clones a repository, scans it with Bandit, and returns the results.
    """
    temp_dir = tempfile.mkdtemp()
    try:
        # Clone the repository
        Repo.clone_from(repo_url, temp_dir)

        # Run bandit and get JSON output
        result = subprocess.run(
            ['bandit', '-r', temp_dir, '-f', 'json'],
            capture_output=True,
            text=True
        )

        # Check for errors during the scan
        if result.returncode != 0 and result.returncode != 1: # Bandit exits 1 for issues found
            # Log the error or handle it as needed
            error_message = result.stderr or "Unknown error during scan"
            return {"error": "Failed to scan repository.", "details": error_message}

        # It's possible bandit outputs to stderr even on success (e.g., warnings)
        # and the actual JSON report to stdout.
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # If stdout is not valid JSON, it might be an error message.
            return {"error": "Failed to parse scan results.", "details": result.stdout}

    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)
