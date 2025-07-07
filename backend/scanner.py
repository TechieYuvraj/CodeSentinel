
import requests

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
