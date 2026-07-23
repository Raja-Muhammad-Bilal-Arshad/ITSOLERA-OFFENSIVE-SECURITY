# utils/request_handler.py
import requests
from utils.helpers import print_error

def send_request(url, method="GET", timeout=20, **kwargs):
    # Add realistic browser User-Agent to bypass basic bot blockers
    headers = kwargs.pop('headers', {})
    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=timeout, **kwargs)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, timeout=timeout, **kwargs)
        else:
            response = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
            
        return response

    except requests.exceptions.Timeout:
        print_error(f"Connection Timed Out: The target ({url}) did not respond within {timeout} seconds.")
        return None
    except requests.exceptions.ConnectionError:
        print_error(f"Connection Error: Failed to establish a connection to {url}. The host might be down.")
        return None
    except requests.exceptions.RequestException as e:
        print_error(f"An unexpected HTTP error occurred while targeting {url}: {str(e)}")
        return None
