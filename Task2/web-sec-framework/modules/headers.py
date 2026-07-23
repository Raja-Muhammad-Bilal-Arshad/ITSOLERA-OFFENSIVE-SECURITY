# modules/headers.py
from utils.request_handler import send_request
from utils.helpers import print_info, print_success, print_warning, print_error

# Define the target security headers, their risk severity, and remediation advice.
SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'severity': 'High', 
        'rec': "Implement CSP to prevent Cross-Site Scripting (XSS) and data injection attacks."
    },
    'Strict-Transport-Security': {
        'severity': 'High', 
        'rec': "Implement HSTS to enforce secure (HTTPS) connections and prevent downgrade attacks."
    },
    'X-Frame-Options': {
        'severity': 'Medium', 
        'rec': "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent Clickjacking attacks."
    },
    'X-Content-Type-Options': {
        'severity': 'Low', 
        'rec': "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing vulnerabilities."
    },
    'Referrer-Policy': {
        'severity': 'Low', 
        'rec': "Set to 'strict-origin-when-cross-origin' to protect sensitive referral data from leaking."
    },
    'Permissions-Policy': {
        'severity': 'Low', 
        'rec': "Restrict access to browser features (like camera, microphone, geolocation)."
    }
}

def analyze_headers(url):
    """
    Analyzes the HTTP response headers of a target URL for missing security controls.
    """
    print_info(f"Initiating Security Headers Analysis for: {url}")
    print("-" * 50)
    
    # 1. Fetch the Headers
    response = send_request(url, method="GET")
    
    # If the request failed (timeout, bad url), the request_handler already printed the error.
    # We just need to exit the module gracefully.
    if response is None:
        return

    # Extract headers (requests handles case-insensitivity automatically)
    server_headers = response.headers

    found_headers = []
    missing_headers = []

    # 2. Analyze the Specific Targets
    for header, details in SECURITY_HEADERS.items():
        if header in server_headers:
            found_headers.append((header, server_headers[header]))
        else:
            missing_headers.append((header, details['severity'], details['rec']))

    # 3. Format the Output
    
    # --- Existing Headers ---
    if found_headers:
        print_success("EXISTING SECURITY HEADERS:")
        for header, value in found_headers:
            print(f"  [+] {header}: {value[:80]}" + ("..." if len(value) > 80 else ""))
    else:
        print_error("EXISTING SECURITY HEADERS: None found.")
        
    print("\n")
    
    # --- Missing Headers ---
    if missing_headers:
        print_warning(f"MISSING SECURITY HEADERS ({len(missing_headers)}):")
        for header, severity, rec in missing_headers:
            # Color-code the severity dynamically
            if severity == 'High':
                sev_display = f"\033[91m[{severity}]\033[0m" # Red
            elif severity == 'Medium':
                sev_display = f"\033[93m[{severity}]\033[0m" # Yellow
            else:
                sev_display = f"\033[94m[{severity}]\033[0m" # Blue
                
            print(f"  [-] {header} {sev_display}")
            print(f"      Recommendation: {rec}")
    else:
        print_success("MISSING SECURITY HEADERS: None! The target has excellent header security.")
        
    print("-" * 50)
    print_info("Security Headers Analysis Complete.")
