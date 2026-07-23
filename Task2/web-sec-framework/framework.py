# framework.py
import argparse
import sys
from utils.helpers import print_info, print_success, print_warning, print_error

# Attempt to import your module. 
# We use try/except so the framework doesn't crash if a file is missing during development.
try:
    from modules.headers import analyze_headers
except ImportError:
    analyze_headers = None

# --- Added: imports for Module 2 (auth.py) and Module 5 (disclosure.py) ---
try:
    from modules.auth import AuthAssessmentModule
except ImportError:
    AuthAssessmentModule = None

try:
    from modules.disclosure import InformationDisclosureModule
except ImportError:
    InformationDisclosureModule = None

# --- Added: imports for Module 3 (xss.py) and Module 4 (sqli.py) ---
try:
    from modules.xss import XSSTestingModule
except ImportError:
    XSSTestingModule = None

try:
    from modules.sqli import SQLiTestingModule
except ImportError:
    SQLiTestingModule = None


# --- Added: shared helper to print findings returned by auth.py / disclosure.py ---
# (headers.py prints its own report internally, but auth.py and disclosure.py
# return a list of finding dicts from .run(), so something needs to display them.)
def print_findings(findings):
    if not findings:
        print_success("No issues found by this module.")
        print("-" * 50)
        return

    severity_colors = {
        "Critical": "\033[95m",  # Magenta
        "High": "\033[91m",      # Red
        "Medium": "\033[93m",    # Yellow
        "Low": "\033[94m",       # Blue
        "Info": "\033[96m",      # Cyan
    }
    reset = "\033[0m"

    print_warning(f"FINDINGS ({len(findings)}):")
    for i, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "Info")
        color = severity_colors.get(severity, "")
        print(f"\n  [{i}] {finding.get('title', 'Untitled Finding')} "
            f"{color}[{severity}]{reset}")
        print(f"      Evidence: {finding.get('evidence', 'N/A')}")
        print(f"      Recommendation: {finding.get('recommendation', 'N/A')}")
    print("\n" + "-" * 50)


def main():
    # 1. Argument Parsing

    parser = argparse.ArgumentParser(
        description="ITSOLERA Web Security Testing Framework",
        epilog="Example: python framework.py --target http://testphp.vulnweb.com --module xss"
    )

    # Required: The target URL
    parser.add_argument(
        "--target",
        required=True,
        type=str,
        help="The target URL to test (must include http:// or https://)"
    )

    # Required: The module to run, restricted to specific choices
    parser.add_argument(
        "--module",
        required=True,
        type=str,
        choices=['headers', 'auth', 'xss', 'sqli', 'disclosure', 'all'],
        help="Which security module to execute"
    )

    # Optional: Configuration file loading (Advanced Feature)
    parser.add_argument(
        "--config",
        required=False,
        type=str,
        help="Path to an optional configuration file (e.g., config.json)"
    )

    # --- Added: options needed for Module 2 (auth) ---
    parser.add_argument(
        "--login-path",
        required=False,
        type=str,
        default="/login",
        help="Path to the login form, relative to target (default: /login). Used by the auth module."
    )

    # --- Added: Additional Features required for Member 2's modules ---
    parser.add_argument(
        "--cookies",
        required=False,
        type=str,
        help="Custom cookies to send with requests, format: 'name1=value1; name2=value2'"
    )
    parser.add_argument(
        "--header",
        action="append",
        dest="headers",
        required=False,
        help="Custom header, format: 'Key: Value'. Can be passed multiple times."
    )
    parser.add_argument(
        "--user-agent",
        required=False,
        type=str,
        help="Custom User-Agent string to use instead of the default."
    )

    # --- Added: option needed for Module 4 (sqli) ---
    parser.add_argument(
        "--time-based",
        action="store_true",
        dest="time_based",
        required=False,
        help="Enable optional time-based SQL injection detection (adds SLEEP()/"
            "WAITFOR DELAY payloads that intentionally delay some requests "
            "by several seconds). Off by default."
    )

    # Parse the arguments
    args = parser.parse_args()

    # Print initial startup info using your new colored output utility
    print_info(f"Targeting: {args.target}")
    print_info(f"Selected Module: {args.module}")

    # Handle the advanced configuration feature if the user provided it
    if args.config:
        print_info(f"Loading configuration from {args.config}...")
        # TODO: Add logic later to parse a JSON or YAML file to override default settings

    # --- Added: build custom headers/cookies dicts from CLI input for auth/disclosure ---
    custom_cookies = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                custom_cookies[key.strip()] = value.strip()

    custom_headers = {}
    if args.headers:
        for entry in args.headers:
            if ":" in entry:
                key, value = entry.split(":", 1)
                custom_headers[key.strip()] = value.strip()

    if args.user_agent:
        custom_headers["User-Agent"] = args.user_agent

    print("-" * 50)


    # 2. The Module Loader (Dispatcher)

    
    run_all = (args.module == 'all')

    # Route to Module 1: Security Headers
    if args.module == 'headers' or run_all:
        if analyze_headers:
            print_info("Starting Security Headers Analysis...")
            # Call the function from headers.py and pass the target
            analyze_headers(args.target)
        else:
            print_error("Failed to load 'headers.py'. Ensure the file exists and the function is named 'analyze_headers'.")

    # Route to Module 2: Authentication
    if args.module == 'auth' or run_all:
        if AuthAssessmentModule:
            print_info("Starting Authentication Assessment...")
            auth_module = AuthAssessmentModule(
                args.target,
                login_path=args.login_path,
                headers=custom_headers,
                cookies=custom_cookies,
            )
            findings = auth_module.run()
            print_findings(findings)
        else:
            print_error("Failed to load 'auth.py'. Ensure the file exists and the class is named 'AuthAssessmentModule'.")

    # Route to Module 3: XSS Testing
    if args.module == 'xss' or run_all:
        if XSSTestingModule:
            print_info("Starting XSS Testing...")
            xss_module = XSSTestingModule(
                args.target,
                headers=custom_headers,
                cookies=custom_cookies,
            )
            findings = xss_module.run()
            print_findings(findings)
        else:
            print_error("Failed to load 'xss.py'. Ensure the file exists and the class is named 'XSSTestingModule'.")

    # Route to Module 4: SQL Injection Testing
    if args.module == 'sqli' or run_all:
        if SQLiTestingModule:
            print_info("Starting SQL Injection Testing...")
            sqli_module = SQLiTestingModule(
                args.target,
                headers=custom_headers,
                cookies=custom_cookies,
                enable_time_based=args.time_based,
            )
            findings = sqli_module.run()
            print_findings(findings)
        else:
            print_error("Failed to load 'sqli.py'. Ensure the file exists and the class is named 'SQLiTestingModule'.")

    # Route to Module 5: Information Disclosure
    if args.module == 'disclosure' or run_all:
        if InformationDisclosureModule:
            print_info("Starting Information Disclosure Scan...")
            disclosure_module = InformationDisclosureModule(
                args.target,
                headers=custom_headers,
                cookies=custom_cookies,
            )
            findings = disclosure_module.run()
            print_findings(findings)
        else:
            print_error("Failed to load 'disclosure.py'. Ensure the file exists and the class is named 'InformationDisclosureModule'.")

if __name__ == "__main__":
    # Ensure properr exit on keyboard interrupt (Ctrl+C)
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        print_error("Scan interrupted by user. Exiting...")
        sys.exit(0)