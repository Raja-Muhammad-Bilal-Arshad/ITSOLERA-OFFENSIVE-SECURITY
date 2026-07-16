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

    # Parse the arguments
    args = parser.parse_args()

    # Print initial startup info using your new colored output utility
    print_info(f"Targeting: {args.target}")
    print_info(f"Selected Module: {args.module}")

    # Handle the advanced configuration feature if the user provided it
    if args.config:
        print_info(f"Loading configuration from {args.config}...")
        # TODO: Add logic later to parse a JSON or YAML file to override default settings
    
    print("-" * 50)


    # 2. The Module Loader (Dispatcher)

    
    # Route to Module 1: Security Headers (Your task)
    if args.module == 'headers' or args.module == 'all':
        if analyze_headers:
            print_info("Starting Security Headers Analysis...")
            # Call the function from headers.py and pass the target
            analyze_headers(args.target) 
        else:
            print_error("Failed to load 'headers.py'. Ensure the file exists and the function is named 'analyze_headers'.")

    # Route to Module 2: Authentication (Member 2's task)
    elif args.module == 'auth':
        print_warning("Authentication Assessment module is currently under development by Member 2.")
        # When Member 2 finishes, you will import their function at the top and call it here.

    # Route to Module 3: XSS (Member 3's task)
    elif args.module == 'xss':
        print_warning("XSS Testing module is currently under development by Member 3.")

    # Route to Module 4: SQL Injection (Member 3's task)
    elif args.module == 'sqli':
        print_warning("SQL Injection module is currently under development by Member 3.")

    # Route to Module 5: Information Disclosure (Member 2's task)
    elif args.module == 'disclosure':
        print_warning("Information Disclosure module is currently under development by Member 2.")

if __name__ == "__main__":
    # Ensure properr exit on keyboard interrupt (Ctrl+C)
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        print_error("Scan interrupted by user. Exiting...")
        sys.exit(0)
