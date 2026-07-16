# utils/helpers.py

class Colors:
    """Standard ANSI escape sequences for terminal colors."""
    SUCCESS = '\033[92m'  # Green
    WARNING = '\033[93m'  # Yellow
    ERROR = '\033[91m'    # Red
    INFO = '\033[94m'     # Blue
    RESET = '\033[0m'     # Reset to default terminal color

def print_success(message):
    """Outputs a successful finding or action in green."""
    print(f"{Colors.SUCCESS}[+] {message}{Colors.RESET}")

def print_warning(message):
    """Outputs a warning, missing configuration, or low/medium severity finding in yellow."""
    print(f"{Colors.WARNING}[!] {message}{Colors.RESET}")

def print_error(message):
    """Outputs an error, failure, or high severity vulnerability in red."""
    print(f"{Colors.ERROR}[-] {message}{Colors.RESET}")

def print_info(message):
    """Outputs general framework information or status updates in blue."""
    print(f"{Colors.INFO}[*] {message}{Colors.RESET}")
