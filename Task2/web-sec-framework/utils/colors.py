"""
colors.py
---------
Minimal ANSI color helper so the framework has colored terminal output
without pulling in an external dependency like colorama.
"""

import sys


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    # Disable colors automatically if output is piped/redirected (not a tty)
    _enabled = sys.stdout.isatty()

    @classmethod
    def wrap(cls, text, color):
        if not cls._enabled:
            return text
        return f"{color}{text}{cls.RESET}"


def info(text):
    return Colors.wrap(text, Colors.CYAN)


def success(text):
    return Colors.wrap(text, Colors.GREEN)


def warning(text):
    return Colors.wrap(text, Colors.YELLOW)


def error(text):
    return Colors.wrap(text, Colors.RED)


def bold(text):
    return Colors.wrap(text, Colors.BOLD)


def severity_color(severity):
    """Return a colorized severity label (High/Medium/Low/Info)."""
    severity = (severity or "").lower()
    mapping = {
        "critical": Colors.RED,
        "high": Colors.RED,
        "medium": Colors.YELLOW,
        "low": Colors.BLUE,
        "info": Colors.GRAY,
    }
    color = mapping.get(severity, Colors.GRAY)
    return Colors.wrap(severity.upper() or "INFO", color)
