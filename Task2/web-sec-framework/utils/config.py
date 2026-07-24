"""
config.py
---------
Optional configuration file support. Lets a user store defaults
(target, modules, headers, proxy, cookies, thread count, timeout, etc.)
in a JSON file instead of retyping long CLI commands.

CLI arguments always take precedence over config file values.
"""

import json
import os


DEFAULT_CONFIG = {
    "target": None,
    "modules": [],
    "user_agent": None,
    "headers": {},
    "cookies": {},
    "proxy": None,
    "timeout": 10,
    "threads": 5,
    "output_format": "html",
    "output_dir": "reports"
}


def load_config(path):
    """Load a JSON config file and merge it over the defaults.
    Returns DEFAULT_CONFIG unchanged if the path doesn't exist or is None."""
    config = DEFAULT_CONFIG.copy()
    if not path:
        return config
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        user_config = json.load(f)
    config.update(user_config)
    return config
