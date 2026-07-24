#!/usr/bin/env python3
"""
framework.py
============
Custom Web Security Testing Framework — CLI entrypoint.

Summer Internship Task 2 — Offensive Security
ITSOLERA PVT LTD

Usage examples:
    python framework.py --target http://testphp.vulnweb.com --module xss
    python framework.py --target http://demo.testfire.net --module headers
    python framework.py --target http://testphp.vulnweb.com --module all
    python framework.py --target http://testphp.vulnweb.com/listproducts.php?cat=1 \\
        --module sqli,xss --output-format both --threads 3

IMPORTANT: Only test applications you own or are explicitly authorized to
assess (e.g. DVWA, OWASP Juice Shop, bWAPP, WebGoat, Mutillidae, or the
intentionally vulnerable public test sites referenced in this task).
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils import colors
from utils.http_client import HttpClient
from utils.progress import ProgressBar
from utils.config import load_config
from utils.report import generate_report

from modules import headers as mod_headers
from modules import auth as mod_auth
from modules import xss as mod_xss
from modules import sqli as mod_sqli
from modules import disclosure as mod_disclosure

MODULE_REGISTRY = {
    "headers": ("Security Headers Analyzer", mod_headers),
    "auth": ("Authentication Assessment", mod_auth),
    "xss": ("XSS Testing", mod_xss),
    "sqli": ("SQL Injection Testing", mod_sqli),
    "disclosure": ("Information Disclosure", mod_disclosure),
}

BANNER = r"""
 __      __      _     ____                     _____                          _
 \ \    / /____ | |__ / ___|  ___  ___          |  ___| __ __ _ _ __ ___   __ _|| |__
  \ \  / // _ \| '_ \\___ \ / _ \/ __|         | |_ | '__/ _` | '_ ` _ \ / _` | '_ \
   \ \/ /|  __/| |_) |___) |  __/ (__          |  _|| | | (_| | | | | | | (_| | | | |
    \  /  \___||_.__/|____/ \___|\___|         |_|  |_|  \__,_|_| |_| |_|\__,_|_| |_|

        Web Security Testing Framework  |  ITSOLERA PVT LTD  |  Task 2 (Offensive Security)
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="framework.py",
        description="Custom Web Security Testing Framework — automates detection of common "
                    "web application vulnerabilities against authorized/intentionally "
                    "vulnerable targets.",
    )
    parser.add_argument("--target", help="Target URL, e.g. http://testphp.vulnweb.com")
    parser.add_argument(
        "--module", default="all",
        help="Comma-separated modules to run: headers,auth,xss,sqli,disclosure or 'all' (default: all)"
    )
    parser.add_argument("--login-url", help="Explicit login page URL for the auth module")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument(
        "--header", action="append", default=[],
        help="Custom request header 'Name: Value' (repeatable)"
    )
    parser.add_argument(
        "--cookie", action="append", default=[],
        help="Cookie 'name=value' to send with every request (repeatable)"
    )
    parser.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp Suite, etc.)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=3, help="Number of modules to run concurrently (default: 3)")
    parser.add_argument(
        "--output-format", choices=["html", "json", "both"], default="html",
        help="Report output format (default: html)"
    )
    parser.add_argument("--output-dir", default="reports", help="Directory to write reports to (default: reports/)")
    parser.add_argument("--config", help="Path to a JSON config file with default options")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--verbose", action="store_true", help="Print extra detail per finding as it's found")
    return parser.parse_args()


def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ":" in h:
            name, value = h.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers


def parse_cookies(cookie_list):
    cookies = {}
    for c in cookie_list:
        if "=" in c:
            name, value = c.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies


def resolve_modules(module_arg):
    if module_arg.strip().lower() == "all":
        return list(MODULE_REGISTRY.keys())
    requested = [m.strip().lower() for m in module_arg.split(",") if m.strip()]
    invalid = [m for m in requested if m not in MODULE_REGISTRY]
    if invalid:
        print(colors.error(f"[!] Unknown module(s): {', '.join(invalid)}"))
        print(colors.info(f"    Available modules: {', '.join(MODULE_REGISTRY.keys())}"))
        sys.exit(1)
    return requested


def run_module(module_key, target, http_client, login_url=None):
    display_name, module = MODULE_REGISTRY[module_key]
    start = time.time()
    try:
        result = module.run(target, http_client, login_url=login_url)
    except Exception as exc:  # noqa: BLE001 — surface any module failure as a scan error, don't crash the run
        from utils.findings import ScanResult
        result = ScanResult(module_name=display_name, target=target)
        result.errors.append(f"Module '{module_key}' raised an exception: {exc}")
        result.finish()
    elapsed = time.time() - start
    return module_key, result, elapsed


def main():
    args = parse_args()

    if args.no_color:
        colors.Colors._enabled = False

    print(colors.info(BANNER))

    config = {}
    if args.config:
        try:
            config = load_config(args.config)
        except FileNotFoundError as exc:
            print(colors.error(f"[!] {exc}"))
            sys.exit(1)

    target = args.target or config.get("target")
    if not target:
        print(colors.error("[!] --target is required (or set 'target' in a --config file)."))
        sys.exit(1)
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    module_arg = args.module if args.module != "all" or not config.get("modules") else ",".join(config["modules"])
    modules_to_run = resolve_modules(module_arg)

    user_agent = args.user_agent or config.get("user_agent")
    extra_headers = {**config.get("headers", {}), **parse_headers(args.header)}
    cookies = {**config.get("cookies", {}), **parse_cookies(args.cookie)}
    proxy = args.proxy or config.get("proxy")
    timeout = args.timeout if args.timeout != 10 else config.get("timeout", 10)
    threads = args.threads if args.threads != 3 else config.get("threads", 3)
    output_format = args.output_format if args.output_format != "html" else config.get("output_format", "html")
    output_dir = args.output_dir if args.output_dir != "reports" else config.get("output_dir", "reports")

    print(colors.bold(f"[*] Target:  ") + target)
    print(colors.bold(f"[*] Modules: ") + ", ".join(modules_to_run))
    if proxy:
        print(colors.bold(f"[*] Proxy:   ") + proxy)
    print()

    http_client = HttpClient(
        user_agent=user_agent,
        extra_headers=extra_headers,
        cookies=cookies,
        proxy=proxy,
        timeout=timeout,
    )

    results = {}
    bar = ProgressBar(total=len(modules_to_run), prefix="Scanning")

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        futures = {
            executor.submit(run_module, m, target, http_client, args.login_url): m
            for m in modules_to_run
        }
        for future in as_completed(futures):
            module_key, result, elapsed = future.result()
            results[module_key] = result
            bar.update(step_label=f"{MODULE_REGISTRY[module_key][0]} ({elapsed:.1f}s)")

    print()
    print(colors.bold("[*] Scan Summary"))
    print("-" * 60)
    ordered_results = [results[m] for m in modules_to_run if m in results]

    total_findings = 0
    for module_key in modules_to_run:
        result = results.get(module_key)
        if result is None:
            continue
        display_name = MODULE_REGISTRY[module_key][0]
        actionable = [f for f in result.findings if f.severity != "Info"]
        total_findings += len(actionable)
        print(f"  {colors.bold(display_name)}: {len(actionable)} issue(s) found "
              f"({len(result.findings)} checks total)")
        if args.verbose:
            for f in result.findings:
                if f.severity != "Info":
                    print(f"      - [{colors.severity_color(f.severity)}] {f.title}")
        if result.errors:
            for err in result.errors:
                print(colors.error(f"      ! {err}"))

    print("-" * 60)
    print(colors.bold(f"[*] Total actionable findings: ") +
          (colors.error(str(total_findings)) if total_findings else colors.success("0")))

    print()
    print(colors.info("[*] Generating report..."))
    paths, report_data = generate_report(
        target, ordered_results, output_dir=output_dir, output_format=output_format
    )
    print(colors.success(f"[+] Overall Risk Rating: {report_data['overall_risk_rating']}"))
    for p in paths:
        print(colors.success(f"[+] Report written to: {p}"))


if __name__ == "__main__":
    main()
