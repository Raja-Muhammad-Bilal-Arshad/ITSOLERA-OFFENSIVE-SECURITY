# Web Security Testing Framework

A modular, CLI-based Web Security Testing Framework built for **ITSOLERA PVT LTD — Summer
Internship 2026, Task 2 (Offensive Security)**.

It automates detection of common web application vulnerabilities against intentionally
vulnerable / authorized test targets and produces a professional HTML or JSON report.

> ⚠️ **Authorization notice:** Only run this tool against applications you own or have
> explicit written authorization to test (e.g. DVWA, OWASP Juice Shop, bWAPP, WebGoat,
> Mutillidae, or the public intentionally-vulnerable demo sites). Do not use this against
> systems you do not have permission to assess.

---

## Features

- 5 independent, selectable modules (see below)
- Multi-threaded module execution (`--threads`)
- Live progress bar during scanning
- Custom User-Agent, custom headers, cookie support
- Proxy support (route traffic through Burp Suite, etc.)
- Configurable timeout and JSON config file support
- Colored terminal output
- Professional HTML and/or JSON report generation with severity ratings,
  evidence, and remediation guidance

## Modules

| Key          | Name                          | What it checks |
|--------------|-------------------------------|----------------|
| `headers`    | Security Headers Analyzer     | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS, Permissions-Policy, tech-disclosure headers |
| `auth`       | Authentication Assessment     | Username enumeration, login response differences/timing, basic lockout detection, session cookie flags (Secure/HttpOnly/SameSite) |
| `xss`        | XSS Testing                   | Reflected XSS in GET parameters and discovered HTML forms (GET/POST), using safe marker payloads |
| `sqli`       | SQL Injection Testing         | Error-based, boolean-based, and (optional) time-based blind SQL injection in GET parameters — non-destructive only |
| `disclosure` | Information Disclosure        | robots.txt, sitemap.xml, `.git` exposure, backup files, phpinfo, `.env`/config files, directory listing |

## Project Structure

```
framework/
│
├── framework.py            # CLI entrypoint
├── modules/
│   ├── headers.py
│   ├── auth.py
│   ├── xss.py
│   ├── sqli.py
│   └── disclosure.py
├── utils/
│   ├── http_client.py       # shared HTTP session (UA, headers, cookies, proxy, timeout)
│   ├── findings.py           # Finding / ScanResult data model
│   ├── report.py             # HTML + JSON report generation
│   ├── colors.py              # colored terminal output
│   ├── progress.py             # dependency-free progress bar
│   └── config.py                # JSON config file loader
├── reports/                  # generated reports land here
├── requirements.txt
├── config.sample.json        # example config file
└── README.md
```

## Installation

```bash
git clone <your-repo-url>
cd framework
pip install -r requirements.txt
```

Requires Python 3.8+.

## Usage

Basic:

```bash
python framework.py --target http://testphp.vulnweb.com --module xss
python framework.py --target http://demo.testfire.net --module headers
```

Run everything:

```bash
python framework.py --target http://testphp.vulnweb.com --module all
```

Run a subset of modules, generate both report formats, use more threads:

```bash
python framework.py --target "http://testphp.vulnweb.com/listproducts.php?cat=1" \
  --module sqli,xss --output-format both --threads 3
```

Route traffic through Burp Suite, add a custom header and cookie:

```bash
python framework.py --target http://demo.testfire.net --module all \
  --proxy http://127.0.0.1:8080 \
  --header "X-Test-Run: internship" \
  --cookie "session=abc123" \
  --user-agent "Mozilla/5.0 (WebSecFramework Test)"
```

Use a config file for defaults (CLI flags still override it):

```bash
python framework.py --config config.sample.json
```

Point the auth module at an explicit login page:

```bash
python framework.py --target http://demo.testfire.net --module auth \
  --login-url http://demo.testfire.net/login.jsp
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--target` | Target URL to test (required, unless set in `--config`) |
| `--module` | Comma-separated module keys, or `all` (default: `all`) |
| `--login-url` | Explicit login page URL for the `auth` module |
| `--user-agent` | Custom User-Agent string |
| `--header` | Custom header `"Name: Value"` (repeatable) |
| `--cookie` | Cookie `"name=value"` (repeatable) |
| `--proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--threads` | Modules to run concurrently (default: 3) |
| `--output-format` | `html`, `json`, or `both` (default: `html`) |
| `--output-dir` | Report output directory (default: `reports/`) |
| `--config` | Path to a JSON config file |
| `--no-color` | Disable colored terminal output |
| `--verbose` | Print each actionable finding as a bullet in the summary |

## Report Contents

Every generated report includes:

- Target URL and scan date
- Modules executed
- All vulnerabilities found, with severity, evidence, and remediation
- An overall risk rating derived from the highest-severity finding

## Advanced Features Implemented

- ✅ Multi-threading (concurrent module execution via `ThreadPoolExecutor`)
- ✅ Progress bar
- ✅ Custom User-Agent
- ✅ Cookie support
- ✅ Custom request headers
- ✅ Proxy support (Burp Suite compatible)
- ✅ Timeout handling
- ✅ Colored terminal output
- ✅ HTML report generation
- ✅ JSON export
- ✅ Configuration file support

## Sample Report

See `sample_report.html` / `sample_report.json` (included in the submission) for an
example run against a local intentionally-vulnerable test target.

## Recommended Test Targets

- DVWA
- OWASP Juice Shop
- bWAPP
- WebGoat
- Mutillidae
- `testphp.vulnweb.com`, `demo.testfire.net` (public intentionally-vulnerable demo apps)

## Disclaimer

This tool is provided for educational and authorized security-testing purposes only.
The author and ITSOLERA PVT LTD accept no liability for misuse. Always obtain explicit
authorization before testing any system you do not own.
