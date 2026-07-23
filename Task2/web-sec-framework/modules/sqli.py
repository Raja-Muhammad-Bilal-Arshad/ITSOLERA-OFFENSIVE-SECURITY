import re
import time
from urllib.parse import urlencode

from utils.request_handler import send_request
from utils.helpers import print_info, print_success, print_warning, print_error
from utils.param_discovery import discover_get_params, discover_forms

# Known SQL error signatures across common database engines.
_SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"pg_query\(\)",
    r"postgresql.*error",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"sqlite3\.operationalerror",
    r"sqlite_error",
    r"near \".*\": syntax error",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch_array\(\)",
    r"syntax error at or near",
    r"unterminated quoted string",
    r"odbc sql server driver",
]
_SQL_ERROR_RE = re.compile("|".join(_SQL_ERROR_PATTERNS), re.IGNORECASE)

# Simple, non-destructive syntax-breaking probes for error-based detection.
_ERROR_PROBES = ["'", "\"", "')", "\";", "' OR '"]

# Boolean-based probes: TRUE and FALSE conditions that don't alter data.
_BOOLEAN_TRUE = "' OR '1'='1"
_BOOLEAN_FALSE = "' OR '1'='2"

# Time-based probes (SELECT-only delay functions, no data modification).
_TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -",
    "' OR SLEEP(5)#",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)-- -",
]
_TIME_DELAY_SECONDS = 5
_TIME_THRESHOLD_SECONDS = 4.5  # allow some tolerance below the actual delay


class SQLiTestingModule:
    """Module 4: probes discovered GET/POST parameters for SQL injection."""

    name = "SQL Injection Testing"

    def __init__(self, target, timeout=25, headers=None, cookies=None,
                enable_time_based=False):
        self.target = target.rstrip("/")
        self.timeout = timeout
        # --- custom headers / cookies (consistent with auth.py / disclosure.py) ---
        self.custom_headers = headers or {}
        self.custom_cookies = cookies or {}
        self.enable_time_based = enable_time_based
        self.findings = []
        self._confirmed_params = set()  # avoid duplicate findings per param

    def _request_kwargs(self):
        kwargs = {}
        if self.custom_headers:
            kwargs["headers"] = self.custom_headers
        if self.custom_cookies:
            kwargs["cookies"] = self.custom_cookies
        return kwargs

    def _add_finding(self, title, severity, evidence, recommendation):
        self.findings.append({
            "module": self.name,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    # --- Orchestration -----------------------------------------------------

    def run(self):
        print_info(f"[Module 4] Starting SQL Injection Testing on {self.target}")
        if self.enable_time_based:
            print_warning("Time-based detection ENABLED: this will deliberately "
                        "delay some requests by several seconds.")

        get_params = discover_get_params(self.target)
        base_url = self.target.split("?", 1)[0]
        if get_params:
            print_info(f"Discovered GET parameter(s): {', '.join(get_params.keys())}")
            self._test_params("GET", base_url, get_params)
        else:
            print_warning("No GET query parameters present on the target URL; "
                        "skipping GET-based SQLi tests.")

        resp = send_request(self.target, method="GET", timeout=self.timeout, **self._request_kwargs())
        if resp is not None and resp.text:
            forms = discover_forms(resp.text, self.target)
            if forms:
                for form in forms:
                    print_info(f"Discovered form: {form['method']} {form['action']} "
                            f"params={list(form['params'].keys())}")
                    self._test_params(form["method"], form["action"], form["params"])
            else:
                print_warning("No HTML forms discovered on the target page; "
                            "skipping form-based SQLi tests.")
        else:
            print_warning("Could not retrieve target page; skipping form discovery.")

        print_success(f"[Module 4] Completed with {len(self.findings)} finding(s)")
        return self.findings

    # --- Request helper ------------------------------------------------

    def _send(self, method, base_url, params, timeout=None):
        timeout = timeout or self.timeout
        if method == "GET":
            url = f"{base_url}?{urlencode(params)}"
            return send_request(url, method="GET", timeout=timeout, **self._request_kwargs())
        return send_request(base_url, method="POST", timeout=timeout, data=params,
                             **self._request_kwargs())

    # --- Test implementations --------------------------------------------

    def _test_params(self, method, base_url, params):
        for param in params:
            key = (method, base_url, param)
            if key in self._confirmed_params:
                continue

            if self._test_error_based(method, base_url, params, param):
                self._confirmed_params.add(key)
                continue  # already confirmed; no need for boolean/time checks

            if self._test_boolean_based(method, base_url, params, param):
                self._confirmed_params.add(key)
                continue

            if self.enable_time_based:
                if self._test_time_based(method, base_url, params, param):
                    self._confirmed_params.add(key)

    def _test_error_based(self, method, base_url, params, param):
        for probe in _ERROR_PROBES:
            test_params = dict(params)
            test_params[param] = probe
            resp = self._send(method, base_url, test_params)
            if resp is None or not resp.text:
                continue
            match = _SQL_ERROR_RE.search(resp.text)
            if match:
                self._add_finding(
                    title=f"SQL Injection (Error-Based) in {method} parameter '{param}'",
                    severity="Critical",
                    evidence=(
                        f"Injecting `{probe}` into '{param}' at {base_url} triggered a "
                        f"visible database error matching pattern '{match.group(0)[:60]}'."
                    ),
                    recommendation="Use parameterized queries / prepared statements for "
                                "all database access, and disable verbose database "
                                "error output in production (return generic error pages).",
                )
                return True
        return False

    def _test_boolean_based(self, method, base_url, params, param):
        true_params = dict(params)
        true_params[param] = _BOOLEAN_TRUE
        false_params = dict(params)
        false_params[param] = _BOOLEAN_FALSE

        true_resp = self._send(method, base_url, true_params)
        false_resp = self._send(method, base_url, false_params)
        if true_resp is None or false_resp is None:
            return False

        true_text = true_resp.text or ""
        false_text = false_resp.text or ""

        status_diff = true_resp.status_code != false_resp.status_code
        len_true, len_false = len(true_text), len(false_text)
        length_diff_pct = abs(len_true - len_false) / max(len_true, len_false, 1)

        if status_diff or length_diff_pct > 0.15:
            self._add_finding(
                title=f"Possible SQL Injection (Boolean-Based) in {method} parameter '{param}'",
                severity="High",
                evidence=(
                    f"TRUE condition ({_BOOLEAN_TRUE}) -> HTTP {true_resp.status_code}, "
                    f"{len_true} bytes; FALSE condition ({_BOOLEAN_FALSE}) -> "
                    f"HTTP {false_resp.status_code}, {len_false} bytes "
                    f"(~{length_diff_pct:.0%} size difference) on parameter '{param}' "
                    f"at {base_url}."
                ),
                recommendation="Use parameterized queries / prepared statements so that "
                            "injected logical operators cannot alter the executed SQL. "
                            "Confirm manually before treating this as a definite finding, "
                            "as legitimate pages can occasionally vary in size.",
            )
            return True
        return False

    def _test_time_based(self, method, base_url, params, param):
        # Establish a lightweight baseline first so a slow target isn't
        # mistaken for an injectable one.
        baseline_params = dict(params)
        baseline_params[param] = "1"
        start = time.time()
        baseline_resp = self._send(method, base_url, baseline_params)
        baseline_elapsed = time.time() - start
        if baseline_resp is None:
            return False

        for payload in _TIME_PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload
            start = time.time()
            resp = self._send(method, base_url, test_params,
                            timeout=self.timeout + _TIME_DELAY_SECONDS + 5)
            elapsed = time.time() - start
            if resp is None:
                continue

            delta = elapsed - baseline_elapsed
            if delta >= _TIME_THRESHOLD_SECONDS:
                self._add_finding(
                    title=f"Possible SQL Injection (Time-Based) in {method} parameter '{param}'",
                    severity="High",
                    evidence=(
                        f"Payload `{payload}` on parameter '{param}' at {base_url} "
                        f"caused a response delay of {elapsed:.2f}s vs a baseline of "
                        f"{baseline_elapsed:.2f}s (delta {delta:.2f}s)."
                    ),
                    recommendation="Use parameterized queries / prepared statements. "
                                "Confirm manually (network jitter can produce false "
                                "positives); repeat the test to rule out coincidence.",
                )
                return True
        return False