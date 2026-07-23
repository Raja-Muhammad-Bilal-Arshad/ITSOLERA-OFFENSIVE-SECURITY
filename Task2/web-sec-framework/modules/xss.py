import random
import string
from urllib.parse import urlencode, quote

from utils.request_handler import send_request
from utils.helpers import print_info, print_success, print_warning, print_error
from utils.param_discovery import discover_get_params, discover_forms


def _random_marker(length=6):
    return "z" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class XSSTestingModule:
    """Module 3: probes discovered GET/POST parameters for reflected XSS."""

    name = "Cross-Site Scripting (XSS) Testing"

    def __init__(self, target, timeout=20, headers=None, cookies=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        # --- custom headers / cookies (consistent with auth.py / disclosure.py) ---
        self.custom_headers = headers or {}
        self.custom_cookies = cookies or {}
        self.findings = []
        self._tested_params = set()
        self.marker = _random_marker()

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

    # --- Payloads --------------------------------------------------------

    def _payload_set(self):
        """Safe, inert marker-based payloads plus basic encoded variants.
        These do not perform any real attack action; they only exist to be
        detected verbatim (or decoded) in a reflected response."""
        raw = [
            f"<script>/*{self.marker}*/alert('{self.marker}')</script>",
            f"\"'><svg/onload=alert('{self.marker}')>",
            f"<{self.marker}tag>",
        ]
        # Basic payload encoding (URL-encoding) to see if the app decodes
        # input before reflecting it back — a common filter-bypass vector.
        encoded = [quote(p, safe="") for p in raw]
        return raw + encoded

    @staticmethod
    def _reflected(response_text, payload):
        return bool(response_text) and payload in response_text

    # --- Orchestration -----------------------------------------------------

    def run(self):
        print_info(f"[Module 3] Starting XSS Testing on {self.target}")

        # 1. GET parameters discovered directly from the target URL
        get_params = discover_get_params(self.target)
        base_url = self.target.split("?", 1)[0]
        if get_params:
            print_info(f"Discovered GET parameter(s): {', '.join(get_params.keys())}")
            self._test_get_params(base_url, get_params)
        else:
            print_warning("No GET query parameters present on the target URL; "
                        "skipping GET-based XSS tests.")

        # 2. Forms (GET or POST) discovered on the target page itself
        resp = send_request(self.target, method="GET", timeout=self.timeout, **self._request_kwargs())
        if resp is not None and resp.text:
            forms = discover_forms(resp.text, self.target)
            if forms:
                for form in forms:
                    print_info(f"Discovered form: {form['method']} {form['action']} "
                            f"params={list(form['params'].keys())}")
                    if form["method"] == "POST":
                        self._test_post_params(form)
                    else:
                        self._test_get_params(form["action"].split("?", 1)[0], form["params"])
            else:
                print_warning("No HTML forms discovered on the target page; "
                            "skipping form-based XSS tests.")
        else:
            print_warning("Could not retrieve target page; skipping form discovery.")

        print_success(f"[Module 3] Completed with {len(self.findings)} finding(s)")
        return self.findings

    # --- Test implementations --------------------------------------------

    def _test_get_params(self, base_url, params):
        for param in params:
            key = ("GET", base_url, param)
            if key in self._tested_params:
                continue
            self._tested_params.add(key)

            for payload in self._payload_set():
                test_params = dict(params)
                test_params[param] = payload
                url = f"{base_url}?{urlencode(test_params)}"
                resp = send_request(url, method="GET", timeout=self.timeout, **self._request_kwargs())
                if resp is None:
                    continue
                if self._reflected(resp.text, payload):
                    self._add_finding(
                        title=f"Reflected XSS in GET parameter '{param}'",
                        severity="High",
                        evidence=(
                            f"Marker payload was reflected unescaped at {base_url} "
                            f"via parameter '{param}': {payload[:80]}"
                        ),
                        recommendation="Context-aware output-encode all user-supplied "
                                    "GET parameters before reflecting them in HTML, "
                                    "and set a restrictive Content-Security-Policy as "
                                    "defense in depth.",
                    )
                    break  # one confirmed reflection is enough evidence per param

    def _test_post_params(self, form):
        action = form["action"]
        for param in form["params"]:
            key = ("POST", action, param)
            if key in self._tested_params:
                continue
            self._tested_params.add(key)

            for payload in self._payload_set():
                test_params = dict(form["params"])
                test_params[param] = payload
                resp = send_request(action, method="POST", timeout=self.timeout,
                                     data=test_params, **self._request_kwargs())
                if resp is None:
                    continue
                if self._reflected(resp.text, payload):
                    self._add_finding(
                        title=f"Reflected XSS in POST parameter '{param}'",
                        severity="High",
                        evidence=(
                            f"Marker payload was reflected unescaped at {action} "
                            f"via POST field '{param}': {payload[:80]}"
                        ),
                        recommendation="Context-aware output-encode all user-supplied "
                                    "POST input before reflecting it in HTML responses, "
                                    "and validate input server-side.",
                    )
                    break