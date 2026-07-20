import re
import time
import math
from collections import Counter
from difflib import SequenceMatcher

from utils.request_handler import send_request
from utils.helpers import print_info, print_success, print_warning, print_error

_PROBE_USERNAMES = ["admin", "test_user_nonexistent_12345", "administrator"]
_FAKE_PASSWORD = "Wr0ng-Probe-Password!"


def _build_url(target, path):
    target = target.rstrip("/")
    path = (path or "").lstrip("/")
    return f"{target}/{path}" if path else target


class AuthAssessmentModule:
    """Module 2: evaluates login functionality for common weaknesses."""

    name = "Authentication Assessment"

    def __init__(self, target, login_path="/login", username_field="username",
                 password_field="password", timeout=20, max_lockout_attempts=5):
        self.target = target
        self.login_path = login_path
        self.username_field = username_field
        self.password_field = password_field
        self.timeout = timeout
        self.max_lockout_attempts = max_lockout_attempts
        self.findings = []

    def run(self):
        print_info(f"[Module 2] Starting Authentication Assessment on {self.target}")
        self._check_weak_password_policy()
        self._check_username_enumeration()
        self._check_login_response_differences()
        self._check_account_lockout()
        self._check_session_cookies()
        print_success(f"[Module 2] Completed with {len(self.findings)} finding(s)")
        return self.findings

    def _add_finding(self, title, severity, evidence, recommendation):
        self.findings.append({
            "module": self.name,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    def _get_login_page(self):
        url = _build_url(self.target, self.login_path)
        return send_request(url, method="GET", timeout=self.timeout)

    def _post_login(self, username, password):
        url = _build_url(self.target, self.login_path)
        data = {self.username_field: username, self.password_field: password}
        return send_request(url, method="POST", timeout=self.timeout, data=data)

    def _check_weak_password_policy(self):
        print_info("Checking password policy hints...")
        resp = self._get_login_page()
        if resp is None or not getattr(resp, "text", None):
            print_warning("Could not reach login page; skipping password policy check.")
            return

        html = resp.text
        minlength_match = re.search(r'minlength=["\']?(\d+)', html, re.IGNORECASE)
        has_pattern = re.search(r'pattern=["\']', html, re.IGNORECASE)

        if minlength_match:
            min_len = int(minlength_match.group(1))
            if min_len < 8:
                self._add_finding(
                    title="Weak Client-Side Password Length Requirement",
                    severity="Medium",
                    evidence=f"Form field enforces minlength={min_len} (< 8 characters).",
                    recommendation="Enforce a minimum password length of at least 8-12 "
                                   "characters, validated server-side.",
                )
        elif not has_pattern:
            self._add_finding(
                title="No Client-Side Password Complexity Indicators Found",
                severity="Low",
                evidence="No minlength/pattern attribute detected on password field; "
                         "server-side policy could not be verified remotely.",
                recommendation="Confirm server-side password policy enforces minimum "
                               "length, complexity, and rejects common/breached passwords.",
            )

    def _check_username_enumeration(self):
        print_info("Checking for username enumeration...")
        responses = {}
        for user in _PROBE_USERNAMES:
            resp = self._post_login(user, _FAKE_PASSWORD)
            if resp is None:
                continue
            responses[user] = {
                "status": resp.status_code,
                "length": len(resp.text or ""),
                "text": resp.text or "",
            }

        if len(responses) < 2:
            print_warning("Insufficient responses to compare for enumeration check.")
            return

        keys = list(responses.keys())
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                a, b = responses[keys[i]], responses[keys[j]]
                similarity = SequenceMatcher(None, a["text"], b["text"]).ratio()
                status_diff = a["status"] != b["status"]
                length_diff_pct = (
                    abs(a["length"] - b["length"]) / max(a["length"], b["length"], 1)
                )

                if status_diff or similarity < 0.85 or length_diff_pct > 0.15:
                    self._add_finding(
                        title="Possible Username Enumeration via Login Response",
                        severity="Medium",
                        evidence=(
                            f"'{keys[i]}' -> HTTP {a['status']}, {a['length']} bytes vs "
                            f"'{keys[j]}' -> HTTP {b['status']}, {b['length']} bytes "
                            f"(similarity {similarity:.2f})."
                        ),
                        recommendation="Return identical status codes, response length, "
                                       "and generic error messages regardless of whether "
                                       "the username exists.",
                    )
                    return

    def _check_login_response_differences(self):
        print_info("Comparing login response behaviour...")
        wrong_pw = self._post_login(_PROBE_USERNAMES[0], _FAKE_PASSWORD)
        empty_pw = self._post_login(_PROBE_USERNAMES[0], "")

        if wrong_pw is None or empty_pw is None:
            return

        if wrong_pw.status_code != empty_pw.status_code:
            self._add_finding(
                title="Inconsistent Login Error Handling",
                severity="Low",
                evidence=(
                    f"Wrong password -> HTTP {wrong_pw.status_code}; "
                    f"empty password -> HTTP {empty_pw.status_code}."
                ),
                recommendation="Normalize error handling and status codes across all "
                               "invalid-credential scenarios.",
            )

    def _check_account_lockout(self):
        print_info(f"Checking account lockout (max {self.max_lockout_attempts} probe attempts)...")
        user = _PROBE_USERNAMES[0]
        lockout_detected = False
        last_resp = None

        for attempt in range(1, self.max_lockout_attempts + 1):
            resp = self._post_login(user, f"{_FAKE_PASSWORD}-{attempt}")
            if resp is None:
                break
            last_resp = resp

            if resp.status_code == 429:
                lockout_detected = True
                break
            body = (resp.text or "").lower()
            if any(kw in body for kw in ["locked", "too many attempts", "try again later"]):
                lockout_detected = True
                break
            time.sleep(0.5)

        if lockout_detected:
            print_success("Account lockout / rate-limiting mechanism detected.")
        else:
            self._add_finding(
                title="No Account Lockout / Rate Limiting Detected",
                severity="High",
                evidence=(
                    f"{self.max_lockout_attempts} consecutive failed login attempts "
                    f"returned no lockout indicator "
                    f"(last status: {last_resp.status_code if last_resp else 'N/A'})."
                ),
                recommendation="Implement account lockout, exponential backoff, or "
                               "CAPTCHA after a small number of failed attempts.",
            )

    def _check_session_cookies(self):
        print_info("Analyzing session cookies...")
        resp = self._get_login_page()
        if resp is None:
            return

        cookies = resp.cookies if hasattr(resp, "cookies") else {}
        if not cookies:
            print_warning("No cookies observed on login page; skipping cookie analysis.")
            return

        for cookie in cookies:
            issues = []
            secure = getattr(cookie, "secure", False)
            httponly = "httponly" in str(getattr(cookie, "_rest", {})).lower() if hasattr(cookie, "_rest") else False
            samesite = getattr(cookie, "_rest", {}).get("SameSite") if hasattr(cookie, "_rest") else None

            if not secure and self.target.startswith("https"):
                issues.append("missing Secure flag")
            if not httponly:
                issues.append("missing HttpOnly flag")
            if not samesite:
                issues.append("missing SameSite attribute")

            entropy = self._shannon_entropy(cookie.value or "")
            if entropy < 3.0 and len(cookie.value or "") > 4:
                issues.append(f"low entropy value (~{entropy:.2f} bits/char, possibly predictable)")

            if issues:
                self._add_finding(
                    title=f"Session Cookie Weakness: '{cookie.name}'",
                    severity="Medium",
                    evidence=f"Cookie '{cookie.name}' issues: {', '.join(issues)}.",
                    recommendation="Set Secure, HttpOnly, and SameSite=Strict/Lax on all "
                                   "session cookies, and use a cryptographically secure "
                                   "session ID generator.",
                )

    @staticmethod
    def _shannon_entropy(s):
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())