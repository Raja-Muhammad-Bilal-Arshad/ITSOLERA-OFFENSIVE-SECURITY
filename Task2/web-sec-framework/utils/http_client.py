"""
http_client.py
--------------
Thin wrapper around requests.Session that centralizes:
  - custom User-Agent
  - custom headers
  - cookie support
  - proxy support (e.g. routing through Burp Suite)
  - timeout handling
  - basic retry-free error normalization

All modules should go through this client instead of calling requests
directly, so global options (set once from CLI args) apply everywhere.
"""

import requests
from requests.exceptions import RequestException

DEFAULT_UA = "WebSecFramework/1.0 (+internal-security-testing)"


class HttpClient:
    def __init__(self, user_agent=None, extra_headers=None, cookies=None,
                 proxy=None, timeout=10, verify_ssl=False):
        self.session = requests.Session()
        self.timeout = timeout
        self.session.verify = verify_ssl

        headers = {"User-Agent": user_agent or DEFAULT_UA}
        if extra_headers:
            headers.update(extra_headers)
        self.session.headers.update(headers)

        if cookies:
            self.session.cookies.update(cookies)

        if proxy:
            # e.g. {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
            # Passing a single string sets both http/https (handy for Burp Suite).
            if isinstance(proxy, str):
                self.session.proxies.update({"http": proxy, "https": proxy})
            else:
                self.session.proxies.update(proxy)

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        try:
            return self.session.request(method, url, **kwargs)
        except RequestException as exc:
            return HttpError(url, exc)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)


class HttpError:
    """Returned in place of a Response when a request fails, so modules can
    check `isinstance(resp, HttpError)` instead of catching exceptions everywhere."""

    def __init__(self, url, exc):
        self.url = url
        self.exc = exc
        self.ok = False
        self.status_code = None
        self.text = ""
        self.headers = {}

    def __repr__(self):
        return f"<HttpError url={self.url} error={self.exc}>"
