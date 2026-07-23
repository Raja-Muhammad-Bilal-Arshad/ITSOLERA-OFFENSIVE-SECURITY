import re

from utils.request_handler import send_request
from utils.helpers import print_info, print_success, print_warning, print_error

_BACKUP_SUFFIXES = [
    ".bak", ".old", ".orig", ".save", ".swp", "~", ".zip", ".tar.gz",
    ".sql", ".sql.gz", ".copy", ".backup",
]

_COMMON_ROOT_FILES = ["index", "config", "settings", "database", "db",
                       "app", "backup", "site", "wp-config"]

_CONFIG_FILE_PATHS = [
    ".env", "config.php", "configuration.php", "web.config", "wp-config.php",
    "config.yml", "config.yaml", "settings.py", ".env.local", ".env.production",
    "appsettings.json", "database.yml",
]

_PHPINFO_PATHS = ["phpinfo.php", "info.php", "test.php", "php_info.php"]

_DIRECTORY_LISTING_MARKERS = [
    "index of /", "directory listing for", "<title>index of",
]


def _build_url(target, path):
    target = target.rstrip("/")
    path = (path or "").lstrip("/")
    return f"{target}/{path}" if path else target


class InformationDisclosureModule:
    """Module 5: detects exposed sensitive resources on the target."""

    name = "Information Disclosure"

    def __init__(self, target, timeout=20, common_dirs=None, headers=None, cookies=None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.common_dirs = common_dirs or ["", "backup", "backups", "uploads",
                                            "files", "assets", "old", "test"]
        # --- Additional Features: custom headers / cookies / User-Agent ---
        self.custom_headers = headers or {}
        self.custom_cookies = cookies or {}
        self.findings = []

    def _request_kwargs(self):
        """Builds extra kwargs (custom headers/cookies) to pass into send_request."""
        kwargs = {}
        if self.custom_headers:
            kwargs["headers"] = self.custom_headers
        if self.custom_cookies:
            kwargs["cookies"] = self.custom_cookies
        return kwargs

    def run(self):
        print_info(f"[Module 5] Starting Information Disclosure scan on {self.target}")
        self._check_robots_and_sitemap()
        self._check_git_exposure()
        self._check_backup_files()
        self._check_phpinfo()
        self._check_directory_listing()
        self._check_exposed_config_files()
        print_success(f"[Module 5] Completed with {len(self.findings)} finding(s)")
        return self.findings

    def _add_finding(self, title, severity, evidence, recommendation):
        self.findings.append({
            "module": self.name,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    def _get(self, path):
        url = _build_url(self.target, path)
        return send_request(url, method="GET", timeout=self.timeout, **self._request_kwargs())

    def _exists(self, resp):
        return resp is not None and resp.status_code == 200

    def _check_robots_and_sitemap(self):
        print_info("Checking robots.txt and sitemap.xml...")
        for path, label in [("robots.txt", "robots.txt"), ("sitemap.xml", "sitemap.xml")]:
            resp = self._get(path)
            if self._exists(resp):
                disallowed = re.findall(r"Disallow:\s*(\S+)", resp.text or "", re.IGNORECASE) \
                    if label == "robots.txt" else []
                evidence = f"{label} accessible at {self.target}/{path} (HTTP 200)."
                if disallowed:
                    evidence += f" Discloses {len(disallowed)} disallowed path(s), e.g. {disallowed[:5]}."
                self._add_finding(
                    title=f"{label} Present",
                    severity="Info",
                    evidence=evidence,
                    recommendation="Not a vulnerability by itself, but review disclosed "
                                   "paths to ensure no sensitive/admin routes are hinted at.",
                )

    def _check_git_exposure(self):
        print_info("Checking for exposed .git directory...")
        resp = self._get(".git/HEAD")
        if self._exists(resp) and "ref:" in (resp.text or "").lower():
            self._add_finding(
                title="Exposed .git Directory",
                severity="Critical",
                evidence=f"{self.target}/.git/HEAD is publicly accessible and returns a "
                         f"valid git ref, indicating the full repository may be downloadable.",
                recommendation="Remove the .git directory from the web root, or block "
                               "access to it at the web server level.",
            )

    def _check_backup_files(self):
        print_info("Checking for common backup files...")
        found = []
        for base in _COMMON_ROOT_FILES:
            for suffix in _BACKUP_SUFFIXES:
                path = f"{base}{suffix}"
                resp = self._get(path)
                if self._exists(resp) and len(resp.content or b"") > 0:
                    found.append(path)

        if found:
            self._add_finding(
                title="Exposed Backup File(s)",
                severity="High",
                evidence=f"Accessible backup file(s): {', '.join(found[:10])}"
                         + (f" (+{len(found) - 10} more)" if len(found) > 10 else ""),
                recommendation="Remove backup/temporary files from web-accessible "
                               "directories; store backups outside the web root.",
            )

    def _check_phpinfo(self):
        print_info("Checking for exposed phpinfo() pages...")
        for path in _PHPINFO_PATHS:
            resp = self._get(path)
            if self._exists(resp) and "phpinfo()" in (resp.text or "").lower():
                self._add_finding(
                    title="Exposed phpinfo() Page",
                    severity="Medium",
                    evidence=f"{self.target}/{path} reveals PHP configuration details.",
                    recommendation="Remove phpinfo() pages from production environments.",
                )
                return

    def _check_directory_listing(self):
        print_info("Checking for directory listing...")
        for d in self.common_dirs:
            resp = self._get(d)
            if resp is None or resp.status_code != 200:
                continue
            body = (resp.text or "").lower()
            if any(marker in body for marker in _DIRECTORY_LISTING_MARKERS):
                self._add_finding(
                    title="Directory Listing Enabled",
                    severity="Medium",
                    evidence=f"Directory listing observed at {self.target}/{d or ''}.",
                    recommendation="Disable directory listing/indexing on the web server.",
                )

    def _check_exposed_config_files(self):
        print_info("Checking for exposed configuration files...")
        found = []
        for path in _CONFIG_FILE_PATHS:
            resp = self._get(path)
            if self._exists(resp) and len(resp.content or b"") > 5:
                found.append(path)

        if found:
            self._add_finding(
                title="Exposed Configuration File(s)",
                severity="Critical",
                evidence=f"Accessible configuration file(s): {', '.join(found)}. These "
                         f"may contain database credentials, API keys, or secrets.",
                recommendation="Move configuration files outside the web root and rotate "
                               "any exposed credentials.",
            )
