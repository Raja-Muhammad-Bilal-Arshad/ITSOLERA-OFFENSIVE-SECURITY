
import re
from urllib.parse import urlparse, parse_qs, urljoin

_FORM_RE = re.compile(r'<form\b[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_FORM_ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_TAG_RE = re.compile(r'<(input|textarea|select)\b[^>]*>', re.IGNORECASE)
_NAME_ATTR_RE = re.compile(r'name=["\']([^"\']+)["\']', re.IGNORECASE)
_VALUE_ATTR_RE = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)
_TYPE_ATTR_RE = re.compile(r'type=["\']([^"\']*)["\']', re.IGNORECASE)

# Input types we should not overwrite with payloads (they won't reflect
# text meaningfully and submitting garbage into them is pointless/unsafe).
_SKIP_TYPES = {"submit", "button", "reset", "file", "image", "checkbox", "radio"}


def discover_get_params(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: (v[0] if v else "test") for k, v in qs.items()}


def discover_forms(html, base_url):
    forms = []
    if not html:
        return forms

    for match in _FORM_RE.finditer(html):
        form_html = match.group(0)

        action_match = _FORM_ACTION_RE.search(form_html)
        method_match = _FORM_METHOD_RE.search(form_html)
        action = action_match.group(1) if action_match else ""
        method = (method_match.group(1) if method_match else "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"

        params = {}
        for input_match in _INPUT_TAG_RE.finditer(form_html):
            tag = input_match.group(0)
            type_match = _TYPE_ATTR_RE.search(tag)
            field_type = type_match.group(1).lower() if type_match else "text"
            if field_type in _SKIP_TYPES:
                continue

            name_match = _NAME_ATTR_RE.search(tag)
            if not name_match:
                continue
            name = name_match.group(1)

            value_match = _VALUE_ATTR_RE.search(tag)
            default_value = value_match.group(1) if value_match else "test"
            params[name] = default_value

        if params:
            forms.append({
                "action": _resolve_action(base_url, action),
                "method": method,
                "params": params,
            })

    return forms


def _resolve_action(base_url, action):
    if not action:
        return base_url
    if action.startswith("http://") or action.startswith("https://"):
        return action
    return urljoin(base_url, action)