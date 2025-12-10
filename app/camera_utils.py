from __future__ import annotations

from typing import Optional
from urllib.parse import quote, urlparse, urlunparse
import json
import re

from .models import CameraDevice, CameraUrlPattern


def build_camera_url(
    device: CameraDevice,
    pattern: Optional[CameraUrlPattern],
) -> Optional[str]:
    base_url: Optional[str]
    if pattern is not None and pattern.rtsp_url_pattern:
        base_url = pattern.rtsp_url_pattern
    else:
        # Fallback: build a simple rtsp:// URL from the device settings.
        ip = getattr(device, "ip_address", None)
        if not ip:
            return None
        port = getattr(device, "port", None)
        username = getattr(device, "username", None)
        password = getattr(device, "password", None)

        netloc = ip if not port else f"{ip}:{port}"

        if username:
            user_part = quote(str(username), safe="")
            if password:
                pass_part = quote(str(password), safe="")
                return f"rtsp://{user_part}:{pass_part}@{netloc}"
            return f"rtsp://{user_part}@{netloc}"

        return f"rtsp://{netloc}"

    ip_value = getattr(device, "ip_address", None)
    if not ip_value:
        return None

    port_value = getattr(device, "port", None) or 554
    username = getattr(device, "username", None)
    password = getattr(device, "password", None)

    url = str(base_url)

    pattern_use_auth_raw = getattr(pattern, "use_auth", None) if pattern is not None else None
    pattern_use_auth = True if pattern_use_auth_raw is None else bool(pattern_use_auth_raw)

    # Decode per-camera pattern parameters, if any.
    params_raw = getattr(device, "pattern_params", None)
    extra_params = {}
    if params_raw:
        try:
            extra_params = json.loads(params_raw)
            if not isinstance(extra_params, dict):
                extra_params = {}
        except Exception:  # noqa: BLE001
            extra_params = {}

    def _pick_param(names, default: str) -> str:
        for name in names:
            if name in extra_params and extra_params[name]:
                return str(extra_params[name])
        return default

    # Apply stream/channel selections, falling back to legacy defaults.
    channel = _pick_param(["channel", "CHANNEL"], "1")
    stream = _pick_param(["stream", "STREAM"], "0")

    # Angle-bracket token replacements.
    replacements = {
        "<IP>": ip_value,
        "<PORT>": str(port_value),
        "<CHANNEL>": channel,
        "<STREAM>": stream,
        "<STREAM#>": stream,
    }

    for key, val in extra_params.items():
        if not val:
            continue
        token = f"<{key}>"
        replacements[token] = str(val)

    has_cred_angle = "<USERNAME>" in url or "<PASSWORD>" in url
    if has_cred_angle:
        if not username or not password or not pattern_use_auth:
            return None
        replacements["<USERNAME>"] = username
        replacements["<PASSWORD>"] = password

    for token, value in replacements.items():
        url = url.replace(token, value)

    # Mustache-style {{token}} replacements, used by paths.csv-derived patterns.
    mustache_values: dict[str, str] = {}

    # Generic extra parameters, including any custom tokens.
    for key, val in extra_params.items():
        if not val:
            continue
        mustache_values.setdefault(str(key), str(val))

    # Ensure stream/channel are always available for {{stream}} / {{channel}}.
    mustache_values.setdefault("stream", stream)
    mustache_values.setdefault("channel", channel)
    mustache_values.setdefault("STREAM", stream)
    mustache_values.setdefault("CHANNEL", channel)

    # IP/port tokens (if a pattern decides to keep them in the path/query).
    mustache_values.setdefault("ip", ip_value)
    mustache_values.setdefault("ip_address", ip_value)
    if port_value:
        mustache_values.setdefault("port", str(port_value))

    # Credential-related mustache tokens.
    has_cred_mustache = bool(
        re.search(r"\{\{\s*username\s*\}\}", url, re.IGNORECASE)
        or re.search(r"\{\{\s*password\s*\}\}", url, re.IGNORECASE)
    )
    has_cred_tokens = has_cred_angle or has_cred_mustache

    if has_cred_tokens and (not username or not password or not pattern_use_auth):
        return None

    if pattern_use_auth and username:
        mustache_values.setdefault("username", quote(str(username), safe=""))
    if pattern_use_auth and password:
        mustache_values.setdefault("password", quote(str(password), safe=""))

    def _replace_mustache(text: str) -> str:
        def _repl(match: "re.Match") -> str:  # type: ignore[type-arg]
            name = match.group(1)
            if not name:
                return match.group(0)
            key = str(name)
            if key in mustache_values:
                return mustache_values[key]
            return match.group(0)

        return re.sub(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", _repl, text)

    url = _replace_mustache(url)

    # Literal 'username' / 'password' segments in patterns (existing behaviour).
    if pattern_use_auth and username:
        url = url.replace("'username'", f"'{quote(str(username), safe='')}'")
    if pattern_use_auth and password:
        url = url.replace("'password'", f"'{quote(str(password), safe='')}'")

    lower = url.lower()
    if "://" not in lower:
        path = url or "/"
        if not path.startswith("/"):
            path = "/" + path

        netloc = ip_value
        if port_value:
            netloc = f"{netloc}:{port_value}"

        if username and not has_cred_tokens and pattern_use_auth:
            user_part = quote(str(username), safe="")
            if password:
                pass_part = quote(str(password), safe="")
                netloc = f"{user_part}:{pass_part}@{netloc}"
            else:
                netloc = f"{user_part}@{netloc}"

        return f"rtsp://{netloc}{path}"

    # If the pattern did not use credential placeholders but the device has
    # credentials, inject them into the URL's userinfo section, preserving
    # any existing host/port/path/query.
    if username and not has_cred_tokens and pattern_use_auth:
        parsed = urlparse(url)
        # Do not overwrite explicit userinfo embedded in the pattern.
        if not parsed.username and not parsed.password and parsed.netloc:
            user_part = quote(str(username), safe="")
            netloc = parsed.netloc
            if password:
                pass_part = quote(str(password), safe="")
                netloc = f"{user_part}:{pass_part}@{netloc}"
            else:
                netloc = f"{user_part}@{netloc}"
            url = urlunparse(parsed._replace(netloc=netloc))

    return url

