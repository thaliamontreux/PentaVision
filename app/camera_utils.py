from __future__ import annotations

from typing import Optional
from urllib.parse import quote, urlparse, urlunparse

from .models import CameraDevice, CameraUrlPattern


def build_camera_url(
    device: CameraDevice,
    pattern: Optional[CameraUrlPattern],
) -> Optional[str]:
    base_url: Optional[str]
    if pattern is not None and pattern.rtsp_url_pattern:
        base_url = pattern.rtsp_url_pattern
    else:
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
    channel = "1"
    stream = "0"

    url = str(base_url)
    pattern_use_auth_raw = getattr(pattern, "use_auth", None) if pattern is not None else None
    pattern_use_auth = True if pattern_use_auth_raw is None else bool(pattern_use_auth_raw)
    replacements = {
        "<IP>": ip_value,
        "<PORT>": str(port_value),
        "<CHANNEL>": channel,
        "<STREAM>": stream,
        "<STREAM#>": stream,
    }

    has_cred_tokens = "<USERNAME>" in url or "<PASSWORD>" in url
    if has_cred_tokens:
        if not username or not password:
            return None
        replacements["<USERNAME>"] = username
        replacements["<PASSWORD>"] = password

    for token, value in replacements.items():
        url = url.replace(token, value)

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
