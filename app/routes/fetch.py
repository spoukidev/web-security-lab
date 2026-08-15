"""Controlled SSRF lab routes that never target arbitrary systems."""
from __future__ import annotations
import ipaddress
import socket
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from flask import Blueprint, render_template, request

blueprint = Blueprint("fetch", __name__)
FetchMode = Literal["vulnerable", "secure"]
LAB_INTERNAL_HOSTS = frozenset({"internal-service", "127.0.0.1", "localhost"})
PUBLIC_FETCH_ALLOWLIST = frozenset({"docs.security-lab.example"})
FETCH_TIMEOUT_SECONDS = 2
MAX_RESPONSE_BYTES = 65_536


class NoRedirect(HTTPRedirectHandler):
    """Reject redirects instead of following a potentially unsafe second URL."""
    def redirect_request(self, *_: object, **__: object) -> None:
        return None


def parse_url(value: str):
    """Parse a URL and turn parser errors into a safe lab error."""
    try:
        return urlsplit(value)
    except ValueError as error:
        raise ValueError("The URL is malformed.") from error


def is_controlled_lab_target(value: str) -> bool:
    """Allow the intentionally vulnerable path to reach only the lab mock service."""
    try:
        parsed = parse_url(value)
        return (
            parsed.scheme == "http"
            and parsed.hostname in LAB_INTERNAL_HOSTS
            and parsed.port in (None, 8000)
            and not parsed.username
            and not parsed.password
        )
    except ValueError:
        return False


def ensure_secure_target(value: str) -> None:
    """Apply layered SSRF defenses before any outbound request is attempted."""
    parsed = parse_url(value)
    if parsed.scheme != "https":
        raise ValueError("Secure mode permits HTTPS only.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Secure mode requires a plain hostname with no user info.")
    if parsed.hostname not in PUBLIC_FETCH_ALLOWLIST:
        raise ValueError("Hostname is not on the secure public allowlist.")
    if parsed.port not in (None, 443):
        raise ValueError("Secure mode permits the default HTTPS port only.")

    resolved_addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    if not resolved_addresses:
        raise ValueError("Hostname did not resolve.")
    for address in resolved_addresses:
        resolved_ip = ipaddress.ip_address(address[4][0])
        if not resolved_ip.is_global:
            raise ValueError("Secure mode blocks private, loopback, and reserved addresses.")


def fetch_limited(url: str) -> tuple[int, str]:
    """Fetch once, reject redirects, and cap both time and response size."""
    opener = build_opener(NoRedirect())
    request_object = Request(url, headers={"User-Agent": "WebSecurityLab/1.0"})
    try:
        with opener.open(request_object, timeout=FETCH_TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("Response exceeded the 64 KiB lab limit.")
            return response.status, body.decode("utf-8", errors="replace")
    except HTTPError as error:
        if 300 <= error.code < 400:
            raise ValueError("Redirects are blocked in this lab.") from error
        raise ValueError(f"The controlled service returned HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError) as error:
        raise ValueError("The selected service could not be reached.") from error


@blueprint.get("/fetch")
def fetch() -> str:
    """Render the SSRF lab; requests are constrained before they leave Flask."""
    supplied_url = request.args.get("url", "http://internal-service:8000/")
    mode: FetchMode = "secure" if request.args.get("mode") == "secure" else "vulnerable"
    result: str | None = None
    status_code: int | None = None
    error_message: str | None = None
    if "url" in request.args:
        try:
            if mode == "vulnerable":
                # INTENTIONALLY VULNERABLE
                # This code exists only for the local Web Security Lab.
                # It permits a user to induce a request to the Docker-only internal mock.
                if not is_controlled_lab_target(supplied_url):
                    raise ValueError("Vulnerable mode is limited to the controlled lab service.")
            else:
                ensure_secure_target(supplied_url)
            status_code, result = fetch_limited(supplied_url)
        except ValueError as error:
            error_message = str(error)
    return render_template("fetch.html", mode=mode, supplied_url=supplied_url,
                           result=result, status_code=status_code, error_message=error_message)
