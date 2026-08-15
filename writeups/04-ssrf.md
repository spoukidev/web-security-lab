# Server-Side Request Forgery (SSRF)

## Overview

This Docker-only lab demonstrates how a server-side fetch feature can reach an internal service that is not directly published to the browser. The only vulnerable destination is a harmless internal mock service.

## OWASP Classification

OWASP Top 10 2021: A10 — Server-Side Request Forgery (SSRF).

## Affected Endpoint

`GET /fetch?url=http://internal-service:8000/&mode=vulnerable`

## Vulnerable Code

```python
# INTENTIONALLY VULNERABLE
# This code exists only for the local Web Security Lab.
if not is_controlled_lab_target(supplied_url):
    raise ValueError("Vulnerable mode is limited to the controlled lab service.")
status_code, result = fetch_limited(supplied_url)
```

## Why It Is Vulnerable

The route allows the requester to choose a server-side URL, turning Flask into a proxy to the Docker-network-only internal service. The lab deliberately constrains this behavior to the known mock target so it cannot be used against arbitrary systems.

## Lab Reproduction

Run `docker compose up --build` and request `/fetch?mode=vulnerable&url=http://internal-service:8000/`. Flask retrieves the mock's harmless JSON response. The browser cannot address the mock directly because Compose publishes no internal-service host port.

## Burp Suite Request

Capture only this localhost request in Burp Repeater:

```http
GET /fetch?mode=vulnerable&url=http://internal-service:8000/ HTTP/1.1
Host: 127.0.0.1:5000
```

Modified parameter: `url`. Do not replace the controlled hostname with external systems, private infrastructure, or metadata services.

## Observed Result

Vulnerable mode returns the mock internal service's JSON response. Secure mode rejects the same URL before fetching because it permits HTTPS, configured public hostnames, default port 443, and publicly routable resolved addresses only.

## Security Impact

In a real system, SSRF can let an attacker use a trusted server to access internal services, bypass network boundaries, or retrieve sensitive data. This lab has no external targeting, no cloud metadata demonstration, and only returns a harmless mock response.

## Root Cause

Untrusted URL selection was allowed to influence a server-side network request.

## Secure Implementation

```python
if parsed.scheme != "https" or parsed.hostname not in PUBLIC_FETCH_ALLOWLIST:
    raise ValueError("URL violates secure policy.")

for address in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM):
    if not ipaddress.ip_address(address[4][0]).is_global:
        raise ValueError("Non-public address blocked.")
```

The secure fetcher also disables redirects, uses a two-second timeout, and caps response bodies at 64 KiB.

## Before vs After

Before, a user could induce a request to the internal mock service. After, the internal host is rejected at scheme and hostname validation, before DNS resolution or a network request.

## Detection Techniques

Review code for user-controlled URL fetches, test allowed URL schemes and hostnames, monitor DNS and egress activity, and add regression tests for loopback, private, reserved, redirect, timeout, and oversized-response behavior.

## Mitigation

Use strict URL and hostname allowlists, allow only necessary schemes and ports, resolve and reject non-public addresses, disable redirects, set short timeouts and size limits, and enforce egress controls at the network layer.

## Lessons Learned

URL validation alone is insufficient. Robust SSRF defenses validate the parsed URL, the hostname, the resolved address, and every subsequent request hop while also limiting what the application can reach at the network layer.

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10: SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
