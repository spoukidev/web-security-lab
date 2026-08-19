# Cross-Site Request Forgery (CSRF)

## Overview

This local lab demonstrates a forged state-changing request against a fake email-change endpoint. It compares an unprotected form handler with a session-bound CSRF token and Origin/Referer validation.

## OWASP Classification

OWASP Top 10 2021: A01 — Broken Access Control.

## Affected Endpoint

`POST /change-email?mode=vulnerable`

## Vulnerable Code

```python
# INTENTIONALLY VULNERABLE
# This code exists only for the local Web Security Lab.
get_database().execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user["id"]))
```

## Why It Is Vulnerable

The handler changes state when a browser sends an authenticated request but does not require evidence that the request originated from the application’s own form. A cross-origin form can cause a browser to submit cookies automatically in some configurations.

## Lab Reproduction

Issue a fake local token at `/login`, then open the harmless local form in `exploits/csrf/local-form.html` and submit it to the vulnerable endpoint. The fake email changes. Repeat using secure mode: the request lacks the session-bound token and same-origin metadata, so it is rejected.

## Burp Suite Request

Capture only a localhost request after a fake local login:

```http
POST /change-email?mode=vulnerable HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<local-lab-session>
Content-Type: application/x-www-form-urlencoded

email=changed-by-local-csrf%40example.test
```

In secure mode, removing or altering `csrf_token` must produce a rejection. Do not use third-party sites or real accounts.

## Observed Result

Vulnerable mode changes the fake email without a token. Secure mode requires a token that matches the user’s session and an Origin or Referer matching the current host.

## Security Impact

CSRF can cause a victim’s browser to perform unwanted actions such as changing contact details, submitting forms, or altering settings. This lab affects only deterministic fake accounts.

## Root Cause

The server relied on cookie-based session context but did not verify request intent.

## Secure Implementation

Secure mode uses a synchronizer token stored in the session and a hidden form field, validates it with constant-time comparison, checks Origin/Referer, and sets Flask session cookies to `HttpOnly` and `SameSite=Lax`.

## Before vs After

Before, any request carrying the session cookie could change state. After, the request must also contain an unpredictable per-session token and originate from the trusted host.

## Detection Techniques

Identify state-changing endpoints, submit them from a separate origin, remove CSRF fields, and inspect cookie SameSite settings. Automate negative tests for missing, malformed, and cross-origin tokens.

## Mitigation

Use synchronizer or double-submit tokens where appropriate, set SameSite cookie attributes, validate Origin/Referer for sensitive requests, and avoid state-changing GET endpoints.

## Lessons Learned

CSRF defenses establish request intent for cookie-authenticated actions. They complement, rather than replace, authentication, authorization, and XSS defenses.

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
