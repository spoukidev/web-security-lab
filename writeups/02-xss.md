# Cross-Site Scripting (XSS)

## Overview

This local lab demonstrates reflected and stored XSS using a harmless alert and a SQLite database containing only fake local data. It contrasts unsafe HTML rendering with Jinja output encoding and a restrictive Content Security Policy (CSP).

## OWASP Classification

OWASP Top 10 2021: A03 — Injection.

## Affected Endpoint

`GET /comments?preview=<input>&mode=vulnerable` and `POST /comments`.

## Vulnerable Code

```jinja
<!-- INTENTIONALLY VULNERABLE -->
<!-- This code exists only for the local Web Security Lab. -->
{{ preview|safe }}
```

## Why It Is Vulnerable

The `safe` filter disables Jinja's automatic HTML escaping. Browser parsing therefore treats a submitted tag as markup and a submitted script tag as JavaScript rather than visible text.

## Lab Reproduction

For reflected XSS, open the comments lab in vulnerable mode and submit `<script>alert("XSS demonstration")</script>` as the preview. For stored XSS, submit the same harmless text in the comment form. The secure mode renders the tags literally and includes a CSP response header.

## Burp Suite Request

Capture only a localhost request in Burp Repeater:

```http
GET /comments?mode=vulnerable&preview=%3Cscript%3Ealert(%22XSS%20demonstration%22)%3C%2Fscript%3E HTTP/1.1
Host: 127.0.0.1:5000
```

Modified parameter: `preview`. To test stored behavior, intercept the local form's `body` parameter. Do not target third-party systems.

## Observed Result

Vulnerable mode sends an unescaped script tag in the HTML response, which the browser can execute. Secure mode encodes the angle brackets and returns a CSP header that restricts scripts to same-origin external files.

## Security Impact

XSS can cause actions in a victim's browser context, manipulate displayed content, or expose sensitive data when an application lacks other protections. This lab uses only a harmless alert and fake local data; it does not collect cookies or credentials.

## Root Cause

An explicit escape hatch (`safe`) was applied to untrusted data in an HTML context.

## Secure Implementation

```jinja
{{ preview }}
```

Jinja's default autoescaping encodes HTML-sensitive characters. The secure route also adds `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'` as defense in depth.

## Before vs After

Before, the browser receives user data as markup. After, the browser receives encoded text, so it has no script element to execute. CSP reduces impact but does not replace correct output encoding.

## Detection Techniques

Review template escape hatches such as `safe`, test request and stored fields with harmless markup, inspect responses for unencoded angle brackets, and use browser developer tools to confirm CSP headers.

## Mitigation

Use framework autoescaping by default, encode for the precise output context, avoid dangerous sinks, sanitize only when users genuinely need limited HTML, and deploy CSP as an additional control.

## Lessons Learned

Reflected XSS originates in a request and is immediately returned. Stored XSS persists in application data and can affect later viewers. Both require server-side output handling, not just client-side filtering.

## References

- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Top 10: Injection](https://owasp.org/Top10/A03_2021-Injection/)
