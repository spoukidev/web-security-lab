# Insecure Direct Object Reference (IDOR)

## Overview

This local lab demonstrates an IDOR by changing the profile identifier in a URL while the simulated actor remains Alice. It compares a route that loads any requested profile with one that performs a server-side ownership check.

## OWASP Classification

OWASP Top 10 2021: A01 — Broken Access Control.

## Affected Endpoint

`GET /profile/<user_id>?mode=vulnerable`

## Vulnerable Code

```python
# INTENTIONALLY VULNERABLE
# This code exists only for the local Web Security Lab.
return render_template("profile.html", mode=mode, actor=actor, profile=profile_row)
```

## Why It Is Vulnerable

The application loads the object identified in the path but does not verify that the current actor is entitled to access that object. An identifier is a locator, not proof of authorization.

## Lab Reproduction

Select Alice (User A) in the fake actor selector and request `/profile/1`. Change only the path to `/profile/2` with vulnerable mode selected. Bob's fake profile is returned. Switch to secure mode and repeat: the server responds with `403 Forbidden` without profile data.

## Burp Suite Request

Capture only a localhost request in Burp Repeater after selecting Alice in the lab:

```http
GET /profile/2?mode=vulnerable HTTP/1.1
Host: 127.0.0.1:5000
Cookie: session=<local-lab-session>
```

Modified parameter: the path identifier, from `1` to `2`. Do not use this process against third-party systems.

## Observed Result

Vulnerable mode returns Bob's fake profile even though Alice is the selected actor. Secure mode denies the same request because the actor ID and object owner ID differ.

## Security Impact

Missing object authorization can expose or permit modification of other users' records. The lab contains only deterministic fake profile data and does not implement real authentication in this phase.

## Root Cause

The server trusted the direct object reference without enforcing a relationship between the requesting identity and the requested object.

## Secure Implementation

```python
if actor_id != user_id:
    return render_template("profile.html", mode=mode, actor=actor, profile=None), 403
```

## Before vs After

Before, any existing profile ID was readable. After, the server verifies ownership for every profile request before rendering data.

## Detection Techniques

Create at least two accounts, request an owned object, then change only the object identifier. Add authorization tests for read, update, delete, export, and administrative operations.

## Mitigation

Enforce authorization server-side for every object access, scope database lookups to the authenticated user's permitted objects, and apply least privilege. Random identifiers are defense in depth, never a replacement for authorization.

## Lessons Learned

Authentication answers who is requesting access. Authorization answers whether that identity may access a particular object. Both are necessary.

## References

- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [OWASP Top 10: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
