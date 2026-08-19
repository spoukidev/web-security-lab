# JWT / Authentication Flaw

## Overview

This local lab contrasts JWT-shaped tokens signed with a publicly documented weak lab secret against a secure mode that requires a strong secret and validates fixed algorithm, expiration, issuer, and audience claims.

## OWASP Classification

OWASP Top 10 2021: A07 — Identification and Authentication Failures.

## Affected Endpoint

`POST /login` and `POST /token/inspect`.

## Vulnerable Code

```python
# INTENTIONALLY VULNERABLE
# This code exists only for the local Web Security Lab.
WEAK_LAB_SECRET = "lab-weak-secret"
# Vulnerable mode validates a signature only and skips claims.
```

## Why It Is Vulnerable

A known weak signing secret permits anyone with access to the lab source to create a valid HMAC signature. Skipping expiration, issuer, and audience checks also accepts tokens outside their intended context.

## Lab Reproduction

Issue a fake Alice token in vulnerable mode, then validate it. Compare it with secure mode, where the token contains a 15-minute expiry plus issuer and audience and must pass all checks.

## Burp Suite Request

Intercept a local `POST /token/inspect` request and modify only the local `token` field. Observe the validation response in each mode. Do not send tokens to third-party services.

## Observed Result

Vulnerable mode accepts a correctly signed token using the documented weak local secret regardless of contextual claims. Secure mode rejects invalid algorithms, expired tokens, and issuer/audience mismatches.

## Security Impact

In a real application, weak JWT validation can let attackers impersonate users or retain access after tokens should be invalid. The lab covers fake accounts only.

## Root Cause

The token verifier did not establish a trustworthy signing key or validate required claims.

## Secure Implementation

Secure mode uses a random or environment-supplied secret, pins `HS256`, verifies HMAC signatures in constant time, and requires `exp`, `iss`, and `aud`. Flask session cookies are configured `HttpOnly` and `SameSite=Lax`, with `Secure` enabled when `LAB_HTTPS=true`.

## Before vs After

Before, a known key and incomplete validation made identity assertions unreliable. After, only tokens from the intended issuer, audience, time window, and signing key are accepted.

## Detection Techniques

Review token verification for hard-coded or weak keys, missing algorithm restrictions, absent expiration checks, and missing issuer/audience validation. Add negative tests for every claim.

## Mitigation

Use high-entropy rotatable signing keys, allow only expected algorithms, verify all required claims, use short expirations, and enforce authorization separately for every protected object.

## Lessons Learned

JWT validation establishes identity; it does not replace authorization. A valid token must still be subject to server-side access-control checks.

## References

- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Top 10: Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
