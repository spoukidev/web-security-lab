# Insecure File Upload

## Overview

This local lab contrasts trusting a submitted filename and MIME type with layered validation of harmless text and image uploads. Files are never executed or served from web-accessible directories.

## OWASP Classification

OWASP Top 10 2021: A04 — Insecure Design.

## Affected Endpoint

`POST /upload`.

## Vulnerable Code

```python
# INTENTIONALLY VULNERABLE
# This code exists only for the local Web Security Lab.
if extension not in ALLOWED_EXTENSIONS or upload.mimetype not in {"text/plain", "image/png", "image/jpeg"}:
    raise ValueError("Vulnerable mode permits only harmless files.")
```

## Why It Is Vulnerable

Filename extensions and client-provided MIME types are metadata that a requester controls. They do not establish the content's true type.

## Lab Reproduction

Upload a harmless UTF-8 text file named `notes.png` with declared MIME type `image/png`. Vulnerable mode accepts it based on its metadata. Secure mode reads the bytes and rejects it because the PNG signature is missing.

## Burp Suite Request

Intercept a localhost multipart request to `POST /upload`, modify only the local filename or `Content-Type` field for a harmless text body, and compare modes. Do not upload executables, malware, or files to third-party services.

## Observed Result

Vulnerable mode stores allowed-name/MIME combinations without checking bytes. Secure mode requires allowed extensions, expected MIME, UTF-8 text or matching image signature, size under 1 MiB, and a random server-generated name.

## Security Impact

Weak validation can enable dangerous content to reach a server or web-accessible path. This lab constrains files to harmless extensions, keeps them outside static directories, and never executes them.

## Root Cause

The server treated user-supplied metadata as proof of file type.

## Secure Implementation

Secure validation checks extensions, MIME, magic bytes for PNG/JPEG, UTF-8 for text, 1 MiB size, generated filenames, non-public storage, and `0600` permissions.

## Before vs After

Before, content was accepted based on claims. After, the server verifies its expected characteristics and controls storage independently from input.

## Detection Techniques

Test mismatched extension, MIME, and file signature combinations; review public/static upload paths; inspect filesystem permissions; and monitor uploads for unexpected formats or size spikes.

## Mitigation

Allowlist types, validate content bytes, generate names, enforce size limits, store outside executable/public paths, scan where appropriate, and serve downloads with safe disposition and content types.

## Lessons Learned

File validation is defense in depth. No single property—extension, MIME, or magic bytes—is sufficient by itself.

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Top 10: Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
