# SQL Injection

## Overview

This local lab demonstrates Boolean-based SQL injection against a SQLite table containing only deterministic fake users. It compares an unsafe string-built query with a parameterized alternative.

## OWASP Classification

OWASP Top 10 2021: A03 — Injection.

## Affected Endpoint

`GET /search?q=<input>&mode=vulnerable`

## Vulnerable Code

```python
# INTENTIONALLY VULNERABLE
# This code exists only for the local Web Security Lab.
statement = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{search_term}%' ORDER BY id"
rows = get_database().execute(statement).fetchall()
```

## Why It Is Vulnerable

The application places untrusted text directly in the SQL program. A quote can terminate the intended `LIKE` value and a Boolean expression can modify the `WHERE` clause.

## Lab Reproduction

First request `/search?q=alice&mode=vulnerable`; the lab returns Alice. Then submit the local Boolean demonstration input `' OR '1'='1' -- ` in vulnerable mode. The resulting predicate contains an always-true condition and returns all fake users. Repeat in secure mode to see no matching results.

## Burp Suite Request

Capture only a localhost request in Burp Repeater:

```http
GET /search?q=%27%20OR%20%271%27%3D%271%27%20--%20&mode=vulnerable HTTP/1.1
Host: 127.0.0.1:5000
```

Modified parameter: `q`. Do not target third-party systems.

## Observed Result

Vulnerable mode returns Alice, Bob, and Carol. Secure mode treats the same characters as a literal search value and returns no users.

## Security Impact

In a real application, SQL injection can bypass data filters, disclose records, or modify data according to the database account's privileges. This lab exposes only fake local data and provides no external database access.

## Root Cause

Dynamic SQL construction merged program syntax and untrusted data into one string.

## Secure Implementation

```python
statement = "SELECT id, username, email, role FROM users WHERE username LIKE ? ORDER BY id"
rows = get_database().execute(statement, (f"%{search_term}%",)).fetchall()
```

## Before vs After

Before, input was parsed as SQL syntax. After, SQL structure is fixed before the value is bound, so the driver sends the input as data.

## Detection Techniques

Review code for string interpolation or concatenation in database calls. Add tests containing quotes and Boolean payloads, use static analysis, and monitor database errors or unusual query result counts.

## Mitigation

Use parameterized queries for every value, validate inputs as a secondary control, avoid dynamic identifiers where possible, and enforce least-privilege database access.

## Lessons Learned

Escaping is fragile and database-specific. Parameter binding is the primary defense because it preserves the distinction between SQL code and user data.

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10: Injection](https://owasp.org/Top10/A03_2021-Injection/)
