# Phase 9 Security Review

## Scope

This review checks the final local-lab boundaries and confirms that deliberate vulnerabilities remain labelled, paired with remediation, and constrained to fake data.

## Findings

| Area | Result | Control |
| --- | --- | --- |
| Network exposure | Pass | Local process binds to loopback; Compose publishes only `127.0.0.1:5000`. |
| SSRF scope | Pass | Vulnerable mode allows only the Docker-only mock; secure mode validates scheme, host, resolved IP, redirects, timeout, and response size. |
| Upload safety | Pass | Files are constrained to harmless formats, stored outside static paths, and never executed. |
| Fake data | Pass | Seed users use only `example.test` addresses and fake profiles. |
| Vulnerability labelling | Pass | Each intentionally weak path includes a local-lab warning and has a secure alternative. |
| Test suite | Pass | pytest covers startup and vulnerable/secure comparisons for all labs. |

## Remaining operational checks

Run the following on a developer machine with Docker Compose installed:

```bash
docker compose up --build
```

Then verify the dashboard at `http://127.0.0.1:5000`, confirm the internal service has no published host port, and exercise the SSRF mock only through `/fetch`.

## Conclusion

The application is appropriate as a deliberately vulnerable, local-only portfolio laboratory. It is not a production security baseline.
