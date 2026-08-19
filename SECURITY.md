# Security and Responsible Use

`web-security-lab` intentionally contains constrained vulnerable code for education. Run it only on your own machine or an explicitly authorized local environment.

## Scope boundaries

- The normal Flask process binds to `127.0.0.1`.
- Docker publishes only `127.0.0.1:5000`.
- The SSRF exercise is restricted to the Docker-network-only mock service and rejects arbitrary targets.
- Uploads accept only harmless test formats and are never executed or served publicly.
- All records and accounts are deterministic fake data.

## Reporting a project issue

If you find behavior that can escape these local-lab boundaries, please open a private security advisory on the repository rather than publishing exploitation details. Include the affected route, reproduction using the local lab only, impact, and suggested mitigation.

## Not in scope

The project must not be used for attacks against third-party systems, credential harvesting, malware, persistence, destructive payloads, or external attack automation.
