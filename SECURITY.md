# Security Policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose uploaded artifacts, rule content, host files or remote users.

After the repository is published, use GitHub private vulnerability reporting from the repository Security tab. Include:

- affected version or commit;
- deployment topology;
- minimal reproduction steps;
- expected impact;
- suggested remediation, if known.

Do not include live malware, credentials, personal data or third-party confidential material. Use a harmless fixture whenever possible.

## Deployment boundary

C2 Signal is an analyst tool, not a hardened internet-facing sandbox.

- The API currently has no authentication.
- Uploaded files are passed to third-party parsers.
- Rule-management endpoints can change active local YARA content.
- `0.0.0.0` binding must be protected by a firewall or authenticated reverse proxy.
- Never mount the Docker socket, host secrets or production credentials.
- Use an isolated host or VM and block scanner egress for higher-risk workloads.

## Supported versions

The current supported line is `v0.1.x` and the `main` branch. Older pre-release snapshots are unsupported.
