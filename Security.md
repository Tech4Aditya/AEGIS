# Security Policy

## AEGIS – JIIT Autonomous Cyber Defense Dashboard

AEGIS is designed as an autonomous cyber defense dashboard for monitoring security incidents, analyzing threats, managing security policies, and supporting incident response.

We take security seriously and welcome responsible reports of vulnerabilities.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest / Main | ✅ Yes |
| Older versions | ❌ No |

Security updates will primarily be provided for the latest version available in the repository.

---

## Reporting a Vulnerability

If you discover a security vulnerability in AEGIS, please report it responsibly.

### Please do not

- Publicly disclose the vulnerability before it has been reviewed.
- Exploit vulnerabilities against systems or users.
- Access, modify, or delete data that does not belong to you.
- Perform denial-of-service attacks.
- Share credentials, API keys, tokens, or other sensitive information in public issues.

### How to Report

For security-sensitive issues, please contact the project maintainers privately.

When reporting a vulnerability, please include:

1. A clear description of the vulnerability.
2. The affected component or file.
3. Steps to reproduce the issue.
4. Potential security impact.
5. Screenshots or logs, if applicable.
6. A suggested mitigation, if you have one.

---

## Security Considerations

AEGIS may process security-related information such as:

- Security incidents
- Host information
- Indicators of compromise (IOCs)
- Security policies
- Agent information
- Investigation data
- Approval and response actions

Users should avoid storing real credentials, passwords, private keys, authentication tokens, or other sensitive personal information in the repository.

---

## API Security

The AEGIS backend exposes API endpoints used by the dashboard.

Deployments should ensure that:

- Authentication and authorization are properly configured.
- Sensitive API endpoints are not publicly exposed without protection.
- Input received from clients is validated and sanitized.
- API errors do not expose sensitive implementation details.
- Rate limiting is considered for publicly accessible deployments.
- HTTPS should be used in production environments.

---

## Secrets and Credentials

Never commit sensitive credentials to GitHub.

Examples include:

- API keys
- Passwords
- Access tokens
- Private keys
- Database credentials
- Cloud credentials
- Authentication secrets

Use environment variables or a secure secrets-management system instead.

If a secret is accidentally committed, it should be revoked and replaced immediately.

---

## Dependency Security

Project dependencies should be regularly reviewed and updated.

Developers should:

- Keep dependencies up to date.
- Remove unnecessary packages.
- Review security advisories for dependencies.
- Avoid installing packages from untrusted sources.

---

## Responsible Disclosure

We appreciate responsible security research.

Security researchers who report vulnerabilities responsibly will be acknowledged where appropriate and with their permission.

Thank you for helping keep AEGIS and its users secure.

---

## Contact

For security-related concerns, contact the AEGIS project maintainers through the project's official repository or designated project contact.