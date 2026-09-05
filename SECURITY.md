# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in BytesCop-Reporter, please report it responsibly.

**Email:** [team@bytescop.com](mailto:team@bytescop.com)

Please include:
- A description of the vulnerability and its potential impact.
- Steps to reproduce or a proof-of-concept.
- The version of BytesCop-Reporter you are running.
- Your deployment environment (OS, Docker version, database, etc.) if relevant.

## What to Expect

- We will acknowledge your report within **3 business days**.
- We will investigate and work on a fix. We aim to release patches for confirmed vulnerabilities promptly.
- We will credit you in the release notes (unless you prefer to remain anonymous).
- We will **not** take legal action against researchers who act in good faith and follow responsible disclosure.

## Responsible Disclosure

We ask that you:
- **Do not** publicly disclose the vulnerability until we have released a fix and had reasonable time to notify users.
- **Do not** exploit the vulnerability beyond what is necessary to demonstrate it.
- **Do not** access, modify, or delete data belonging to other users.

## Scope

This policy covers the BytesCop-Reporter application code in this repository, including:
- The Django API (`api/`)
- The Angular UI (`ui/`)
- Docker and deployment configurations
- Dependencies and supply chain (please report vulnerable dependencies too)

This policy does **not** cover:
- Your own infrastructure, network, or operating system — those are your responsibility.
- Third-party services you integrate with BytesCop-Reporter.
- The BytesCop-Reporter Portal website (bytescop.com) — report those separately to [team@bytescop.com](mailto:team@bytescop.com) with "Portal" in the subject line.

## Security Updates

Security advisories and patches are published through:
- GitHub releases and the repository's changelog.
- The [BytesCop-Reporter documentation](https://bytescop.com/docs) page.

We strongly recommend subscribing to repository releases to receive timely notifications of security updates.

## Your Responsibility

BytesCop-Reporter is self-hosted software that runs on your infrastructure. You are responsible for:
- Keeping BytesCop-Reporter updated to the latest version.
- Securing your servers, databases, and network.
- Managing user access, credentials, and MFA.
- Maintaining backups of your data.

See the [Terms of Service](https://bytescop.com/terms) for full details.
