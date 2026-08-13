# Repository Safety

The repository is expected to become public. Treat every commit as permanently public even while the repository is private.

Never commit:

- API keys, access tokens, passwords, cookies, private keys, certificates, or provisioning profiles
- Real credential-store exports or authentication responses
- Personal documents, machine logs, crash reports, or absolute local paths
- Production request or response payloads
- Customer, device, or account identifiers

Use synthetic fixtures and reserved example values in tests and documentation. Keep runtime credentials in environment variables or an operating-system credential store.

Before every commit, review the exact staged diff. Before making the repository public, scan the complete Git history and rotate any credential that may have entered it.
