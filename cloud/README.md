# RalX cloud and self-hosting

Hosted RalX Cloud is coming soon. Local-first installation is in
[the root README](../README.md). This directory retains the Worker for operators
who want to host their own service. See [self-hosting](../docs/self-host.md).

Node 22+ is required. The tracked Wrangler config contains local defaults.
Configure accounts privately; never commit real secrets or deployment IDs.

```sh
npm ci
npm run typecheck
npm test
npm run selfhost -- --local --check
```

Local tests use synthetic data and mocked providers. Self-hosting creates a Worker
and D1 database only when explicitly selected. WorkOS owner sign-in, native Google
OAuth, Gmail/Drive tools, revocable agent identities, exact-argument approvals,
private-vault import and sealed login metadata are implemented.

## Known limit

Cloud Gmail subjects/snippets and Drive contents are not filtered against saved
private-vault passwords. Hostile upstream content containing such a password may
return it. Do not treat cloud reply filtering as a guarantee against this case.
The local-first launch does not establish hosted production readiness.
