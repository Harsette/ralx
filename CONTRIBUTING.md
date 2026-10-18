# Contributing

RalX uses Apache-2.0. Public contributions open after publication. Until then, this describes the intended workflow.

Discuss changes to credentials, approvals, provider permissions or the user journey before building. Use a branch and focused changes. Include reproduction steps and checks. Never commit real credentials or personal/customer data. Use synthetic fixtures and example.invalid addresses.

## Local checks

Install Git, Go 1.27.1, Node 22+ and Python 3 for generated-script syntax checks. On Windows Python can be installed through uv; set PYTHON_BIN if needed. A Cloudflare account is not required for these checks.

```sh
go vet ./...
go test -p=1 ./... -count=1
go build ./cmd/ralx
cd cloud
npm ci
npm run typecheck
npm test
npm run selfhost -- --local --check
```

The local helper applies migrations only to local D1, starts a loopback Worker, checks responses and stops it. Cloud tests mock providers. Never run scripts/live-proof.mjs against an account without explicit authorization.

Cloud settings belong in ignored cloud/wrangler.selfhost.json. The tracked config contains local defaults. Credentials belong in Worker secrets, never committed config or fixtures. See [self-hosting](docs/self-host.md).

Preserve authentication and approval checks. Add focused behavioral regression tests for security-sensitive changes. Do not loosen host checks, inspection limits or token revocation to make tests pass.

## Pull requests

Explain the problem, resulting behavior, validation and remaining limits. Review hostile inputs and output disclosure carefully when editing cloud/src/private-vault.ts, vault-zip.ts or security.ts. Report vulnerabilities privately through [SECURITY.md](SECURITY.md). Keep third-party notices. License changes and releases require maintainer approval.
