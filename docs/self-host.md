# Self-host RalX on Cloudflare

As of 18 October 2026, this guide targets cloud/. The Go daemon is a separate local mode. Self-hosting puts the Cloudflare account, database and encryption key under your control.

## Prerequisites

Install Git and Node 22+. Go 1.27.1 is needed only for the Go CLI. You need your own Cloudflare account with Workers/D1 and a workers.dev subdomain, a WorkOS AuthKit application, a Google Cloud project with an OAuth web application, and a private backup location.

After publication, or with authorized private access:

```sh
git clone https://github.com/Harsette/ralx.git
cd ralx/cloud
npm ci
```

## Check locally first

```sh
npm run selfhost -- --local --check
```

This writes ignored wrangler.selfhost.local.json with synthetic keys, applies every migration with `wrangler d1 migrations apply DB --local`, queries the local schema, starts `wrangler dev --local` on loopback, checks the home page and authentication refusals, then stops it. No login, remote database operation, secret upload or deployment occurs. Omit --check to leave the preview running until Ctrl+C.

Use a separate clean checkout if cloud/ contains .env or .dev.vars files; local proof refuses to load private development settings. This does not sign in to WorkOS or Google. The test suite separately exercises synthetic OAuth, encryption, approvals and revocation in Miniflare/workerd.

## Configure your provider applications

Choose the final HTTPS origin first, such as `https://ralx.YOUR-SUBDOMAIN.workers.dev`. Find your subdomain and account ID in Cloudflare's dashboard. Do not copy another operator's IDs.

In your WorkOS application, configure AuthKit and register exactly `https://YOUR-HOST/callback` as a redirect URI. Set the home URL to your origin. Copy your own client ID and API key privately. Use production settings for production. See [WorkOS redirect configuration](https://workos.com/docs/authkit/applications). WorkOS sign-up and account-access rules determine who can create a RalX account; configure your intended audience before exposing it.

In [Google Cloud Console](https://console.cloud.google.com/), select your own project, enable Gmail API and Google Drive API, and configure Google Auth Platform branding, audience and data access. The requested scopes are in cloud/src/native-google.ts. Add yourself as a test user if the application is in Testing. Create an OAuth client of type **Web application**, with this exact authorized redirect:

```text
https://YOUR-HOST/oauth/google/callback
```

Copy its client ID and secret privately. A Desktop client is not the Worker client. Public sensitive/restricted scopes may need Google's review. Testing-mode refresh tokens can expire after seven days for these scopes. Follow Google's [web-server OAuth guide](https://developers.google.com/identity/protocols/oauth2/web-server) and [OAuth policies](https://developers.google.com/identity/protocols/oauth2/policies).

## Deploy to your account

These commands create resources and deploy in the account you select:

```sh
npx wrangler login
npm run selfhost
```

The helper asks for a Worker name, your account ID and your final HTTPS origin. It checks login, creates a D1 database in your selected account and writes its ID to ignored wrangler.selfhost.json. It privately prompts for WORKOS_CLIENT_ID, WORKOS_API_KEY, GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET. Input is not echoed.

It generates independent 32-byte random SESSION_SECRET and ENCRYPTION_KEY values locally, sends secrets to Wrangler over stdin, applies remote migrations and deploys. It prints your URL and:

```sh
ralx setup --mode cloud --url https://YOUR-HOST
```

The RC includes `ralx setup`. Select Self-host to deploy and continue Cloud client setup at your configured URL, or run the printed Cloud setup command after manual deployment. From the repository root, the Go shortcut is:

```sh
go run ./cmd/ralx deploy cloudflare --source .
go run ./cmd/ralx deploy cloudflare --source . --local --check
```

A standalone binary needs --source pointing to a checkout with cloud/scripts/selfhost.mjs and installed cloud dependencies.

Keep ignored .selfhost-secrets.json private. It backs up your key and permits interrupted setup to resume without replacing it. The helper sets Unix mode 0600 or removes inherited Windows access and grants your user access before writing secrets. Use a private checkout without additional explicit shared-user grants. Never use a shared or publicly served folder. Never commit these files.

If D1 creation was interrupted, inspect your account before retrying. The helper refuses to create another database while creation_pending remains in config. Add the existing DB binding and remove the marker after checking.

Run the printed setup command and approve once in your browser to connect every detected agent. Open the URL, sign in, connect Google, check a read, and confirm a send is held. Real provisioning and consent need an operator-run trial. This helper's maintained proof is local-only.

## Costs and limits

Checked 18 October 2026 against official docs. Workers Free permits 100,000 requests/day and 10 ms CPU per invocation. Workers Paid starts at USD 5/month with additional usage charges. This Worker runs before assets, so budget page requests too. See [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/).

D1 Free includes 5 million rows read/day, 100,000 written/day and 5 GB total storage. Each free database is capped at 500 MB. Exceeding daily free allowances can stop queries. Large imports may need a paid plan or smaller batches; local success does not establish Free CPU/query compliance. See [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/) and [D1 limits](https://developers.cloudflare.com/d1/platform/limits/).

WorkOS and Google are separate services. Check your provider plans, quotas and verification requirements before production. The helper does not choose paid plans, buy domains or create OAuth applications.

## Update and recover

Back up D1 and the unchanged encryption key. Fetch and inspect your chosen release, then:

```sh
cd cloud
npm ci
npm run typecheck
npm test
npm run selfhost -- --update
```

Update reuses config, account and database, applies pending migrations and deploys. It does not recreate secrets. Changing ENCRYPTION_KEY alone makes existing data unreadable. Rolling back code may not undo schema changes. Review migrations and keep a database backup. D1 offers [Time Travel recovery](https://developers.cloudflare.com/d1/reference/time-travel/).

The RC keeps the sealed `0003_private_vault.sql`; `0004` and later migrations apply
after it on a fresh database. An older pre-release local vault table is incompatible.
Startup returns: "this database has a pre-release vault table; recreate your local
dev DB with npm run db:local". For disposable local development only, stop your
own preview, remove its local D1 state under `cloud/.wrangler/state/v3/d1`, then
run `npm run db:local` from `cloud/`. This discards that local test database.
Do not delete a hosted database or apply this procedure to a database with real
data. Check its migration ledger and plan an explicit conversion first.

For an intentional secret update, run `npx wrangler secret put NAME --config wrangler.selfhost.json` in your private terminal and update your private recovery copy. Encryption-key rotation requires a data migration and is not implemented.

## Existing hosted operators

The previous tracked config is preserved in this preparation checkout as ignored wrangler.hosted.local.jsonc. After separate deployment authorization, use `npx wrangler deploy --config wrangler.hosted.local.jsonc` for that deployment. Existing Worker secrets remain in Cloudflare. Do not replace them with generated self-host keys. The tracked config contains no hosted account or D1 ID.

## Local daemon name

Local mode uses a generic owner identity. Set RALX_OWNER_NAME in the daemon process environment to customize the passkey display name. Historical audit actors remain readable. No existing passkey user ID or credential is migrated.

