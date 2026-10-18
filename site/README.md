# RalX public site

Static HTML, CSS and JavaScript in `public/`. Cloudflare Pages Functions in `functions/`. No framework or build step.

## Local preview

Use Node 22 or newer. From `site/`:

```sh
npm install
npm run dev
```

Open http://127.0.0.1:7431. Local storage only. RalX and port 7317 stay untouched. `wrangler pages dev public --kv WAITLIST` provides the local KV binding.

## Cloudflare Pages setup, after approval

Publish `site/public` with `site` as the project root. No build command. Pages picks up `site/functions/api/waitlist.js`. Create a KV namespace and bind it as `WAITLIST` in preview and production settings. Without it, the form returns 503 and a contact address.

The form stores normalized email and first signup timestamp under a SHA-256 email key. Short-lived hashed-IP/minute keys deter abuse. KV is eventually consistent; this is a basic deterrent, not an atomic limit. No email is sent. Export/delete signups in the operator's KV account when the launch is over. Confirm the draft privacy/terms, legal operator and retention before publication.

URLs target `Harsette/ralx`, as directed. The public repo, install guide, release and Apache-2.0 license are launch-prep dependencies. No deployment was performed here.

Origins and choices: `DESIGN.md` and `ASSETS.md`. Visual and functional proof: ignored `tmp/landing-proof/`. Final receipt: `checks/receipt.json`.

Fonts have a one-year immutable cache header. Rename them if their content changes.

## Repeat the checks

`npm run check:waitlist` tests storage and failure behavior. With local Pages and the proof server running, `npm run check:browser` captures every section and checks the real form, clipboard, tabs, overflow and phone CPU timing. Set `CHROME_PATH` for a browser installed outside the default Windows location. The shared project heavy lock must belong to `landing` before any browser or render check. The proof server is `node site/checks/proof-server.cjs` from the repo root. Prepare its README first with `uv run --with markdown python site/checks/readme-preview.py`.

Wait until `landing` is first in the parent `.heavy.order`, then create the parent `.heavy.lock` exclusively with `landing` and the UTC time. Release only your own lock after browser work, then remove your queue line. Never remove another worker's lock.

The browser check runs three fresh Chrome processes at each CPU rate, 4x and 1x, at 390x844 CSS pixels and DPR2. Each process has a fresh context with browser caching disabled. Network is unthrottled loopback. It records nearest-rank frame p95 for the first three seconds and for a 1000 CSS pixel/second top-to-bottom scroll, plus LCP and the longest main-thread task starting in the first three seconds. Budgets are 50 ms p95 at 4x, 34 ms at 1x, and no task above 200 ms in the first three seconds at 4x. The task observer reports tasks of at least 50 ms; a zero value means none met that length. This is a local rendering check, not a field-network benchmark.

Set `PERF_ONLY=1` to run just the six performance checks, `SKIP_PERF=1` to capture after a retained performance pass, and `PROOF_DIR` to keep a separate final capture folder. The performance JSON includes every run. The receipt records the actual viewport, broken-image, overflow, console, form, clipboard and FAQ checks.

The approved-direction polish check is saved under `tmp/landing-proof/polish-20261018/`, with preserved `before/` and final `after/` screenshots. `comparison.json` maps the five review items and retains all twelve before/after perf measurements. The committed receipt also keeps both sets, computed desktop/phone sizes, caption placement, once-only connector checks, crop sources and the official Claude SVG source.
