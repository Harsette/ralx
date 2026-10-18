# Agent website sign-in

Implementation dated 18 Oct 2026. Isolated fixture proof only. No installed hub,
service, real account, deployment, push or social publication is involved.

An agent handles a login id. RalX generates or decrypts the password and assigns
it inside Chrome/Edge over CDP. The model-facing response never includes the
password, a password hash, input values or screenshots.

Passwords never enter the agent's conversation through RalX. An agent with raw browser debugging access to the same page could still read a filled field before submit; browser_sign_up/sign_in submit immediately to keep that window minimal.

## Tools

RalX guards against the password landing in the approved page's own web addresses. A site you approved receives your password, like when you type it yourself; RalX does not control what that site's code does with it afterward, including in popups, embedded frames or live connections. Extra hardening for that ships in v0.1.1.

Both the local stdio MCP registry and `/mcp` advertise the same native actions.
The REST spelling uses dots: `POST /v1/actions/browser.sign_in` with
`{"args":{...}}`. MCP replaces dots with underscores.

```json
{"tool":"logins_new_test","arguments":{"origin":"http://127.0.0.1:8080"}}
{"login_id":"login_abcdefghijklmnop","username":"test-example@example.test","origin":"http://127.0.0.1:8080"}

{"tool":"browser_sign_up","arguments":{"login_id":"login_abcdefghijklmnop","url":"http://127.0.0.1:8080/signup","target":"managed"}}
{"status":"signed_in","username":"test-example@example.test","final_url":"http://127.0.0.1:8080/account","session_file":"<data>/browser-sessions/<agent-id>/state-122.json","cdp_endpoint":"ws://127.0.0.1:9222/devtools/browser/<session-capability>","target_id":"page-id","reason":""}

{"tool":"browser_sign_in","arguments":{"url":"http://127.0.0.1:8080/signin","login_id":"login_abcdefghijklmnop","target":"managed"}}
{"status":"signed_in","username":"test-example@example.test","final_url":"http://127.0.0.1:8080/account","session_file":"<data>/browser-sessions/<agent-id>/state-123.json","cdp_endpoint":"ws://127.0.0.1:9222/devtools/browser/<session-capability>","target_id":"page-id","reason":""}

{"tool":"browser_account_text","arguments":{"login_id":"login_abcdefghijklmnop"}}
{"status":"signed_in","username":"test-example@example.test","text":"Signed in as test-example@example.test","final_url":"http://127.0.0.1:8080/account","session_file":"","cdp_endpoint":"ws://127.0.0.1:9222/devtools/browser/<session-capability>","target_id":"page-id","reason":""}
```

Use `logins_new_test -> browser_sign_up -> browser_sign_in -> browser_account_text`.
For a Clerk test-mode app, set `"clerk_test":true` on `logins_new_test`. It generates
a unique `test-...+clerk_test@example.com` address. `browser_sign_up` recognizes a
single verification-code field or six numeric code fields and enters `424242`
only for an exact `+clerk_test` subaddress, once per attempt. Ordinary accounts
return `needs_verification` with a hint to finish in the same browser; RalX does
not guess their code. If Clerk test mode is disabled, an unsuccessful test-code
attempt also returns `needs_verification`.

[Clerk's test emails and phones documentation](https://clerk.com/docs/guides/development/testing/test-emails-and-phones)
confirms that development instances enable test mode by default and reserved
test email addresses accept `424242` without sending an email code. Verification
links are a different flow and can still send mail. This option does not turn
test mode on for an instance or operate a Clerk account API.

Sign-up handles single-page and identifier/Continue/password forms, including
confirmation fields. Sign-up and sign-in fill passwords and submit in one browser
task. Neither returns page text during credential entry. The separate account-text
tool reads scrubbed visible text only on the exact verified success URL for that
agent and login, and refuses any page containing a password input. It cannot
navigate, inspect values, run arbitrary JavaScript or read session files.

Pages load normal resources and can post to another origin, as Clerk does through
its Frontend API. The approved origin controls those scripts and destinations.
RalX checks the top document and the field's own frame against the exact approved
origin immediately before each input batch and before submit. It never fills a
cross-origin iframe. Password forms using GET, including submit-button overrides,
are refused before identifier or password input; identifier-only GET steps remain
supported. HTTP or script navigation to another origin does not authorize filling
there. This is password-manager behavior, not a network sandbox for the website.

Keep `browser_fill` for unusual forms. It deliberately does not submit; omit
`url` on subsequent fills to avoid resetting the form. For Playwright MCP,
use its `--cdp-endpoint` option to continue in this browser; use `--storage-state`
with the returned file for a separate Playwright context.

`target` is `managed` for headless system Chrome, `managed-edge` for headless
system Edge, or an HTTP/WS CDP endpoint on a literal loopback IP. An attached
endpoint gets a new owned tab unless `target_id` selects an existing one. Existing
tabs detach on shutdown; RalX does not close an attached browser. Managed browser
profiles are dedicated to the RalX agent. CDP discovery refuses redirects and
endpoint changes. Managed Chrome uses owner-only inherited debugging pipes, with
no Chrome debugging TCP port. RalX returns a websocket proxy on `127.0.0.1`
with a random 128-bit capability path for this session. Connections without
that capability are refused, including discovery requests. The proxy does not
log the path and closes when the session/browser closes. Treat `cdp_endpoint`
as a private credential: give it only to the requesting agent. A separately
attached browser keeps the security properties of its own CDP listener.

The default success check requires no visible password field and a stable URL
outside the sign-in route. Single-page forms can use `success_selector` to name a
visible authenticated-page element. Unsupported MFA, CAPTCHA or unusual widgets
fail with a fixed reason after 25 seconds. Raw browser exceptions and console
messages are never forwarded. Typed input values are cleared on failure.

## Vault and approvals

The existing `credentials` table stores `kind=website_login`, rather than a
parallel password database. All user text, including display name, username,
origins, notes and extra metadata, is AES-GCM sealed with the existing secretbox.
Only ids, timestamps, enums and domain-separated HMAC origin indexes remain in
plaintext. Origin checks depend on URL syntax only. No validation compares a
user field with any saved password. Owner display reads do not update last-used.

The local owner's Logins section has an Add login form for website, username,
write-only password and optional name. It reuses the signed-in owner session and
CSRF checks, without another approval ceremony. `POST /admin/api/logins` returns
only the new login id. Names default to the site's host and port. Explicit names
are preserved. Reveal remains on the existing fresh-passkey API.

The existing generic passkey-protected credential save/reveal API also works:
use a generated `login_<16 base32 characters>` name, `kind=website_login`, metadata
`kind=real|test`, `created_by=human`, `origins=["https://example.test"]`, and sealed
fields `username`, `password`, optional `name` and `notes`. Origins supplied as
metadata are moved into the sealed fields before SQLite is written. Metadata-only
patches are refused for website logins; save the complete replacement instead.

Only RalX-generated agent test logins on HTTP `localhost`, `127.0.0.1` or `::1`
bypass human approval. Every other combination returns `needs_approval` with an
approval id. The existing UI approval card shows the decrypted username and exact
origin to the human, while the stored approval contains only login id and keyed
origin index. `browser_authorize` is the underlying gated action. Check the
approval using `ralx_approval`, then retry the browser operation. The remembered
grant binds login version and exact origin; replacing credentials invalidates it.
Denied calls do not silently create another approval.

Audit records contain login ids and outcomes, without username, URL, selectors
or password. Results pass the existing redactor/deep scanner. Cookies, including
HttpOnly cookies, and local/session storage values observed during export or
account reads are registered with the same output checks before text is returned.
Rotated values stay registered for subsequent replies. A protected session file
deliberately retains these session values; its separate vault check still refuses
stored passwords and other vault credentials.
An export that reconstructs a vault password is refused. Session files use the
Playwright cookies/localStorage schema, mode 0600 on Unix, and a protected
current-user-only DACL on Windows. Parent session folders and browser profiles
are protected too.

## Limits

Passwords never enter the agent's conversation through RalX. An agent with raw browser debugging access to the same page could still read a filled field before submit; browser_sign_up/sign_in submit immediately to keep that window minimal.

A client with unrestricted CDP access can deliberately inspect a populated password input;
`browser_fill` necessarily leaves that input populated until signup submits.
A hostile bound website can also retain or transform the password. CDP handoff
is an authorized browser-session capability, not isolation against a malicious
browser client. The scanner remains the existing best-effort backstop.

Real Clerk accounts, production service-account browser startup, MFA/CAPTCHA,
system Edge execution, Linux race checks and the parent's independent security
review remain separate proof. Fixture success is not security certification.
