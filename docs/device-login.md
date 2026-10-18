# One browser approval for this computer

As of 18 October 2026. Local implementation and synthetic proof only.

The customer job is to install RalX and connect every installed agent with one
browser approval. This extends `ralx setup --mode cloud`; it does not introduce
another account or a separate setup app. The confirmation page uses the existing
cloud font, colors, rows, icons and buttons.
The existing Agents screen lists and revokes each resulting agent separately.

## Protocol

Modeled on [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) and
[gh auth login](https://cli.github.com/manual/gh_auth_login), checked 18 October
2026. Reuses the existing WorkOS session and hashed agent-key model. No new
service, paid dependency or account is needed.

| Route | Result |
| --- | --- |
| `POST /device/code` | Machine name and up to eight distinct supported client names. Returns a secret device code, eight-character human code, same-origin verification URLs, five-second interval and 600-second expiry. |
| `GET /device?user_code=...` | Confirmation page, or sign-in link preserving this request through WorkOS. `/device` also accepts a typed code. |
| `GET /api/device?user_code=...` | Authenticated review, first-review user binding and session-bound CSRF value. |
| `POST /api/device/approve` or `/deny` | Same-origin JSON, CSRF and approving-user checks. One atomic decision and secret-free audit event. |
| `POST /device/token` | Polling with `authorization_pending`, persistent interval increases on `slow_down`, `access_denied`, `expired_token`, and replay rejection. One successful poll returns a 120-second machine grant. |
| `POST /device/enroll` | Grant plus one reviewed client name. Atomically consumes that client's slot and creates its normal, separately revocable agent identity. |

Device codes, normalized human codes and machine grants are hashed in D1.
The machine grant never authenticates MCP and cannot enroll another client or
reuse a consumed client slot. Only each client's normal credential is saved.
Browser request codes pass through a secure HttpOnly cookie during WorkOS
sign-in, not oauth_states. Production observability remains disabled in the
existing Wrangler configuration. Do not enable URL/body logging for these routes.

CLI output intentionally prints the human code and verification URL. It never
prints the device secret, machine grant or returned agent keys. SSH and
`--no-browser` print the same instructions. `--yes` never approves a request.
No provider accounts are connected by this approval; existing connected accounts
become available to the enrolled agents.

