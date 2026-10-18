# Security

## Report privately

Report vulnerabilities privately to **hello@ralveto.com**. Do not publish sensitive details in a public issue.

Include the commit or release, local/cloud mode, synthetic reproduction steps, expected behavior and observed result. Never send real passwords, provider tokens, vault exports or customer records.

No response deadline or supported-release policy has been committed yet. This branch is release preparation as of 18 October 2026.

## Protection and limits

RalX guards against the password landing in the approved page's own web addresses. A site you approved receives your password, like when you type it yourself; RalX does not control what that site's code does with it afterward, including in popups, embedded frames or live connections. Extra hardening for that ships in v0.1.1.

Agents use revocable RalX keys instead of provider credentials. Provider requests use fixed destinations and checked arguments. Listed risky actions need human approval of exact arguments. Credential replacement, disconnection and revocation are checked when requests run. Stored secrets are encrypted and filtered from replies.

Local quickstart runs as your user and uses passkeys. A dedicated-account service is available for stronger OS separation. Cloud uses WorkOS owner sessions, per-user records and Worker secrets. Cloud approval is not a local passkey ceremony.

- Development mode has no separate OS account. Administrators and anyone controlling the daemon account can access credentials.
- The cloud operator controls the database and encryption key. Encryption does not hide data from that operator.
- Agent keys are readable by processes running as the same OS user. Separate OS accounts or sandboxes provide stronger separation.
- Connected services may disguise secrets in output. Filtering is best effort, with fail-closed size and inspection limits.
- Approval and revocation cannot undo a request already dispatched.
- Local audit writes may fail without blocking an action. The log is not a complete transaction ledger.
- Synthetic tests do not establish production account isolation, installed filesystem permissions or live OAuth correctness.

Back up the encryption key privately, separately from the database. Losing it makes encrypted data unrecoverable. Rotation needs a data migration; changing the key alone is unsafe.
