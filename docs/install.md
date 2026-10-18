# Install RalX

## Let your agent install it

Paste: `Install RalX for me: follow https://github.com/Harsette/ralx/blob/main/AGENT_INSTALL.md`

The agent runs non-interactive local setup and doctor. You restart your agent app,
create the approval passkey in the private browser window and connect accounts.

## Manual quickstart

Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/Harsette/ralx/main/install.ps1 | iex
```

macOS or Linux, in Terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/Harsette/ralx/main/install.sh | sh
```

Choose **This computer**, then finish onboarding in the browser. RalX connects
the supported agents it finds. Restart those agents to load their new tools.
Add your accounts in RalX once, then use them from each connected agent.

These commands require public repository access and a binary release to be
published. The RC includes installers but does not publish anything.

## Choose where RalX runs

### Upgrade or roll back

Run the same installer again to upgrade. A working doctor does not skip a newer
release. The exact same version is left untouched, including data and configs.
Before changing an older installation, the verified binary takes a private backup
under `~/RalX-backups/pre-v<release>-<timestamp>/`. Its `manifest.json` records
SHA256 hashes for every saved file. SQLite uses an online snapshot, including
committed WAL data. The snapshot includes the binary, vault key, data, identities,
client configs, permissions and service definition. No secrets are printed.

The upgrade keeps the existing data directory and agent identities, updates the
binary and login service, reruns setup and checks doctor. Legacy Windows services
keep `NT SERVICE\RalX` and their protected data directory because Windows encrypts
the vault key for that account. Their daemon moves to `Program Files\RalX\bin`;
the former binary path remains usable for older clients such as Hermes.
Administrator approval is needed for an existing system service. A Linux systemd
installation likewise keeps its service user and unit. Unknown registrations are
kept with a diagnostic, rather than starting another vault.

The installer prints the snapshot and a rollback command. `ralx rollback` uses
the last upgrade snapshot. Every snapshot also contains its own `rollback.exe`
(Windows) or `rollback` executable, so rollback works if setup fails. For example:

```powershell
& 'C:\Users\you\RalX-backups\pre-v0.1.0-<timestamp>\rollback.exe' rollback --backup 'C:\Users\you\RalX-backups\pre-v0.1.0-<timestamp>'
```

Rollback verifies saved hashes before stopping anything, restores the saved
binary, data and configs, verifies restored bytes and restarts the prior service.
Changes made after that snapshot are replaced by the saved data. Neither upgrade
nor rollback signs into a provider. `ralx backup` makes another snapshot without
stopping the current daemon.

Isolated copied-vault trials may set both `RALX_SETUP_SANDBOX=1` and
`RALX_SETUP_OFFLINE=1`. Doctor then checks that provider records are readable,
without claiming their stored network status is healthy. All local service,
client and identity checks still run. Trial executables must separately block
outbound traffic. Normal doctor keeps its provider status checks.

### This computer (recommended)

No administrator password is needed. The installer checks the downloaded
binary's SHA256 against the release's `checksums.txt`, puts it in `~/.local/bin`
(`%USERPROFILE%\.local\bin` on Windows), adds that directory to your user PATH,
and runs `ralx setup`. HTTPS protects the binary and checksums download. The
checksums are not a separate publisher signature.

Setup starts the existing RalX daemon as your user and arranges startup at login.
Your browser opens onboarding at `http://localhost:7317`. Register your passkey,
then connect accounts. Windows uses a hidden Startup-folder launcher; macOS uses
a LaunchAgent; Linux enables a systemd user unit when systemd is installed,
with desktop autostart as the fallback. The systemd unit starts when your user
session starts, without enabling lingering or requiring root. Linux servers can
also use the dedicated-account service in `deploy/linux/install.sh`.

On a Mac, setup loads its LaunchAgent with `launchctl`, and doctor checks it is
loaded. Each data folder gets its own startup job. No admin access is needed.
The installer picks the native Apple Silicon or Intel binary. It removes the
download quarantine flag if one is present. A `curl` download normally has none.
The PATH entry goes in `~/.zprofile` for zsh. For bash, it uses the first existing
login profile, or creates `~/.bash_profile`. Uninstall restores the original text.

**The per-user option runs with your permissions. Other programs running as you
can read its local files.** For a vault isolated from local agents, use the
existing `ralx admin install` on Windows, the dedicated Linux service, or Cloud.
The dedicated Windows service needs administrator approval and is separate from
this per-user install. Setup refuses an occupied port instead of changing an
existing installation.

Scripted setup:

```sh
ralx setup --mode local --clients all --yes
ralx doctor
```

Choose specific installed clients with `--clients claude-code,codex,cursor`.
Use `--clients none` to install only the service. `all` means all detected clients;
setup does not install missing apps or create their settings directories.
Open a new terminal if `ralx` is not yet on PATH. Run `ralx open` to return to
onboarding. `--no-browser` suppresses browser launch without printing the private
one-time onboarding token into a terminal log.

For a second isolated instance:

```sh
ralx setup --mode local --addr 127.0.0.1:17317 --data /absolute/path/to/data --yes
```

Keep the same address, data directory and binary on repeat runs. Uninstall before
changing them. Data defaults to `~/.ralx/setup/data`. Logs are in
`~/.ralx/setup/service.log`. The private admin pipe/socket is unique to this setup.

### RalX Cloud (coming soon)

Choosing **RalX Cloud** prints the waitlist URL and exits without installing a
service or enrolling clients. The single homepage default is in
`cmd/ralx/launch.go`; `RALX_HOMEPAGE_URL` overrides it. The domain and signup page
are still pending confirmation. The reserved placeholder does not accept data.

### Operator cloud mode

Self-host operators can still explicitly connect their own server. This path is
kept behind `--mode cloud` and is not the default install path:


```sh
ralx setup --mode cloud --url https://YOUR-HOST
```

**Approve once in your browser, every detected agent is connected.** Sign in,
check the computer name, code and installed agents, then press **Approve**. Each client
gets its own revocable identity and uses the hosted MCP server through
`ralx cloud-mcp`. There is no local daemon in this mode.

For SSH or a computer without a browser:

```sh
ralx setup --mode cloud --url https://YOUR-HOST --clients all --yes --no-browser
```

Open the printed URL on another device and check the code. `--yes` still
requires your browser approval. The request expires after ten minutes. Deny
or expiry leaves client configs untouched. A temporary machine grant lasts
two minutes and is discarded after setup; only separate client keys are saved.

Set your operator-provided URL with `--url` or `RALX_CLOUD_URL`. No personal
deployment is configured by default. No per-client codes are needed. See
[device login and local proof](device-login.md) for the protocol and tests.

### Self-host on your own Cloudflare

```sh
ralx deploy cloudflare --source /path/to/ralx
```

This runs the real self-host helper. Follow [docs/self-host.md](self-host.md)
for Node, cloud dependencies, Wrangler login, D1, secrets and OAuth callbacks.
It creates resources and deploys in your selected account. Then approve once in
your browser and every detected agent is connected:

```sh
ralx setup --mode cloud --url https://YOUR-HOST
```

Choosing Self-host in `ralx setup` runs the same helper, reads the deployed URL
from `cloud/wrangler.selfhost.json`, then continues Cloud setup for that URL.
Use `--source /path/to/ralx` if the checkout is elsewhere. Local proof only:
`ralx setup --mode self-host --source /path/to/ralx --local --check --yes`
stops after the local checks and does not register clients.

## Connected clients

| Client | User config | Registration |
|---|---|---|
| Claude Code | `~/.claude.json` | Prefers `claude mcp add --scope user`; file fallback |
| Claude Desktop | Windows `%APPDATA%/Claude/claude_desktop_config.json`; macOS `~/Library/Application Support/Claude/claude_desktop_config.json` | JSON `mcpServers` |
| Codex CLI | `~/.codex/config.toml` | TOML `mcp_servers.ralx` |
| Cursor | `~/.cursor/mcp.json` | JSON `mcpServers` |
| VS Code | Windows `%APPDATA%/Code/User/mcp.json`; macOS `~/Library/Application Support/Code/User/mcp.json`; Linux `~/.config/Code/User/mcp.json` | JSONC `servers` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON `mcpServers`; uses Devin's new config path when that app directory exists |
| Antigravity | Windows `%USERPROFILE%/.gemini/config/mcp_config.json`; macOS/Linux `~/.gemini/config/mcp_config.json` | JSON `mcpServers.ralx`, `command` + `args` + `env`; existing legacy `~/.gemini/antigravity/mcp_config.json` is retained when no modern file exists |
| Gemini CLI | `~/.gemini/settings.json` | JSON `mcpServers` |

Standard user profiles are supported. Named VS Code profiles, portable installs
and custom client config-directory environment overrides need manual registration.
Run `ralx setup --show-config` to see stdio and HTTP examples for other clients. The stdio config
contains only an identity-file path. Provider credentials are never copied into
client configs.

Existing servers and settings are preserved. A pre-existing server named `ralx`
is kept and reported for manual attention. Before editing a config, setup writes
`<config>.ralx-setup.bak` and a private receipt. Plain JSON and VS Code JSONC
comments/trailing commas are accepted. JSON formatting/comments are normalized
during installation; uninstall restores the exact original bytes if unchanged.
Codex's existing TOML text stays intact, with a marked RalX section appended.
Never delete backups or receipts before uninstalling.

`ralx doctor` checks the private service, UI, autostart file, installed binary,
each client registration and each identity against the daemon. It reports saved
provider connection status; it does not send provider operations to prove access.
A new installation reports that accounts still need connecting.

## Remove or uninstall

```sh
ralx setup --remove
```

Restores client configs and revokes setup-created local identities. The service
keeps running. Then `ralx setup --mode local --clients all --yes` can reconnect.

```sh
ralx uninstall
```

Restores client configs, revokes setup-created local identities, stops this
per-user daemon, removes autostart, and removes the installer binary and added
PATH entry. Windows removes the executing binary shortly after the command exits.
Open a new terminal to refresh PATH. Vault data and logs are kept so you can
recover them. The older machine-wide service is never uninstalled by this command.

Changes you made to other servers after setup are preserved. If you edited the
RalX entry or its autostart file, removal stops with a message and keeps the backup.
Hosted identities also need revoking in Cloud's Agents screen: deleting a local
key cannot revoke it on the hosted service without an owner session.

## Test downloads without a release

Windows supports a local folder, a `file:` URL or HTTP in `RALX_RELEASE_BASE_URL`.
Unix supports HTTP or `file:` URLs. Put the matching `ralx_OS_ARCH[.exe]` and
`checksums.txt` there. `RALX_VERSION=vX.Y.Z` pins a GitHub release;
`RALX_INSTALL_DIR` changes the binary directory.

For automated Windows installs, set `RALX_SETUP_ARGS_JSON` to a JSON array of
setup flags. Unix supports `RALX_SETUP_YES=1`, or `sh install.sh --mode local --yes`.
Tests must set HOME, USERPROFILE, APPDATA and LOCALAPPDATA beneath a temporary
directory, set `RALX_SETUP_SANDBOX=1`, use a non-default address and temporary data.
Sandbox mode disables client CLI execution and persistent Windows PATH changes.

The Unix proof can also run against a native Linux binary in an isolated home:
`sh scripts/prove-install-unix.sh /absolute/path/to/ralx_linux_amd64`.

```powershell
pwsh -NoProfile -File scripts/verify-install.ps1 -Mode Sandbox -Go C:/path/to/go.exe
pwsh -NoProfile -File scripts/verify-install.ps1 -Mode Full -Go C:/path/to/go.exe
pwsh -NoProfile -File scripts/verify-install.ps1 -Mode Cross -Go C:/path/to/go.exe
```

The verifier takes the shared `.heavy.lock` before building or running all-package
tests. Sandbox proof installs the built binary through the PowerShell installer,
runs setup twice, runs doctor, completes MCP initialize and tools/list from the
exact Codex TOML and Claude JSON entries, detects a revoked identity, uninstalls,
and compares all eight original files byte for byte. Logs are under
`tmp/install-proof`. Cross mode builds the six release targets sequentially.
The expanded Windows proof also rejects a corrupt checksum, restarts the daemon
through the actual sandbox Startup launcher, removes integrations, reconnects
them and verifies a local hosted-MCP fixture. A real reboot/login remains a
separate check.

The release workflow runs only on a pushed `v*` tag and publishes six binaries
and checksums. It is not triggered by these local checks.

Config formats checked against official documentation on 18 October 2026:
[Claude Code](https://code.claude.com/docs/en/mcp),
[Claude Desktop](https://github.com/modelcontextprotocol/docs/blob/main/quickstart/user.mdx),
[Codex](https://developers.openai.com/codex/mcp),
[Cursor](https://cursor.com/docs/sdk/typescript),
[VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers),
[Windsurf/Cascade](https://docs.windsurf.com/windsurf/cascade/mcp),
[Gemini CLI](https://geminicli.com/docs/tools/mcp-server/).

Antigravity paths and JSON schema checked against [Google's MCP docs](https://antigravity.google/docs/mcp)
on 18 October 2026. Installed Antigravity 2.23.0 and the modern config location
were inspected read-only. The writer also retains the legacy IDE file when present.
Config tests exercise backup, merge, repeat setup, concurrent edits and exact restore
for all eight clients on the three OS path layouts. Fresh Codex config creation is
tested separately. Runtime receipts belong to the private launch proof, not this guide.

`ralx setup` keeps its output short. For another app, run `ralx config --list`,
then `ralx config <app>` to print its example. Replace the identity-file
placeholder with that app's own enrolled identity. `ralx config http` prints
the HTTP MCP example. These commands only print config; they do not write it.
`ralx setup --clients <app>` reuses the saved installation settings.
Set `RALX_OWNER_NAME` in the daemon environment to name the person an agent
should ask for approval. Without it, prompts refer to the owner.
