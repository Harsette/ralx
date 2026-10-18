# Install RalX for this person

You are the installing agent. Complete the work, then report at most three short
lines. Do not make the person run commands you can run. Never print, read out or
copy passwords, agent keys, identity-file contents or private onboarding tokens.

1. Detect the operating system and CPU architecture. Supported: Windows, macOS
   and Linux on amd64 or arm64. Use the user's normal, non-elevated account.
2. Run the installer even when `ralx doctor` succeeds. It compares the installed
   version with the verified release. The same version stays completely untouched.
   An older version gets a private full backup, an in-place binary/service upgrade,
   idempotent setup and doctor. Keep its data directory, accounts and identities.
   Never uninstall first. Unknown or conflicting registrations stop with a
   diagnostic instead of creating another vault. Report that diagnostic.
   Windows system installs keep their service account because the vault key is
   encrypted for that account. Windows may ask for administrator permission.
3. Run the official installer non-interactively:

   Windows PowerShell:

   ```powershell
   $env:RALX_SETUP_ARGS_JSON='["--mode","local","--clients","all","--yes"]'
   irm https://raw.githubusercontent.com/Harsette/ralx/main/install.ps1 | iex
   ```

   macOS or Linux:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/Harsette/ralx/main/install.sh | sh -s -- --mode local --clients all --yes
   ```

   Respect an existing `RALX_RELEASE_BASE_URL` override for private release tests.
   An isolated test may also set `RALX_INSTALL_SCRIPT_BASE_URL`; when set, fetch
   `install.ps1` or `install.sh` from that base instead of raw.githubusercontent.com.
   Preserve all inherited sandbox HOME, config, port and no-browser settings.
   Never change a sandbox to use the person's real home or port 7317.
4. The installer runs `ralx setup --mode local --clients all --yes` and doctor.
   An upgrade prints its snapshot directory and a one-command rollback. Keep that
   command in your reply. `ralx rollback` restores the last upgrade snapshot.
   Rollback replaces data with the saved snapshot, including provider records.
   If the installer finished, do not repeat setup or doctor and open another
   browser window. If setup did not finish, run that setup command, then doctor.
   If PATH has not refreshed, use `%USERPROFILE%\.local\bin\ralx.exe`
   on Windows or `$HOME/.local/bin/ralx` on macOS/Linux. Setup is idempotent.
   `all` connects detected apps, including Antigravity; it does not install apps.
   Do not fabricate client folders or bypass custom profile warnings.
5. Confirm doctor has no failures. A TODO for unconnected accounts is expected on
   a fresh machine. Setup opens a private browser window. If no browser
   opened, run `ralx open` without printing its private URL. If
   `RALX_SETUP_NO_BROWSER=1`, leave the browser closed and tell the person to run
   `ralx open` instead. Keep passkey creation,
   provider sign-in/consent and exact-action approvals with the person. These
   protect their accounts; never automate or waive them. No local setup
   passphrase or per-client enrollment is needed.

Finish with only the applicable human steps, at most three short lines:

For an upgrade with existing accounts, report the upgrade, doctor result and
printed rollback command. Do not ask them to reconnect their accounts or create
another passkey. Ask them to restart connected agent apps to load the new binary.

> Restart this agent app to load RalX.
> In the RalX browser window, create your passkey and connect your accounts.
> Then ask me: "Use RalX to sign in to <site>."

If a command fails, report that failure and the smallest required fix instead of
claiming installation succeeded. Do not claim a real sign-in was tested until it
was. Installing RalX adds tools; it does not grant provider access automatically.
