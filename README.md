# Apple Watch Unlock for Omarchy

A headless Omarchy service plugin (`krosdai.watch-unlock`) that lets a nearby, unlocked
Apple Watch unlock the Omarchy lock screen. Wake the lock, type any key and press Enter
while wearing the watch. Your password keeps working as before.

It bundles and configures [`watch-unlock-rs`](https://github.com/KatelynHaworth/watch-unlock-rs),
a PAM module by Katelyn Haworth, with two discovery fixes (see
[Bundled module](#bundled-module)). Tested
on a Dell XPS 14 DA14260 with Omarchy 4.0.4, BlueZ 5.87 and an Apple Watch with
Auto Unlock enabled for a Mac.

## How it works

On each unlock attempt, the PAM module:

1. scans over Bluetooth LE for up to 3 seconds and resolves the watch's rotating
   private address with its Identity Resolving Key (IRK);
2. requires a signal strength (RSSI) of at least −80 dBm, roughly within arm's reach
   to a few metres depending on the room;
3. reads the watch's Apple Continuity *Nearby Info* advertisement and requires
   *watch unlocked* and *Auto Unlock enabled*.

If any check fails, it steps aside and your typed password is checked as usual.

The module is added only to Omarchy's `omarchy-lock-password` PAM service, which runs
after you press Enter. Omarchy's fingerprint service retries continuously in the
background, so using it would unlock the screen again about a second after every
manual lock.

## Requirements

- Omarchy with its Quickshell lock screen (`/etc/pam.d/omarchy-lock-password` present).
- A working Bluetooth LE adapter, with BlueZ running.
- An Apple Watch paired to an iPhone, and **a Mac on the same Apple Account with
  "Unlock with Apple Watch" turned on**. The Mac is needed once, to copy the watch's
  IRK from iCloud Keychain; Apple offers no other way to get it.
- Internet access during setup, to fetch the module's locked Rust crates from crates.io.
  Setup installs `clang`, `pkgconf` and, if `cargo` is missing, `rust` with
  `omarchy-pkg-add`.

## Install

Review this repository, then add and enable the plugin:

```sh
omarchy plugin add https://github.com/krosdai/omarchy-watch-unlock.git --enable
```

On first enable, the plugin opens a terminal with a disclosure and a `[y/N]` prompt.
After you agree, setup:

1. builds the bundled PAM module in a temporary directory;
2. asks for the watch's IRK (hidden input) and checks that the watch is found, near
   enough, unlocked and has Auto Unlock enabled. Nothing is installed if this fails;
3. asks for your sudo password and runs the privileged step from a frozen copy of
   `setup_watch_unlock.py`, never from your writable checkout;
4. authenticates once through the real lock PAM service. If that fails, the previous
   files are restored.

Declining or failing setup writes no completion marker, so the prompt appears again at
the next login. Disable the plugin to stop it. You can also run setup directly as your
desktop user:

```sh
/usr/bin/python ~/.config/omarchy/plugins/krosdai.watch-unlock/setup_watch_unlock.py
```

### Getting the IRK

1. On the watch, open **Settings → General → About** and note the **Bluetooth** address.
2. On the Mac, open **Keychain Access**
   (`/System/Library/CoreServices/Applications/Keychain Access.app` on recent macOS),
   choose **iCloud** and search for `bluetooth`.
3. Open the entry whose **Account** is `Public: <watch's Bluetooth address>`, tick
   **Show password** and authenticate.
4. Copy the base64 value under the `Remote IRK` key (24 characters ending in `==`).
   Paste it unchanged; the module reverses the bytes itself.

Treat the IRK as a secret: anyone who has it can recognise your watch over Bluetooth.

## System-wide effects

The privileged step writes:

```text
/usr/lib/security/pam_apple_watch.so    the module (refused if a package owns this file)
/etc/security/apple_watch.conf          one `user;irk` line per configured user, mode 644
/etc/pam.d/omarchy-lock-password        one added line, after the faillock preauth check
```

The added PAM line is:

```text
auth       sufficient                  pam_apple_watch.so search_timeout_ms=3000
```

- `apple_watch.conf` must be readable by every user, because the lock screen runs PAM
  as you. Other local accounts can read your IRK.
- Faillock lockouts still apply: a failed `required` preauth check overrides a later
  `sufficient` success.
- When the watch is absent, password unlock can take up to 3 seconds longer.
- To tune it, edit the line: `search_timeout_ms=<ms>` and `unlock_threshold=<dBm>`
  (default `-80`). Setup and repair keep an existing line as it is.

Before each change, the previous versions of these files are saved under
`/var/lib/omarchy-watch-unlock/backup-*/`.
The setup's own record and the CLI live at
`${XDG_STATE_HOME:-~/.local/state}/omarchy-watch-unlock/installed.json` and
`${XDG_DATA_HOME:-~/.local/share}/omarchy-watch-unlock/watch_unlock_cli`.

## Security

This is a convenience, not a security boundary. macOS Auto Unlock measures distance with
radio time-of-flight to resist relays. This module checks only signal strength and
unencrypted advertisement flags. Someone near you could record the watch's advertisement
and replay it near the computer until the watch rotates its address (about 15 minutes).
Use your judgement about where you leave the computer locked.

## After Omarchy updates

`omarchy-apply-lock`, run by Omarchy installs and some upgrades, rewrites
`/etc/pam.d/omarchy-lock-password` and drops the added line. Unlocking then falls back to
password-only. At the next shell start, the plugin notices and opens a terminal offering
to add the line back (sudo required). To do it manually:

```sh
/usr/bin/python ~/.config/omarchy/plugins/krosdai.watch-unlock/setup_watch_unlock.py --repair
```

## Check, disable or remove

```sh
~/.local/share/omarchy-watch-unlock/watch_unlock_cli query_status --timeout-ms 10000 "$IRK"
```

shows whether the watch is found, its RSSI, and whether it is locked.

Disabling or removing the Omarchy plugin only stops its launcher. It does **not** remove
the PAM line, the module or your IRK. Disable the plugin first, then remove the
configuration:

```sh
omarchy plugin disable krosdai.watch-unlock
/usr/bin/python ~/.config/omarchy/plugins/krosdai.watch-unlock/setup_watch_unlock.py --uninstall
```

Uninstall removes the PAM line and your `apple_watch.conf` entry. The shared module and
config file are deleted once no other user is configured. Backups are kept. For a full
reset of the lock PAM files, `sudo omarchy-apply-lock` regenerates Omarchy's stock
versions.

If the lock screen ever crashes, switch to a text console (`Ctrl+Alt+F3`): console login
does not use this module.

## Bundled module

`watch-unlock-rs/` is upstream
[`KatelynHaworth/watch-unlock-rs`](https://github.com/KatelynHaworth/watch-unlock-rs)
at commit `360aafc`: tag `v0.2.0` plus version, packaging and README changes, with the
same Rust sources. Only `Cargo.toml`, `Cargo.lock` and `src/` are included, under
upstream's MIT license (`watch-unlock-rs/LICENSE`). The repository history
imports it unchanged, then applies two fixes as separate commits, so
`git log -p -- watch-unlock-rs` shows every local change.

Upstream found the watch only about one time in three when unlocking repeatedly:

- **Stale cache:** BlueZ keeps a recently seen watch cached without an RSSI, and every
  retry matched that stale entry instantly. The fix listens for property changes too
  and waits for a fresh advertisement.
- **Fragmented scanning:** three 500 ms scans, each restarting discovery, often missed a
  resting watch. The fix runs one continuous scan bounded by a new `search_timeout_ms`
  argument and a `query_status --timeout-ms` flag. Twelve consecutive runs then all
  found the watch, most in under 1.7 seconds.

The fixes are offered under upstream's MIT license. To update the module, import a new
upstream commit unchanged, then re-apply or drop the fixes as reviewable commits.

## Development

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked ruff check .
uv run --locked ruff format --check .
(cd watch-unlock-rs && CARGO_TARGET_DIR=/tmp/watch-unlock-target cargo clippy --locked --lib)
omarchy plugin validate <clean export>
```

Keep Cargo output outside the plugin folder with `CARGO_TARGET_DIR`, as setup does.

The unit tests use temporary directories and mock every package, sudo, Bluetooth and
PAM command. Never run setup as a test unless you intend to configure the host. Validate
a clean export (for example `git archive HEAD | tar -x -C <dir>`), because the validator
rejects the symlinks in `.venv`.
