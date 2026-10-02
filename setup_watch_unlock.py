#!/usr/bin/python
"""Unlock the Omarchy lock screen with a nearby, unlocked Apple Watch."""

import argparse
import base64
import binascii
import fcntl
import getpass
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

VERSION = "0.1.0"
UPSTREAM = "https://github.com/KatelynHaworth/watch-unlock-rs.git"
# Pin the reviewed upstream tree; the patches below are written against it.
UPSTREAM_COMMIT = "360aafcaca6394359646a14fb2e771a56d5b6ef0"
PLUGIN = Path(__file__).resolve().parent
PATCHES = (
    "patches/0001-fix-watch-wait-for-fresh-adverts-of-cached-watches.patch",
    "patches/0002-feat-pam-scan-once-with-a-configurable-timeout.patch",
)
SOURCES = ("setup_watch_unlock.py",)

PAM_FILE = "etc/pam.d/omarchy-lock-password"
CONF_FILE = "etc/security/apple_watch.conf"
MODULE_FILE = "usr/lib/security/pam_apple_watch.so"
STATE_DIRECTORY = "var/lib/omarchy-watch-unlock"
# Only Omarchy's password service is used: its fingerprint service is retried
# continuously, which would undo a manual lock while the watch is nearby.
PAM_LINE = "auth       sufficient                  pam_apple_watch.so search_timeout_ms=3000"
# The module's default minimum RSSI; setup checks the same value up front.
UNLOCK_THRESHOLD = -80
PAM_ANCHOR = re.compile(r"^auth\s+required\s+pam_faillock\.so\s+preauth\b")
PAM_OWNED = re.compile(r"^\s*-?auth\s+\S+\s+pam_apple_watch\.so(\s|$)")
USER_NAME = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")
CONF_HEADER = """#
# Users allowed to unlock with an Apple Watch, managed by krosdai.watch-unlock.
# Each line is `user;irk`, where irk is the watch's base64 Identity Resolving Key.
#
"""

BOOTSTRAP = """
import json, sys, tempfile
from pathlib import Path

payload = json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix="omarchy-watch-unlock-source-") as directory:
    root = Path(directory)
    for name, text in payload["sources"].items():
        (root / name).write_text(text)
    sys.path.insert(0, str(root))
    import setup_watch_unlock

    setup_watch_unlock.configure(payload["request"])
"""


# Pure helpers ----------------------------------------------------------------


def decode_irk(value):
    """Return the base64 IRK exactly as Keychain shows it, or raise ValueError."""
    value = value.strip()
    try:
        raw = base64.b64decode(value, validate=True)
    except binascii.Error, ValueError:
        raise ValueError("The IRK must be base64, as shown in Keychain Access.") from None
    if len(raw) != 16:
        raise ValueError(f"The IRK must decode to 16 bytes, not {len(raw)}.")
    return value


def add_pam_line(text):
    """Insert the watch module after faillock's preauth check, once."""
    lines = text.splitlines()
    if any(PAM_OWNED.match(line) for line in lines):
        # Keep an existing line, including any tuned timeout or threshold.
        return text
    anchors = [index for index, line in enumerate(lines) if PAM_ANCHOR.match(line)]
    if len(anchors) != 1:
        raise ValueError(
            f"Expected one pam_faillock preauth line in /{PAM_FILE}; "
            "Omarchy's lock PAM layout changed, so integrate the module manually."
        )
    lines.insert(anchors[0] + 1, PAM_LINE)
    return "\n".join(lines) + "\n"


def remove_pam_line(text):
    lines = [line for line in text.splitlines() if not PAM_OWNED.match(line)]
    return "\n".join(lines) + "\n"


def has_pam_line(text):
    return any(PAM_OWNED.match(line) for line in text.splitlines())


def conf_entries(text):
    return [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]


def set_conf_entry(text, user, irk):
    """Add or replace one user's entry, preserving every other line."""
    entry = f"{user};{irk}"
    lines = text.splitlines() if text else CONF_HEADER.splitlines()
    for index, line in enumerate(lines):
        if line.split(";", 1)[0] == user and not line.lstrip().startswith("#"):
            lines[index] = entry
            break
    else:
        lines.append(entry)
    return "\n".join(lines) + "\n"


def remove_conf_entry(text, user):
    lines = [line for line in text.splitlines() if line.split(";", 1)[0] != user]
    return "\n".join(lines) + "\n"


def watch_ready(output):
    """Interpret `watch_unlock_cli query_status`; return an error message or None."""
    if "Found Apple Watch" not in output:
        return "The Apple Watch was not found. Keep it on your wrist next to this computer."
    rssi = re.search(r"RSSI\.*: (-?\d+)", output)
    if rssi is None or int(rssi[1]) < UNLOCK_THRESHOLD:
        return "The Apple Watch is too far away. Move it next to this computer, then retry."
    if not re.search(r"Locked\.*: false", output):
        return "The Apple Watch is locked. Unlock it, then retry."
    if not re.search(r"Auto-unlock devices enabled\.*: true", output):
        return "Turn on 'Unlock with Apple Watch' on your Mac, then retry."
    return None


# Privileged phase --------------------------------------------------------------


def atomic_write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def package_owner(path):
    result = subprocess.run(["pacman", "-Qqo", str(path)], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def check_regular(path, required=False):
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError(f"Symlinked path requires manual setup: {path}")
    if path.exists() and not path.is_file():
        raise ValueError(f"Non-regular path requires manual setup: {path}")
    if required and not path.exists():
        raise ValueError(f"Missing {path}; is this a current Omarchy system?")


def backup(root, paths):
    """Copy the files about to change; record which ones did not exist yet."""
    state = root / STATE_DIRECTORY
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="backup-", dir=state))
    created = []
    for path in paths:
        if path.exists():
            target = directory / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        else:
            created.append(str(path.relative_to(root)))
    (directory / "previous.json").write_text(json.dumps({"created": created}, indent=2) + "\n")
    return directory


def restore(root, directory):
    """Put back every file recorded in one backup directory."""
    directory = Path(directory).resolve()
    if directory.parent != (root / STATE_DIRECTORY).resolve():
        raise ValueError(f"Not a watch-unlock backup: {directory}")
    previous = json.loads((directory / "previous.json").read_text())
    for relative in previous["created"]:
        (root / relative).unlink(missing_ok=True)
    for saved in directory.rglob("*"):
        if saved.is_file() and saved.name != "previous.json":
            target = root / saved.relative_to(directory)
            atomic_write(target, saved.read_bytes(), saved.stat().st_mode & 0o7777)


def apply(root, user, irk=None, module=None, owner=package_owner):
    """Install the module, map the user to their watch and enable it for the lock."""
    pam, conf, library = root / PAM_FILE, root / CONF_FILE, root / MODULE_FILE
    check_regular(pam, required=True)
    check_regular(conf)
    check_regular(library)
    if module is not None and library.exists() and owner(library):
        raise ValueError(f"{library} belongs to package {owner(library)}; remove it first.")
    if module is None and not library.exists():
        raise ValueError(f"{library} is missing; run the full setup again.")
    conf_text = conf.read_text() if conf.exists() else ""
    if irk is None and not any(e.split(";", 1)[0] == user for e in conf_entries(conf_text)):
        raise ValueError(f"No watch is configured for {user}; run the full setup again.")
    pam_text = add_pam_line(pam.read_text())

    saved = backup(root, (pam, conf, library))
    try:
        if module is not None:
            atomic_write(library, module, 0o755)
        if irk is not None:
            # The lock screen runs PAM as the desktop user, so it must read this.
            atomic_write(conf, set_conf_entry(conf_text, user, irk).encode(), 0o644)
        atomic_write(pam, pam_text.encode(), pam.stat().st_mode & 0o7777)
    except BaseException:
        restore(root, saved)
        raise
    return saved


def remove(root, user, owner=package_owner):
    """Disable the module for the lock and forget this user's watch."""
    pam, conf, library = root / PAM_FILE, root / CONF_FILE, root / MODULE_FILE
    for path in (pam, conf, library):
        check_regular(path)
    conf_text = conf.read_text() if conf.exists() else ""
    remaining = conf_entries(remove_conf_entry(conf_text, user))
    saved = backup(root, (pam, conf, library))
    try:
        if pam.exists():
            atomic_write(
                pam, remove_pam_line(pam.read_text()).encode(), pam.stat().st_mode & 0o7777
            )
        if remaining:
            atomic_write(conf, remove_conf_entry(conf_text, user).encode(), 0o644)
        else:
            # Other users still need the shared module and file while entries remain.
            conf.unlink(missing_ok=True)
            if library.exists() and not owner(library):
                library.unlink()
    except BaseException:
        restore(root, saved)
        raise
    return saved


def configure(request):
    """Entry point for the root phase, staged by BOOTSTRAP."""
    if os.geteuid() != 0:
        raise RuntimeError("System configuration requires sudo.")
    # Trust only sudo's record of the invoking user, never the request.
    user = os.environ.get("SUDO_USER", "")
    if not USER_NAME.match(user) or user == "root":
        raise RuntimeError("Run setup with sudo from your desktop account.")
    root = Path("/")
    with Path("/run/omarchy-watch-unlock.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Apple Watch unlock setup is already running.") from None
        action = request["action"]
        if action == "install":
            module = base64.b64decode(request["module"])
            saved = apply(root, user, decode_irk(request["irk"]), module)
        elif action == "repair":
            saved = apply(root, user)
        elif action == "remove":
            saved = remove(root, user)
        elif action == "rollback":
            restore(root, request["backup"])
            return
        else:
            raise ValueError(f"Unknown action: {action}")
    print(f"BACKUP={saved}", flush=True)


# Desktop-user phase ------------------------------------------------------------


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def state_directory():
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return base / "omarchy-watch-unlock"


def cli_path():
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return base / "omarchy-watch-unlock/watch_unlock_cli"


def elevate(request):
    """Run one privileged action from a frozen copy of this file."""
    sources = {name: (PLUGIN / name).read_text() for name in SOURCES}
    payload = json.dumps({"sources": sources, "request": request})
    result = run(
        "sudo", "/usr/bin/python", "-I", "-c", BOOTSTRAP,
        input=payload, text=True, stdout=subprocess.PIPE,
    )  # fmt: skip
    for line in result.stdout.splitlines():
        if line.startswith("BACKUP="):
            print(f"Previous files saved in {line.removeprefix('BACKUP=')}")
            return line.removeprefix("BACKUP=")
        print(line)
    return None


def confirm(message):
    print(message)
    return input("Continue? [y/N] ").strip().lower() in {"y", "yes"}


def find_cargo():
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
    return cargo if Path(cargo).is_file() else None


def build(workspace):
    """Build the pinned, patched module; return (module bytes, CLI path)."""
    run("omarchy-pkg-add", "git", "clang", "pkgconf")
    cargo = find_cargo()
    if cargo is None:
        run("omarchy-pkg-add", "rust")
        cargo = find_cargo() or "cargo"
    source = workspace / "watch-unlock-rs"
    run("git", "clone", "--quiet", UPSTREAM, str(source))
    run("git", "-C", str(source), "checkout", "--quiet", "--detach", UPSTREAM_COMMIT)
    head = run("git", "-C", str(source), "rev-parse", "HEAD", capture_output=True, text=True)
    if head.stdout.strip() != UPSTREAM_COMMIT:
        raise RuntimeError("Upstream checkout does not match the pinned commit.")
    patches = [str(PLUGIN / patch) for patch in PATCHES]
    run("git", "-C", str(source), "apply", "--check", *patches)
    run("git", "-C", str(source), "apply", *patches)
    environment = {**os.environ, "CARGO_TARGET_DIR": str(workspace / "target")}
    for target in (("--lib",), ("--bin", "watch_unlock_cli", "--features", "cli")):
        run(cargo, "build", "--locked", "--release", *target, cwd=source, env=environment)
    release = workspace / "target/release"
    return (release / "libpam_apple_watch.so").read_bytes(), release / "watch_unlock_cli"


def ask_irk():
    print(
        "\nOn your Mac, open Keychain Access, choose iCloud and search for 'bluetooth'.\n"
        "Open the entry whose Account is 'Public: <your watch's Bluetooth address>'\n"
        "(Watch: Settings > General > About), tick 'Show password' and copy the\n"
        "base64 value under 'Remote IRK'. Paste it unchanged; input stays hidden."
    )
    while True:
        try:
            return decode_irk(getpass.getpass("Remote IRK: "))
        except ValueError as error:
            print(error)


def check_watch(cli, irk):
    while True:
        result = subprocess.run(
            [str(cli), "query_status", "--timeout-ms", "10000", irk],
            capture_output=True, text=True,
        )  # fmt: skip
        problem = watch_ready(result.stdout + result.stderr)
        if problem is None:
            print("Apple Watch found: unlocked, with Auto Unlock enabled.")
            return
        print(problem)
        if input("Retry? [Y/n] ").strip().lower() in {"n", "no"}:
            raise RuntimeError("The Apple Watch could not be verified; nothing was installed.")


def verify_lock(cli):
    """Authenticate through the real lock PAM service while the watch is nearby."""
    try:
        result = subprocess.run(
            [str(cli), "pam_test", getpass.getuser(), PAM_FILE.rsplit("/", 1)[1]],
            capture_output=True, text=True, timeout=60,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def install(state):
    if not (Path("/") / PAM_FILE).is_file():
        raise RuntimeError(f"/{PAM_FILE} is missing; this needs Omarchy's Quickshell lock.")
    if not confirm(
        "Unlock the Omarchy lock screen with your Apple Watch?\n"
        "Wake the lock, type any key and press Enter while wearing your unlocked watch.\n"
        "Builds the watch-unlock-rs PAM module from GitHub at a pinned commit, with\n"
        "this plugin's patches; may install git, clang, pkgconf and rust with pacman.\n"
        "Needs a Mac with Apple Watch Auto Unlock to copy the watch's IRK.\n"
        f"Writes /{MODULE_FILE} and /{CONF_FILE} (world-readable),\n"
        f"and adds one line to /{PAM_FILE}. Previous files are saved\n"
        f"under /{STATE_DIRECTORY}.\n"
        "This checks signal strength, not distance: a relayed watch signal could\n"
        "unlock the computer. Treat it as a convenience, not a security boundary."
    ):
        return
    with tempfile.TemporaryDirectory(prefix="omarchy-watch-unlock-build-") as directory:
        module, built_cli = build(Path(directory))
        cli = cli_path()
        cli.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built_cli, cli)
    irk = ask_irk()
    check_watch(cli, irk)
    module_b64 = base64.b64encode(module).decode()
    saved = elevate({"action": "install", "irk": irk, "module": module_b64})
    if saved is None:
        raise RuntimeError("The privileged phase did not report its backup; check the output.")
    if not verify_lock(cli):
        elevate({"action": "rollback", "backup": saved})
        raise RuntimeError("The lock screen PAM check failed; previous files were restored.")
    write_marker(state, saved)
    print("Ready. Lock with Super+Ctrl+L, then type any key and press Enter to unlock.")


def repair(state):
    if not confirm(
        f"An Omarchy update rewrote /{PAM_FILE} and removed Apple Watch unlock.\n"
        "Add the watch line back? Your password keeps working either way."
    ):
        return
    saved = elevate({"action": "repair"})
    write_marker(state, saved)
    print("Apple Watch unlock restored.")


def uninstall(state):
    if not confirm(
        f"Remove Apple Watch unlock from /{PAM_FILE} and forget your watch?\n"
        "The shared module is removed once no other user is configured."
    ):
        return
    elevate({"action": "remove"})
    (state / "installed.json").unlink(missing_ok=True)
    cli_path().unlink(missing_ok=True)
    print("Removed. Only your password unlocks the lock screen now.")


def write_marker(state, saved):
    pending = state / "installed.json.tmp"
    pending.write_text(json.dumps({"version": VERSION, "backup": saved}, indent=2) + "\n")
    pending.replace(state / "installed.json")


def launch(state):
    """Run at every shell start: open a terminal only when action is needed."""
    if not (state / "installed.json").exists():
        mode = ""
    else:
        try:
            if has_pam_line((Path("/") / PAM_FILE).read_text()):
                return
        except OSError:
            return
        mode = " --repair"
    command = f"/usr/bin/python {shlex.quote(str(Path(__file__).resolve()))}{mode}"
    run("omarchy-launch-floating-terminal-with-presentation", command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--launch", action="store_true", help="Open setup in a terminal if needed")
    mode.add_argument("--repair", action="store_true", help="Re-add the lock PAM line")
    mode.add_argument("--uninstall", action="store_true", help="Remove Apple Watch unlock")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise RuntimeError("Run as your desktop user, not root or sudo.")
    state = state_directory()
    if args.launch:
        launch(state)
        return
    state.mkdir(parents=True, exist_ok=True)
    with (state / "install.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Apple Watch unlock setup is already running.")
            return
        if args.repair:
            repair(state)
        elif args.uninstall:
            uninstall(state)
        else:
            install(state)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Apple Watch unlock setup cancelled.") from None
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Apple Watch unlock setup failed: {error}") from error
