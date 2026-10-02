import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import setup_watch_unlock as setup

IRK = base64.b64encode(bytes(range(16))).decode()
STOCK_PAM = """#%PAM-1.0
auth       required                    pam_faillock.so preauth silent deny=10 unlock_time=120
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so try_first_pass nullok
auth       [default=die]               pam_faillock.so authfail deny=10 unlock_time=120
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so authsucc
account    include                     system-local-login
"""


def no_owner(_path):
    return None


class PureHelperTests(unittest.TestCase):
    def test_irk_must_be_base64_of_sixteen_bytes(self):
        self.assertEqual(setup.decode_irk(f" {IRK}\n"), IRK)
        for bad in ("not base64!", base64.b64encode(b"short").decode()):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                setup.decode_irk(bad)

    def test_pam_line_goes_after_preauth_before_unix(self):
        lines = setup.add_pam_line(STOCK_PAM).splitlines()
        self.assertEqual(lines[2], setup.PAM_LINE)
        self.assertIn("pam_faillock.so preauth", lines[1])
        # Relative [success=N] jumps after the insertion keep their targets.
        self.assertEqual(lines[3:], STOCK_PAM.splitlines()[2:])

    def test_pam_insert_is_idempotent_and_keeps_tuned_lines(self):
        once = setup.add_pam_line(STOCK_PAM)
        self.assertEqual(setup.add_pam_line(once), once)
        tuned = once.replace("search_timeout_ms=3000", "search_timeout_ms=5000")
        self.assertEqual(setup.add_pam_line(tuned), tuned)

    def test_unknown_pam_layout_is_refused(self):
        for text in ("auth required pam_unix.so\n", STOCK_PAM + STOCK_PAM.splitlines()[1]):
            with self.subTest(text=text), self.assertRaises(ValueError):
                setup.add_pam_line(text)

    def test_pam_removal_restores_stock_file(self):
        self.assertEqual(setup.remove_pam_line(setup.add_pam_line(STOCK_PAM)), STOCK_PAM)
        self.assertFalse(setup.has_pam_line(STOCK_PAM))

    def test_conf_entries_are_per_user(self):
        text = setup.set_conf_entry("", "alice", IRK)
        text = setup.set_conf_entry(text, "bob", "b")
        text = setup.set_conf_entry(text, "alice", "a")
        self.assertEqual(setup.conf_entries(text), ["alice;a", "bob;b"])
        self.assertEqual(setup.conf_entries(setup.remove_conf_entry(text, "alice")), ["bob;b"])

    def test_watch_status_is_interpreted(self):
        ready = (
            "Found Apple Watch after 1 tries\n"
            "RSSI....: -60\n"
            "Locked....: false\n"
            "Auto-unlock devices enabled...: true"
        )
        self.assertIsNone(setup.watch_ready(ready))
        self.assertIn("not found", setup.watch_ready("retries (1) exceeded"))
        self.assertIn("too far", setup.watch_ready(ready.replace("-60", "-91")))
        self.assertIn("locked", setup.watch_ready(ready.replace("false", "true")))
        self.assertIn("Unlock with", setup.watch_ready(ready.replace(": true", ": false")))


class PrivilegedPhaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.pam = self.root / setup.PAM_FILE
        self.conf = self.root / setup.CONF_FILE
        self.library = self.root / setup.MODULE_FILE
        self.pam.parent.mkdir(parents=True)
        self.pam.write_text(STOCK_PAM)
        self.pam.chmod(0o644)

    def tearDown(self):
        self.directory.cleanup()

    def test_install_writes_module_conf_and_pam(self):
        saved = setup.apply(self.root, "alice", IRK, b"module", owner=no_owner)
        self.assertEqual(self.library.read_bytes(), b"module")
        self.assertEqual(self.library.stat().st_mode & 0o777, 0o755)
        self.assertEqual(setup.conf_entries(self.conf.read_text()), [f"alice;{IRK}"])
        self.assertEqual(self.conf.stat().st_mode & 0o777, 0o644)
        self.assertTrue(setup.has_pam_line(self.pam.read_text()))
        self.assertEqual(self.pam.stat().st_mode & 0o777, 0o644)
        self.assertEqual((saved / setup.PAM_FILE).read_text(), STOCK_PAM)

    def test_rollback_restores_previous_state(self):
        saved = setup.apply(self.root, "alice", IRK, b"module", owner=no_owner)
        setup.restore(self.root, saved)
        self.assertEqual(self.pam.read_text(), STOCK_PAM)
        self.assertFalse(self.conf.exists())
        self.assertFalse(self.library.exists())

    def test_failed_write_restores_files(self):
        real_write = setup.atomic_write

        def fail_on_pam(path, data, mode):
            if path == self.pam:
                raise OSError("disk full")
            real_write(path, data, mode)

        with (
            mock.patch.object(setup, "atomic_write", side_effect=fail_on_pam),
            self.assertRaises(OSError),
        ):
            setup.apply(self.root, "alice", IRK, b"module", owner=no_owner)
        # The module and config were written before the failure, then undone.
        self.assertEqual(self.pam.read_text(), STOCK_PAM)
        self.assertFalse(self.library.exists())
        self.assertFalse(self.conf.exists())

    def test_package_owned_module_is_not_replaced(self):
        self.library.parent.mkdir(parents=True)
        self.library.write_bytes(b"packaged")
        with self.assertRaises(ValueError):
            setup.apply(self.root, "alice", IRK, b"module", owner=lambda _p: "watch-unlock-rs")
        self.assertEqual(self.library.read_bytes(), b"packaged")

    def test_symlinked_pam_file_is_refused(self):
        real = self.root / "real"
        real.write_text(STOCK_PAM)
        self.pam.unlink()
        self.pam.symlink_to(real)
        with self.assertRaises(ValueError):
            setup.apply(self.root, "alice", IRK, b"module", owner=no_owner)

    def test_repair_needs_an_existing_install(self):
        with self.assertRaises(ValueError):
            setup.apply(self.root, "alice", owner=no_owner)
        setup.apply(self.root, "alice", IRK, b"module", owner=no_owner)
        self.pam.write_text(STOCK_PAM)
        setup.apply(self.root, "alice", owner=no_owner)
        self.assertTrue(setup.has_pam_line(self.pam.read_text()))
        with self.assertRaises(ValueError):
            setup.apply(self.root, "bob", owner=no_owner)

    def test_remove_keeps_shared_files_for_other_users(self):
        setup.apply(self.root, "alice", IRK, b"module", owner=no_owner)
        setup.apply(self.root, "bob", IRK, b"module", owner=no_owner)
        setup.remove(self.root, "alice", owner=no_owner)
        self.assertEqual(setup.conf_entries(self.conf.read_text()), [f"bob;{IRK}"])
        self.assertTrue(self.library.exists())
        self.assertEqual(self.pam.read_text(), STOCK_PAM)
        setup.remove(self.root, "bob", owner=no_owner)
        self.assertFalse(self.conf.exists())
        self.assertFalse(self.library.exists())

    def test_restore_rejects_foreign_directories(self):
        with self.assertRaises(ValueError):
            setup.restore(self.root, self.root / "tmp")


class DesktopPhaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.state = Path(self.directory.name) / "state"
        self.state.mkdir()

    def tearDown(self):
        self.directory.cleanup()

    def launch_with(self, pam_text):
        with (
            mock.patch.object(Path, "read_text", return_value=pam_text),
            mock.patch.object(setup, "run") as run,
        ):
            setup.launch(self.state)
        return run

    def test_launch_opens_setup_until_installed(self):
        run = self.launch_with(STOCK_PAM)
        self.assertNotIn("--repair", run.call_args.args[1])

    def test_launch_offers_repair_when_update_drops_line(self):
        (self.state / "installed.json").write_text("{}")
        run = self.launch_with(STOCK_PAM)
        self.assertTrue(run.call_args.args[1].endswith("--repair"))

    def test_launch_is_silent_when_configured(self):
        (self.state / "installed.json").write_text("{}")
        self.launch_with(setup.add_pam_line(STOCK_PAM)).assert_not_called()

    def test_elevation_freezes_sources_and_reports_backup(self):
        completed = subprocess.CompletedProcess([], 0, stdout="BACKUP=/var/lib/x/backup-1\n")
        with (
            mock.patch.object(setup, "run", return_value=completed) as run,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            saved = setup.elevate({"action": "repair"})
        self.assertEqual(saved, "/var/lib/x/backup-1")
        self.assertIn("backup-1", output.getvalue())
        self.assertEqual(run.call_args.args[:4], ("sudo", "/usr/bin/python", "-I", "-c"))
        payload = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(payload["request"], {"action": "repair"})
        self.assertIn("def configure", payload["sources"]["setup_watch_unlock.py"])

    def test_failed_lock_check_rolls_back(self):
        with (
            mock.patch.object(Path, "is_file", return_value=True),
            mock.patch.object(setup, "confirm", return_value=True),
            mock.patch.object(setup, "build", return_value=(b"so", Path("/bin/true"))),
            mock.patch.object(setup, "cli_path", return_value=Path(self.directory.name) / "cli"),
            mock.patch.object(setup, "ask_irk", return_value=IRK),
            mock.patch.object(setup, "check_watch"),
            mock.patch.object(setup, "elevate", return_value="/backup") as elevate,
            mock.patch.object(setup, "verify_lock", return_value=False),
            self.assertRaises(RuntimeError),
        ):
            setup.install(self.state)
        self.assertEqual(elevate.call_args.args[0], {"action": "rollback", "backup": "/backup"})
        self.assertFalse((self.state / "installed.json").exists())

    def test_configure_trusts_only_sudo_user(self):
        with (
            mock.patch.object(os, "geteuid", return_value=0),
            mock.patch.dict(os.environ, {"SUDO_USER": "root"}),
            self.assertRaises(RuntimeError),
        ):
            setup.configure({"action": "repair"})


class PatchTests(unittest.TestCase):
    def test_patches_exist_and_target_the_pinned_tree(self):
        for patch in setup.PATCHES:
            with self.subTest(patch=patch):
                text = (setup.PLUGIN / patch).read_text()
                self.assertTrue(text.startswith("From "))
                self.assertIn("diff --git", text)


if __name__ == "__main__":
    unittest.main()
