import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import subprocess

SOURCE = Path(__file__).resolve().parents[1] / "src/omarchy_wireguard.py"
spec = importlib.util.spec_from_file_location("omarchy_wireguard", SOURCE)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class WireguardTests(unittest.TestCase):
    def test_import_rejects_hook_without_showing_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "test.conf"
            conf.write_text("[Interface]\nPrivateKey = SECRET\nPostUp = secret-command\n[Peer]\nPublicKey = dummy\n")
            with self.assertRaisesRegex(ValueError, "строке 3") as caught:
                app.validate_conf(conf)
            self.assertNotIn("SECRET", str(caught.exception))
            self.assertNotIn("secret-command", str(caught.exception))

    def test_import_requires_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "test.conf"
            conf.write_text("[Interface]\nPrivateKey = dummy\n")
            with self.assertRaises(ValueError):
                app.validate_conf(conf)

    def test_status_ignores_foreign_connection(self):
        data = {"profiles": {}, "quick": None, "busy": None, "error": None}
        with patch.object(app, "read_state", return_value=data), patch.object(app, "active_uuids", return_value={"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                app.status()
            self.assertIn("inactive", out.getvalue())

    def test_switch_refuses_unowned_uuid(self):
        with patch.object(app, "lock_operation", return_value=contextlib.nullcontext()), patch.object(app, "read_state", return_value={"profiles": {}, "quick": None}):
            with self.assertRaisesRegex(ValueError, "не принадлежит"):
                app.change("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    def test_status_exposes_busy_without_nm_query(self):
        data = {"profiles": {}, "quick": None, "busy": "Переключение", "error": None}
        with patch.object(app, "read_state", return_value=data), patch.object(app, "active_owned", return_value=[]):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                app.status()
            self.assertIn("switching", out.getvalue())
            self.assertIn("WG:", out.getvalue())

    def test_permission_error_does_not_claim_handshake(self):
        denied = subprocess.CompletedProcess([], 1, "", "Operation not permitted")
        with patch.object(app, "connection_iface", return_value="wg0"), patch.object(app, "run", return_value=denied):
            message = app.handshake("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", {})
        self.assertIn("требует прав", message)
        self.assertNotIn("подтверждено", message)

    def test_recent_polkit_check_is_reported_with_timestamp_source(self):
        key = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        data = {"verification": {
            "profile": key, "interface": "wg0",
            "connection": "/org/freedesktop/NetworkManager/ActiveConnection/8",
            "checked_at": time.time(), "latest": int(time.time()),
        }}
        denied = subprocess.CompletedProcess([], 1, "", "Operation not permitted")
        with patch.object(app, "connection_iface", return_value="wg0"), patch.object(app, "active_connection_path", return_value=data["verification"]["connection"]), patch.object(app, "run", return_value=denied):
            message = app.handshake(key, data)
        self.assertIn("подтверждено", message)
        self.assertIn("Polkit", message)

    def test_polkit_result_is_discarded_after_reconnect(self):
        key = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        data = {"verification": {
            "profile": key, "interface": "wg0",
            "connection": "/org/freedesktop/NetworkManager/ActiveConnection/8",
            "checked_at": time.time(), "latest": int(time.time()),
        }}
        denied = subprocess.CompletedProcess([], 1, "", "Operation not permitted")
        with patch.object(app, "connection_iface", return_value="wg0"), patch.object(app, "active_connection_path", return_value="/org/freedesktop/NetworkManager/ActiveConnection/9"), patch.object(app, "run", return_value=denied):
            message = app.handshake(key, data)
        self.assertNotIn("подтверждено", message)

    def test_explicit_polkit_check_caches_only_timestamps(self):
        key = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        data = {"profiles": {key: "sample"}, "quick": key}
        result = subprocess.CompletedProcess([], 0, f"public-key\t{int(time.time())}\n", "")
        with patch.object(app, "read_state", return_value=data), patch.object(app, "active_owned", return_value=[key]), patch.object(app, "connection_iface", return_value="wg0"), patch.object(app, "active_connection_path", return_value="/org/freedesktop/NetworkManager/ActiveConnection/8"), patch.object(app, "run", return_value=result) as run, patch.object(app, "lock_operation", return_value=contextlib.nullcontext()), patch.object(app, "save"), patch.object(app, "notify"):
            app.verify_handshake()
        self.assertEqual(run.call_args.args[:3], ("pkexec", "/usr/bin/wg", "show"))
        self.assertEqual(data["verification"]["profile"], key)
        self.assertNotIn("public-key", json.dumps(data))

    def test_polkit_check_requires_owned_active_profile(self):
        with patch.object(app, "read_state", return_value={"profiles": {}}), patch.object(app, "active_owned", return_value=[]), patch.object(app, "run") as run:
            with self.assertRaisesRegex(ValueError, "активный профиль"):
                app.verify_handshake()
        run.assert_not_called()

    def test_rofi_colors_follow_omarchy_palette(self):
        source = "background: #1a1b26;\nforeground: #a9b1d6;\nselected: #292e42;\naccent: #7aa2f7;"
        palette = 'background = "#112233"\nforeground = "#eeeeee"\nselection = "#445566"\naccent = "#778899"'
        rendered = app.render_rofi_theme(source, palette)
        self.assertIn("background: #112233;", rendered)
        self.assertIn("selected: #445566;", rendered)
        self.assertIn("accent: #778899;", rendered)

    def test_import_disables_autoconnect_without_activation(self):
        key = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "sample.conf"
            conf.write_text("[Interface]\nPrivateKey = dummy\n[Peer]\nPublicKey = dummy\n")
            data = {"profiles": {}, "quick": None, "busy": None, "error": None}
            calls = []

            def fake_nm(*args, **kwargs):
                calls.append(args)
                output = f"Connection 'sample' ({key}) successfully added." if "import" in args else ""
                return subprocess.CompletedProcess(args, 0, output, "")

            with patch.object(app, "lock_operation", return_value=contextlib.nullcontext()), patch.object(app, "read_state", return_value=data), patch.object(app, "save"), patch.object(app, "notify"), patch.object(app, "nm", side_effect=fake_nm):
                app.import_files([str(conf)])
            self.assertEqual(data["profiles"][key], "sample")
            self.assertEqual(data["quick"], key)
            self.assertTrue(any("connection.autoconnect" in call and "no" in call for call in calls))
            self.assertFalse(any("up" in call for call in calls))

    def test_menu_shows_owned_profiles_only(self):
        key = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        data = {"profiles": {key: "sample"}, "quick": key, "busy": None, "error": None}
        shown = []

        def fake_choose(items, prompt="WireGuard"):
            shown.extend(items)
            return None

        with patch.object(app, "read_state", return_value=data), patch.object(app, "active_owned", return_value=[key]), patch.object(app, "choose", side_effect=fake_choose):
            app.menu()
        self.assertTrue(any("● sample" in item and "★" in item for item in shown))
        self.assertIn("Импортировать .conf…", shown)
        self.assertIn("Проверить рукопожатие…", shown)

    def test_failed_switch_offers_previous_profile_restore(self):
        old = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        new = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        data = {"profiles": {old: "old", new: "new"}, "quick": old, "busy": None, "error": None}
        calls = []

        def fake_nm(*args, **kwargs):
            calls.append(args)
            failed = "up" in args and new in args
            return subprocess.CompletedProcess(args, 1 if failed else 0, "", "")

        with patch.object(app, "lock_operation", return_value=contextlib.nullcontext()), patch.object(app, "read_state", return_value=data), patch.object(app, "active_owned", return_value=[old]), patch.object(app, "nm", side_effect=fake_nm), patch.object(app, "choose", return_value="Восстановить предыдущий профиль"), patch.object(app, "save"), patch.object(app, "notify"), patch.object(app.logging, "error"):
            with self.assertRaisesRegex(ValueError, "Не удалось включить"):
                app.change(new)
        self.assertTrue(any("down" in call and old in call for call in calls))
        self.assertTrue(any("up" in call and old in call for call in calls))
        self.assertIsNone(data["busy"])


if __name__ == "__main__":
    unittest.main()
