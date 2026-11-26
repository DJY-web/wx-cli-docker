import importlib.util
from pathlib import Path
import tempfile
import unittest
import contextlib
import hashlib
import hmac
import io
import struct
import types
from unittest.mock import patch

source = Path(__file__).resolve().parents[2] / "crates/wx-keychain/src/linux_capture.py"
spec = importlib.util.spec_from_file_location("linux_capture", source)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class LocatorTests(unittest.TestCase):
    def test_arm64_adrp_add_resolves_known_rodata_reference(self):
        self.assertEqual(capture.address_use(0x90FC7F40, 0x91143000, 0x83F3BCC, "add"), (0x13DB50C, 0))

    def test_arm64_got_load_resolves_known_global(self):
        self.assertEqual(capture.address_use(0xD0010408, 0xF9444508, 0x83F3BC8, "load"), (0xA475888, 8))

    def test_unrelated_instruction_and_register_do_not_match(self):
        self.assertIsNone(capture.adrp_target(0, 0x1000))
        self.assertIsNone(capture.address_use(0x90FC7F40, 0x91143021, 0x83F3BCC, "add"))

    def test_invalid_and_unsupported_elf_fail_before_debugging(self):
        with tempfile.TemporaryDirectory() as root:
            file = Path(root) / "fake.elf"
            file.write_bytes(b"not an executable")
            with self.assertRaises(ValueError):
                capture.locate(file)
            blob = bytearray(64)
            blob[:6] = b"\x7fELF\x02\x01"
            blob[18:20] = (62).to_bytes(2, "little")
            file.write_bytes(blob)
            with self.assertRaisesRegex(ValueError, "ARM64"):
                capture.locate(file)

    def run_fake_capture(self, valid):
        key = bytes([0xA5] * 32)
        salt = bytes([0x17] * 16)
        page = bytearray(4096)
        page[:16] = salt
        derived = hashlib.pbkdf2_hmac("sha512", key, salt, 256000, 32)
        mac = hashlib.pbkdf2_hmac("sha512", derived, bytes(b ^ 0x3A for b in salt), 2, 32)
        page[4032:] = hmac.new(mac, bytes(page[16:4032]) + struct.pack("<I", 1), "sha512").digest()
        candidate = key if valid else bytes([0xBB] * 32)
        class Inferior:
            def read_memory(self, pointer, size):
                data = struct.pack("<QQQ", 0, 0x2000, 32) if pointer == 0x1000 else candidate
                return memoryview(data[:size])
        class Breakpoint:
            instance = None
            def __init__(self, *args, **kwargs):
                Breakpoint.instance = self
            def delete(self):
                pass
        def execute(command):
            if command == "continue":
                Breakpoint.instance.stop()
        fake = types.SimpleNamespace(Breakpoint=Breakpoint, error=RuntimeError, execute=execute,
                                     parse_and_eval=lambda _: 0x1000, selected_inferior=lambda: Inferior())
        with tempfile.TemporaryDirectory() as root:
            database = Path(root) / "fake.db"
            database.write_bytes(page)
            output = Path(root) / "private-output"
            log = io.StringIO()
            with patch.dict("sys.modules", {"gdb": fake}), contextlib.redirect_stdout(log):
                exec(capture.GDB_CODE, {"DB_FILES": [str(database)], "OUTPUT": str(output), "HOOK": 0x1000})
            self.assertEqual(output.exists(), valid)
            self.assertNotIn(key.hex(), log.getvalue())
            if valid:
                self.assertEqual(output.read_text(), key.hex())
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_capture_saves_only_hmac_validated_key_privately(self):
        self.run_fake_capture(True)

    def test_capture_never_saves_an_unverified_key(self):
        self.run_fake_capture(False)
