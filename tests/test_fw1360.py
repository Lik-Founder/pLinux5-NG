"""Native VMCB fixture tests and source safety invariants; not PS5 boot tests."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Firmware1360Tests(unittest.TestCase):
    def test_vmcb_update_logic_on_native_fixtures(self):
        with tempfile.TemporaryDirectory(prefix="pl5-test-") as tmp:
            binary = Path(tmp) / "test_break_hv"
            subprocess.run([
                os.environ.get("HOST_CC", "cc"), "-std=c11", "-Wall", "-Wextra",
                "-Werror", "-I", str(ROOT / "include"),
                str(ROOT / "tests/test_break_hv.c"),
                str(ROOT / "source/shellcode/break_hv/break_hv.c"),
                "-o", str(binary),
            ], check=True)
            result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
            self.assertEqual(len(result.stdout.splitlines()), 5)

    def test_1360_diagnostic_returns_before_loading_linux(self):
        main = (ROOT / "source/main.c").read_text()
        diagnostic = main.index("if (fw == 0x1360)")
        stop = main.index("return hv_defeat_1360_post_resume();", diagnostic)
        fetch = main.index("if (fetch_linux(&linux_i))")
        self.assertLess(diagnostic, stop)
        self.assertLess(stop, fetch)
        self.assertNotIn("fetch_linux(", main[diagnostic:stop])

    def test_no_linux_staging_or_takeover_in_1360_vector(self):
        source = (ROOT / "source/hv/defeat/hv_defeat_1360.c").read_text()
        for unsafe_call in ("stage_hv_boot(", "takeover_bin", "fetch_linux(", "cave_hv_paging"):
            self.assertNotIn(unsafe_call, source)
        self.assertIn("state == PL5_COOKIE_HV_COMPLETE", source)
        self.assertIn("PL5_EXPECTED_CORE_MASK", source)
        self.assertIn("kh_restore(&resume_hook)", source)
        self.assertIn("poll < RESUME_POLLS", source)
        self.assertNotIn("enter_rest_mode(", source)

    def test_distinct_progress_and_completion_cookies(self):
        header = (ROOT / "include/hv/defeat/resume_status.h").read_text()
        values = re.findall(r"#define PL5_COOKIE_\w+ (0x[0-9A-Fa-f]+)ULL", header)
        self.assertEqual(len(values), 4)
        self.assertEqual(len(set(int(value, 16) for value in values)), 4)

    def test_compiled_main_fails_closed_on_native_fixtures(self):
        # Compile the actual diagnostic main with platform boundaries stubbed.
        # Fixtures do not perform kernel accesses, sleep, or contact a console.
        with tempfile.TemporaryDirectory(prefix="pl5-entry-") as tmp:
            tmp = Path(tmp)
            for header in ("hv_defeat_0304.h", "hv_defeat_0506.h", "hv_defeat_0607.h",
                           "hv_defeat_1320.h", "loader.h", "prepare_resume.h"):
                (tmp / header).write_text("/* native fixture stub */\n")
            (tmp / "hv_defeat_1360.h").write_text(
                "int hv_defeat_1360(void);\nint hv_defeat_1360_post_resume(void);\n")
            (tmp / "utils.h").write_text(
                "#include <stdint.h>\nextern uint32_t fw;\n"
                "unsigned int kernel_get_fw_version(void);\n"
                "int setup_env(void);\nvoid notify(const char *, ...);\n"
                "void enter_rest_mode(void);\n")
            binary = tmp / "entry-fixture"
            subprocess.run([
                os.environ.get("HOST_CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-D_POSIX_C_SOURCE=200809L", "-DPL5_FW1360_DIAGNOSTIC=1",
                "-I", str(tmp), str(ROOT / "tests/fw1360_entry_harness.c"),
                "-o", str(binary),
            ], check=True)
            cases = [
                ("0", "0", "0", "0", "result=-1 setup=0 arm=0 rest=0 post=0"),
                ("0x13200000", "0x1320", "0", "0", "result=-1 setup=0 arm=0 rest=0 post=0"),
                ("0x07610000", "0x0761", "0", "0", "result=-1 setup=0 arm=0 rest=0 post=0"),
                ("0x13600000", "0x1320", "0", "0", "result=-1 setup=1 arm=0 rest=0 post=0"),
                ("0x13600000", "0x1360", "-1", "0", "result=-1 setup=1 arm=0 rest=0 post=0"),
                ("0x13600000", "0x1360", "0", "-1", "result=-1 setup=1 arm=1 rest=0 post=0"),
                ("0x13600000", "0x1360", "0", "0", "result=0 setup=1 arm=1 rest=1 post=1"),
            ]
            for *args, expected in cases:
                with self.subTest(args=args):
                    result = subprocess.run([str(binary), *args], check=True, capture_output=True, text=True)
                    self.assertIn("NATIVE_FIXTURE_ONLY " + expected, result.stdout)
                    self.assertIn("FW1360_DIAGNOSTIC_V2", result.stdout)

    def test_hv_physical_base_is_not_a_leading_zero_bug(self):
        self.assertEqual(int("062800000", 16), int("62800000", 16))


if __name__ == "__main__":
    unittest.main()
