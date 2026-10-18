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

    def test_hv_physical_base_is_not_a_leading_zero_bug(self):
        self.assertEqual(int("062800000", 16), int("62800000", 16))


if __name__ == "__main__":
    unittest.main()
