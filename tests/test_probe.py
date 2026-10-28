import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ProbeTests(unittest.TestCase):
    def run_probe(self, mode, expected, text, args=("1",)):
        environment = dict(
            os.environ, DISPLAY=":10.0", PROBE_TEST_MODE=mode,
            LD_PRELOAD=str(ROOT / "build/libxrdpapi.so"),
        )
        result = subprocess.run(
            [str(ROOT / "build/rdpewa-probe"), *args], env=environment,
            capture_output=True, text=True, timeout=3,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertIn(text, result.stdout + result.stderr)

    def test_exchange(self):
        for mode in ("normal", "fragmented", "retry-write"):
            with self.subTest(mode=mode):
                self.run_probe(mode, 0, "version=9")

    def test_errors(self):
        for mode, code, text in (
            ("open-error", 3, "ERROR open"),
            ("write-error", 4, "ERROR write"),
            ("partial-write", 4, "partial DVC"),
            ("read-error", 5, "ERROR read"),
            ("oversize", 6, "exceeds 8 bytes"),
            ("hresult", 7, "HRESULT=0x80000005"),
            ("version-zero", 8, "API version 0"),
            ("close-error", 9, "ERROR close"),
        ):
            with self.subTest(mode=mode):
                self.run_probe(mode, code, text)

    def test_deadlines(self):
        for mode in ("open-hang", "write-hang", "read-hang", "truncated"):
            with self.subTest(mode=mode):
                self.run_probe(mode, 124, "deadline exceeded")

    def test_invalid_deadline(self):
        for value in ("0", "121", "abc", "-1"):
            with self.subTest(value=value):
                self.run_probe("normal", 2, "Usage:", (value,))
