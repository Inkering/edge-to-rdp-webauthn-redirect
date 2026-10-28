import ctypes
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SYSTEM_LIBRARY = "/usr/lib/x86_64-linux-gnu/xrdp"


@unittest.skipUnless((ROOT / "build/local-api/libxrdpapi.so").exists(),
                     "run make local-api to check the timeout-patched upstream API")
class LocalApiTests(unittest.TestCase):
    def test_open_accepts_acknowledgement_later_than_500ms(self):
        with tempfile.TemporaryDirectory(prefix="rdpewa-api-") as directory:
            library_path = Path(directory) / "libtestapi.so"
            subprocess.run([
                "cc", "-fPIC", "-shared", "-DCONFIG_AC_H", "-DHAVE_STDINT_H",
                "-DHAVE_FUNC_ATTRIBUTE_FORMAT", f'-DXRDP_SOCKET_PATH="{directory}"',
                "-I" + str(ROOT / "build/xrdpapi-src/common"),
                "-I" + str(ROOT / "build/xrdpapi-src/xrdpapi"),
                str(ROOT / "build/local-api/xrdpapi.c"), "-L" + SYSTEM_LIBRARY,
                "-Wl,-rpath," + SYSTEM_LIBRARY, "-lcommon", "-o", str(library_path),
            ], check=True, capture_output=True)
            library = ctypes.CDLL(str(library_path))
            library.WTSVirtualChannelOpenEx.argtypes = [
                ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint,
            ]
            library.WTSVirtualChannelOpenEx.restype = ctypes.c_void_p
            library.WTSVirtualChannelClose.argtypes = [ctypes.c_void_p]
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(Path(directory) / "xrdpapi_123"))
                listener.listen(1)
                listener.settimeout(5)

                def acknowledge():
                    with listener.accept()[0] as endpoint:
                        endpoint.settimeout(5)
                        request = bytearray()
                        while len(request) < 32:
                            chunk = endpoint.recv(32 - len(request))
                            if not chunk:
                                raise RuntimeError("API caller closed before acknowledgement")
                            request.extend(chunk)
                        time.sleep(0.8)
                        endpoint.sendall(bytes(4))
                        return bytes(request)

                with ThreadPoolExecutor(1) as executor, \
                        patch.dict("os.environ", DISPLAY=":123.0"):
                    response = executor.submit(acknowledge)
                    started = time.monotonic()
                    handle = library.WTSVirtualChannelOpenEx(
                        0xffffffff, b"WebAuthN_Channel", 1,
                    )
                    elapsed = time.monotonic() - started
                    try:
                        self.assertTrue(handle, "must not fail at the old 500ms deadline")
                    finally:
                        if handle:
                            self.assertEqual(library.WTSVirtualChannelClose(handle), 1)
                    self.assertGreaterEqual(elapsed, 0.75)
                    self.assertLess(elapsed, 5)
                    self.assertEqual(
                        response.result(timeout=5),
                        struct.pack("<III", 32, 0, 16)
                        + b"WebAuthN_Channel" + struct.pack("<I", 1),
                    )
