"""Smoke-check the installed .deb without contacting xrdp or an authenticator."""

import ctypes
import importlib
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path("/usr/lib/edge-to-rdp-webauthn-redirect")


def main():
    sys.path.insert(0, str(ROOT))
    for name in ("rdpewa", "webauthn", "native_host", "install_native"):
        module = importlib.import_module(name)
        if Path(module.__file__).parent != ROOT:
            raise RuntimeError(f"{name} was not loaded from the installed package")
    rdpewa = sys.modules["rdpewa"]
    if rdpewa.LIBRARY != str(ROOT / "libxrdpapi.so"):
        raise RuntimeError("The installed helper did not select its private library")
    ctypes.CDLL(rdpewa.LIBRARY)
    dependencies = subprocess.run(
        ["ldd", "/usr/bin/rdpewa-probe"], check=True, capture_output=True, text=True,
    )
    if str(ROOT / "libxrdpapi.so.0") not in dependencies.stdout:
        raise RuntimeError("The installed probe did not resolve its private library")
    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(["edge-rdp-webauthn-setup", "--help"], cwd=directory, check=True)
        result = subprocess.run(
            ["rdpewa-probe", "0"], cwd=directory, capture_output=True, text=True,
        )
        if result.returncode != 2 or "Usage:" not in result.stderr:
            raise RuntimeError("The installed probe could not run")
    print("Installed helper imports, private library, setup command and probe passed.")


if __name__ == "__main__":
    main()
