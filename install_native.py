"""Register a per-user, per-desktop Edge native host for an exact extension ID."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

from rdpewa import session_socket


def write_private(path, text, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w") as output:
        metadata = os.fstat(output.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            sys.exit("Native host files must be user-owned regular files")
        os.fchmod(output.fileno(), mode)
        output.truncate(0)
        output.write(text)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "extension_id", help="exact Edge extension ID (signed or unpacked)",
    )
    parser.add_argument(
        "--edge-user-data-dir", type=Path,
        default=Path.home() / ".config/microsoft-edge",
        help="Edge user-data root, not its Default/Profile directory",
    )
    args = parser.parse_args()
    if not re.fullmatch("[a-p]{32}", args.extension_id):
        parser.error("extension ID must contain exactly 32 letters in a..p")
    if os.environ.get("XRDP_SESSION") != "1" or not os.environ.get("DISPLAY"):
        sys.exit("Run this installer inside the intended xrdp desktop")
    root = Path(__file__).resolve().parent
    if not (root / ".venv/bin/python").exists():
        sys.exit("First create .venv and install requirements.txt")
    profile = args.edge_user_data_dir.expanduser().absolute()
    profile.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = profile.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        sys.exit("Edge user-data root must be a user-owned real directory")
    manifest_dir = profile / "NativeMessagingHosts"
    manifest_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = manifest_dir.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        sys.exit("Native messaging directory must be a user-owned real directory")
    os.chmod(manifest_dir, 0o700)
    directory = Path.home() / ".local/lib/linux-rdpewa"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        sys.exit("Native host directory must be a user-owned real directory")
    os.chmod(directory, 0o700)
    origin = f"chrome-extension://{args.extension_id}/"
    config = directory / "session.json"
    write_private(config, json.dumps({
        "uid": os.getuid(), "display": os.environ["DISPLAY"], "origin": origin,
        "socketIdentity": session_socket(),
    }))
    launcher = directory / "native-host"
    write_private(launcher,
        "#!/bin/sh\nexec " + " ".join(shlex.quote(str(path)) for path in (
            root / ".venv/bin/python", root / "native_host.py", config
        )) + ' "$@"\n', mode=0o700
    )
    manifest = manifest_dir / "org.local.xrdp_webauthn.json"
    write_private(manifest, json.dumps({
        "name": "org.local.xrdp_webauthn", "description": "Linux Edge to RDP WebAuthn Redirect native host",
        "path": str(launcher), "type": "stdio", "allowed_origins": [origin],
    }, indent=2) + "\n")
    print(f"Installed {manifest}; bound to this user, extension and DISPLAY.")
    print("Reconnect the extension using its toolbar button. Keep this source "
          "directory and .venv in place.")


if __name__ == "__main__":
    main()
