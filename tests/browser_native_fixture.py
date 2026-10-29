"""Synthetic-only native host for isolated Edge API smoke tests, never hardware evidence."""

import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import native_host
from rdpewa import BridgeError, MAX_REQUEST, decode_one
from test_webauthn import attested_data, authenticator_data, envelope


def worker():
    request = decode_one(sys.stdin.buffer.read(MAX_REQUEST + 1))
    command = request["command"]
    if command == 8:
        result = 9
    elif command == 6:
        result = 0
    elif command == 5:
        inner = decode_one(request["request"][1:])
        operation = request["request"][0]
        rp = inner[2]["id"] if operation == 1 else inner[1]
        if rp != "localhost":
            raise BridgeError("Synthetic fixture is restricted to localhost")
        # Publicly known test key: cannot demonstrate any authenticator or user presence.
        key = ec.derive_private_key(1, ec.SECP256R1())
        delay = float(os.environ.get("XRDP_WEBAUTHN_SYNTHETIC_DELAY", "0.5"))
        if not 0 <= delay <= 65:
            raise BridgeError("Synthetic delay must be between 0 and 65 seconds")
        time.sleep(delay)
        if operation == 1:
            data, _ = attested_data(rp, key)
            result = envelope({2: data}, deviceInfo={"residentKey": False})
        elif operation == 2 and inner.get(3):
            data = authenticator_data(rp)
            result = envelope({
                1: inner[3][0], 2: data,
                3: key.sign(data + inner[2], ec.ECDSA(hashes.SHA256())),
            })
        else:
            raise BridgeError("Synthetic fixture supports non-discoverable create/get only")
    else:
        raise BridgeError("Synthetic fixture received an unsupported command")
    sys.stdout.buffer.write(cbor2.dumps(result))


def start(request):
    return subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True,
    ), cbor2.dumps(request)


if __name__ == "__main__":
    if os.environ.get("XRDP_WEBAUTHN_SYNTHETIC_TEST") != "1":
        sys.exit("Refusing to run: set XRDP_WEBAUTHN_SYNTHETIC_TEST=1 only for an isolated test")
    try:
        if sys.argv[1:] == ["--worker"]:
            worker()
        else:
            print("SYNTHETIC TEST ONLY: no xrdp channel, Windows client or authenticator",
                  file=sys.stderr, flush=True)
            with patch("native_host.start", start):
                native_host.main()
    except (BridgeError, OSError, ValueError, KeyError, cbor2.CBORDecodeError) as error:
        print(f"ERROR synthetic fixture: {error}", file=sys.stderr)
        sys.exit(1)
