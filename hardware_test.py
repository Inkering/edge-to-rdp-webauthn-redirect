"""Disposable controlled-RP registration/assertion test; no credential logging."""

import hashlib
import json
import secrets
import sys
import uuid

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from rdpewa import BridgeError, exchange, rpc, unwrap
from webauthn import auth_data, b64


RP_ID = "localhost"
ORIGIN = "http://localhost:8765"


def client_data(kind):
    return json.dumps({
        "type": f"webauthn.{kind}",
        "challenge": b64(secrets.token_bytes(32)),
        "origin": ORIGIN,
        "crossOrigin": False,
    }, separators=(",", ":")).encode()


def request(kind, inner, data, resident=False):
    cancellation_id = uuid.uuid4().bytes_le
    return rpc(
        5, flags=0x00400000, timeout=60000,
        request=bytes([kind]) + cbor2.dumps(inner),
        clientDataJSON=data,
        webAuthNPara={
            "wnd": 0, "attachment": 2, "requireResident": resident,
            "preferResident": False, "userVerification": 1,
            "attestationPreference": 1, "enterpriseAttestation": 0,
            "cancellationId": cancellation_id,
        },
    )


def check_auth_data(data, registration=False):
    auth_data(data, RP_ID, require_uv=True, registration=registration)
    flags = data[32]
    return flags, int.from_bytes(data[33:37], "big")


def registration_key(data):
    return auth_data(data, RP_ID, require_uv=True, registration=True)


def verify_assertion(assertion, credential_id, public_key, data):
    credential = assertion.get(1, {})
    if credential.get("type") != "public-key" or credential.get("id") != credential_id:
        raise BridgeError("verification: assertion credential ID mismatch")
    auth_data = assertion.get(2)
    flags, counter = check_auth_data(auth_data)
    signature = assertion.get(3)
    if not isinstance(signature, bytes) or not signature:
        raise BridgeError("verification: missing assertion signature")
    try:
        public_key.verify(
            signature, auth_data + hashlib.sha256(data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature:
        raise BridgeError("verification: INVALID assertion signature") from None
    return flags, counter


def main():
    if sys.argv[1:] not in (["--run"], ["--run", "--resident"]):
        print("Usage: python hardware_test.py --run [--resident]\n"
              "Creates a disposable credential for localhost. --resident writes "
              "a discoverable passkey to the key; remove it afterwards. "
              "Requires Windows security UI and YubiKey touches; "
              "enter any PIN only into Windows.", file=sys.stderr)
        return 2
    resident = "--resident" in sys.argv[1:]
    user_id = secrets.token_bytes(32)
    print("Registering disposable localhost ES256 credential; "
          "approve Windows security-key UI and touch YubiKey.", flush=True)
    create_data = client_data("create")
    create = request(1, {
        1: hashlib.sha256(create_data).digest(),
        2: {"id": RP_ID, "name": "Local RDPEWA disposable test"},
        3: {"id": user_id, "name": "disposable",
            "displayName": "Disposable RDPEWA test"},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": resident},
    }, create_data, resident=resident)
    outer = exchange(create)
    registration = unwrap(outer)
    if resident and outer.get("deviceInfo", {}).get("residentKey") is not True:
        raise BridgeError("verification: resident credential was not confirmed")
    credential_id, key = registration_key(registration.get(2))
    print("Registration returned an ES256 key with UP=1 UV=1. "
          "Requesting GetAssertion; approve Windows UI and touch again.", flush=True)
    get_data = client_data("get")
    get_inner = {
        1: RP_ID, 2: hashlib.sha256(get_data).digest(),
        5: {"up": True},
    }
    if not resident:
        get_inner[3] = [{"type": "public-key", "id": credential_id}]
    get = request(2, get_inner, get_data)
    assertion = unwrap(exchange(get))
    if resident and assertion.get(4, {}).get("id") != user_id:
        raise BridgeError("verification: discoverable user handle mismatch")
    flags, counter = verify_assertion(assertion, credential_id, key, get_data)
    print(f"VERIFIED real GetAssertion: signature valid; RP ID hash valid; "
          f"UP=1 UV=1 flags=0x{flags:02x} counter={counter}. "
          "Credential ID and public key discarded; no payload persisted.")
    print("This is proof of key possession, not a trusted hardware-attestation "
          "or YubiKey model/vendor verification.")
    if resident:
        print("Discoverable passkey verified without allowCredentials. "
              "Remove the disposable localhost passkey from the YubiKey afterwards.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BridgeError, ValueError, cbor2.CBORDecodeError) as error:
        print(f"ERROR hardware test: {error}", file=sys.stderr)
        sys.exit(1)
