"""Strict, small WebAuthn subset: same-origin, ES256, roaming authenticators."""

import base64
import binascii
from dataclasses import dataclass
import hashlib
import io
import json
import re
from urllib.parse import urlsplit
import uuid

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rdpewa import BridgeError, rpc, unwrap


class RequestError(BridgeError):
    def __init__(self, message, name="NotSupportedError"):
        super().__init__(message)
        self.name = name


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise RequestError("Invalid base64url input", "DataError")
    try:
        data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except binascii.Error:
        raise RequestError("Invalid base64url input", "DataError") from None
    if b64(data) != value:
        raise RequestError("Noncanonical base64url input", "DataError")
    return data


def auth_data(data, rp_id, require_uv, registration=False):
    if not isinstance(data, bytes) or len(data) < 37:
        raise BridgeError("verification: truncated authenticatorData")
    if data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise BridgeError("verification: RP ID hash mismatch")
    flags = data[32]
    if not flags & 1 or (require_uv and not flags & 4):
        raise BridgeError("verification: signed UP/UV requirements not satisfied")
    if flags & 0x22 or (flags & 0x10 and not flags & 0x08):
        raise BridgeError("verification: invalid authenticator flags")
    if bool(flags & 0x40) != registration:
        raise BridgeError("verification: invalid attested-credential flag")
    offset, credential_id, public_key = 37, None, None
    if registration:
        if len(data) < 55:
            raise BridgeError("verification: truncated attested credential")
        size = int.from_bytes(data[53:55], "big")
        offset = 55 + size
        if not size or offset >= len(data):
            raise BridgeError("verification: invalid credential ID length")
        credential_id = data[55:offset]
        stream = io.BytesIO(data[offset:])
        key = cbor2.CBORDecoder(stream).decode()
        offset += stream.tell()
        if not isinstance(key, dict) or (
            key.get(1), key.get(3), key.get(-1)
        ) != (2, -7, 1):
            raise BridgeError("verification: expected ES256/P-256 public key")
        x, y = key.get(-2), key.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise BridgeError("verification: invalid EC coordinates")
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    if flags & 0x80:
        stream = io.BytesIO(data[offset:])
        extensions = cbor2.CBORDecoder(stream).decode()
        offset += stream.tell()
        if not isinstance(extensions, dict):
            raise BridgeError("verification: extensions are not a CBOR map")
    if offset != len(data):
        raise BridgeError("verification: trailing authenticatorData bytes")
    return credential_id, public_key


@dataclass
class Prepared:
    kind: str
    rpc: dict
    client_data: bytes
    rp_id: str
    require_uv: bool
    credentials: list
    resident_required: bool = False
    cred_props: bool = False


def descriptors(values):
    if not isinstance(values, list):
        raise RequestError("Invalid credential list", "DataError")
    result = []
    for item in values:
        if not isinstance(item, dict) or item.get("type") != "public-key":
            raise RequestError("Invalid credential descriptor", "DataError")
        if set(item) - {"id", "type", "transports"}:
            raise RequestError("Unsupported credential descriptor field")
        descriptor = {"type": "public-key", "id": unb64(item.get("id"))}
        if len(descriptor["id"]) > 1024:
            raise RequestError("Credential ID exceeds PoC limit")
        if "transports" in item:
            masks = {"usb": 1, "nfc": 2, "ble": 4, "internal": 16,
                     "hybrid": 32, "smart-card": 64}
            if not isinstance(item["transports"], list) or any(
                transport not in masks for transport in item["transports"]
            ):
                raise RequestError("Unsupported credential transport")
            descriptor["transports"] = sum(
                masks[transport] for transport in set(item["transports"])
            )
        result.append(descriptor)
    return result


def prepare(kind, options):
    if kind not in ("create", "get") or not isinstance(options, dict):
        raise RequestError("Invalid browser request", "DataError")
    allowed = {
        "challenge", "timeout", "extensions", "hints",
        *(("rp", "user", "pubKeyCredParams", "excludeCredentials",
           "authenticatorSelection", "attestation", "attestationFormats")
          if kind == "create"
          else ("rpId", "allowCredentials", "userVerification"))
    }
    if set(options) - allowed:
        raise RequestError("Unsupported WebAuthn option")
    extensions = options.get("extensions", {})
    if not isinstance(extensions, dict):
        raise RequestError("Invalid extensions", "DataError")
    if set(extensions) - {"remoteDesktopClientOverride", "credProps"}:
        raise RequestError("Unsupported WebAuthn extension; refusing to downgrade")
    if "credProps" in extensions and (kind != "create" or extensions["credProps"] is not True):
        raise RequestError("Unsupported credProps value")
    context = extensions.get("remoteDesktopClientOverride")
    if not isinstance(context, dict) or set(context) != {"origin", "sameOriginWithAncestors"}:
        raise RequestError("Missing browser-authenticated caller context", "SecurityError")
    if context["sameOriginWithAncestors"] is not True:
        raise RequestError("Cross-origin iframe context requires topOrigin; unsupported")
    origin = context["origin"]
    if not isinstance(origin, str):
        raise RequestError("Invalid origin", "SecurityError")
    parsed = urlsplit(origin)
    if (not parsed.hostname or parsed.username or parsed.password or parsed.path
            or parsed.query or parsed.fragment
            or (parsed.scheme != "https" and not (
                parsed.scheme == "http" and parsed.hostname == "localhost"
            ))):
        raise RequestError("Untrusted origin scheme or serialization", "SecurityError")
    rp = options.get("rp", {}) if kind == "create" else {}
    if not isinstance(rp, dict):
        raise RequestError("Invalid RP entity", "DataError")
    rp_id = rp.get("id") if kind == "create" else options.get("rpId")
    # Edge has already done public-suffix/RP validation before proxy dispatch.
    # Do not derive missing RP IDs or origins from tabs or user-controlled fields.
    if (not isinstance(rp_id, str) or not rp_id or rp_id != rp_id.lower()
            or not (parsed.hostname == rp_id or parsed.hostname.endswith("." + rp_id))):
        raise RequestError("RP ID is missing or inconsistent with trusted origin", "SecurityError")
    challenge = unb64(options.get("challenge"))
    if options.get("hints", []) not in ([], ["security-key"]):
        raise RequestError("Only the security-key hint is supported")
    selection = options.get("authenticatorSelection", {}) if kind == "create" else {}
    if not isinstance(selection, dict) or set(selection) - {
        "authenticatorAttachment", "residentKey", "requireResidentKey", "userVerification"
    }:
        raise RequestError("Unsupported authenticator selection")
    if selection.get("authenticatorAttachment") not in (None, "cross-platform"):
        raise RequestError("This PoC only supports roaming authenticators")
    uv = (selection if kind == "create" else options).get("userVerification", "preferred")
    if uv not in ("required", "preferred", "discouraged"):
        raise RequestError("Invalid userVerification value", "DataError")
    timeout = options.get("timeout", 60000)
    if type(timeout) is not int or timeout <= 0:
        raise RequestError("Invalid timeout", "DataError")
    # A shorter deadline is permitted; never extend the browser's deadline.
    timeout = min(timeout, 60000)
    client_data = json.dumps({
        "type": f"webauthn.{kind}", "challenge": b64(challenge),
        "origin": origin, "crossOrigin": False,
    }, separators=(",", ":"), ensure_ascii=True).encode()
    digest = hashlib.sha256(client_data).digest()
    resident_required = False
    params = {
        "wnd": 0, "attachment": 2,
        "requireResident": False, "preferResident": False,
        "userVerification": {"required": 1, "preferred": 2, "discouraged": 3}[uv],
        "attestationPreference": 1, "enterpriseAttestation": 0,
        "cancellationId": uuid.uuid4().bytes_le,
    }
    if kind == "create":
        if options.get("attestation", "none") != "none" or options.get("attestationFormats", []):
            raise RequestError("Only attestation=none is supported")
        algorithms = options.get("pubKeyCredParams")
        if not isinstance(algorithms, list) or not any(
            item == {"type": "public-key", "alg": -7} for item in algorithms
        ):
            raise RequestError("The PoC requires ES256 in pubKeyCredParams")
        user = options.get("user")
        if not isinstance(user, dict) or set(user) - {"id", "name", "displayName"}:
            raise RequestError("Invalid user entity", "DataError")
        user_id = unb64(user.get("id"))
        if not 1 <= len(user_id) <= 64 or any(
            not isinstance(user.get(key), str) for key in ("name", "displayName")
        ):
            raise RequestError("Invalid user entity", "DataError")
        if set(rp) - {"id", "name"} or not isinstance(rp.get("name"), str):
            raise RequestError("Invalid RP entity", "DataError")
        resident = selection.get("residentKey")
        legacy = selection.get("requireResidentKey", False)
        if type(legacy) is not bool or resident not in (None, "required", "preferred", "discouraged"):
            raise RequestError("Invalid resident-key requirement", "DataError")
        resident_required = resident == "required" or (resident is None and legacy)
        params.update(requireResident=resident_required, preferResident=resident == "preferred")
        credentials = descriptors(options.get("excludeCredentials", []))
        inner = {
            1: digest, 2: rp, 3: {**user, "id": user_id},
            4: [{"type": "public-key", "alg": -7}], 5: credentials,
            7: {"rk": resident_required or resident == "preferred"},
        }
        command = 1
    else:
        credentials = descriptors(options.get("allowCredentials", []))
        inner = {1: rp_id, 2: digest, 5: {"up": True}}
        if credentials:
            inner[3] = credentials
        command = 2
    outer = rpc(
        5, flags={"required": 0x00400000, "preferred": 0x00800000,
                  "discouraged": 0x01000000}[uv],
        timeout=timeout, request=bytes([command]) + cbor2.dumps(inner),
        webAuthNPara=params, clientDataJSON=client_data,
    )
    return Prepared(kind, outer, client_data, rp_id, uv == "required",
                    credentials, resident_required, extensions.get("credProps", False))


def complete(prepared, outer):
    inner = unwrap(outer)
    result = {
        "type": "public-key", "authenticatorAttachment": "cross-platform",
        "clientExtensionResults": {},
    }
    if prepared.kind == "create":
        data = inner.get(2)
        credential_id, key = auth_data(
            data, prepared.rp_id, prepared.require_uv, registration=True
        )
        if any(item["id"] == credential_id for item in prepared.credentials):
            raise BridgeError("verification: created credential was excluded")
        info = outer.get("deviceInfo", {})
        if not isinstance(info, dict):
            raise BridgeError("protocol: deviceInfo is not a map")
        resident = info.get("residentKey")
        if prepared.resident_required and resident is not True:
            raise BridgeError("verification: required resident credential not confirmed")
        if prepared.cred_props:
            result["clientExtensionResults"]["credProps"] = (
                {"rk": resident} if type(resident) is bool else {}
            )
        # Implement attestation=none, including anonymizing the AAGUID.
        data = data[:37] + bytes(16) + data[53:]
        attestation = cbor2.dumps(
            {"fmt": "none", "authData": data, "attStmt": {}}, canonical=True
        )
        response = {
            "clientDataJSON": b64(prepared.client_data),
            "authenticatorData": b64(data), "attestationObject": b64(attestation),
            "publicKeyAlgorithm": -7,
            "publicKey": b64(key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )),
            "transports": [],
        }
    else:
        credential = inner.get(1)
        if credential is None and len(prepared.credentials) == 1:
            credential = prepared.credentials[0]
        if not isinstance(credential, dict) or credential.get("type") != "public-key":
            raise BridgeError("verification: missing assertion credential")
        credential_id = credential.get("id")
        if not isinstance(credential_id, bytes) or not credential_id:
            raise BridgeError("verification: invalid credential ID")
        if prepared.credentials and not any(
            item["id"] == credential_id for item in prepared.credentials
        ):
            raise BridgeError("verification: credential is outside allowCredentials")
        data, signature = inner.get(2), inner.get(3)
        auth_data(data, prepared.rp_id, prepared.require_uv)
        if not isinstance(signature, bytes) or not signature:
            raise BridgeError("verification: missing signature")
        user = inner.get(4, {})
        if not isinstance(user, dict) or (
            "id" in user and (
                not isinstance(user["id"], bytes) or not 1 <= len(user["id"]) <= 64
            )
        ):
            raise BridgeError("verification: invalid user handle")
        if not prepared.credentials and not user.get("id"):
            raise BridgeError("verification: discoverable assertion lacks user handle")
        response = {
            "clientDataJSON": b64(prepared.client_data),
            "authenticatorData": b64(data), "signature": b64(signature),
        }
        if user.get("id"):
            response["userHandle"] = b64(user["id"])
    result.update(id=b64(credential_id), rawId=b64(credential_id), response=response)
    return result
