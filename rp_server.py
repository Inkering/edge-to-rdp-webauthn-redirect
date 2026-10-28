"""Disposable loopback relying party for manual Edge create/get/cancel checks."""

import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
import time

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from rdpewa import BridgeError, decode_one
from webauthn import auth_data, b64, unb64


PAGE = b"""<!doctype html><meta charset="utf-8"><title>Disposable localhost RP</title>
<h1>xrdp WebAuthn controlled RP</h1>
<p>Use Windows security-key UI. Never enter a PIN into this page.</p>
<label><input id="resident" type="checkbox">Create a discoverable passkey
(uses storage on your key; remove the localhost passkey afterwards)</label>
<p><label>Request timeout (ms; browser may clamp): <input id="timeout"
type="number" min="1" max="60000" value="60000"></label></p>
<p><button id="create">Register disposable credential</button>
<button id="get">Authenticate and verify signature</button>
<button id="cancel">Cancel current request</button></p><pre id="result">Ready.</pre>
<script>
let active;
const output = document.querySelector("#result");
const binary = text => Uint8Array.from(
  atob(text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4-text.length%4)%4)),
  c => c.charCodeAt(0));
async function post(path, value) {
  const response = await fetch(path, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify(value)
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error);
  return data;
}
async function run(kind) {
  if (active) { output.textContent = "Cancel or finish the current request first."; return; }
  active = new AbortController();
  try {
    const publicKey = await post("/options", {
      kind, resident: document.querySelector("#resident").checked
    });
    const timeout = document.querySelector("#timeout").valueAsNumber;
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 60000)
      throw new RangeError("Timeout must be an integer from 1 to 60000 ms");
    publicKey.timeout = timeout;
    publicKey.challenge = binary(publicKey.challenge);
    if (publicKey.user) publicKey.user.id = binary(publicKey.user.id);
    for (const field of ["allowCredentials", "excludeCredentials"])
      for (const item of publicKey[field] || []) item.id = binary(item.id);
    output.textContent = "Waiting for Windows security-key UI...";
    const credential = await navigator.credentials[kind]({
      publicKey, signal: active.signal
    });
    const result = await post("/complete", {kind, credential: credential.toJSON()});
    output.textContent = result.result;
  } catch (error) {
    output.textContent = `${error.name}: ${error.message}`;
  } finally { active = null; }
}
document.querySelector("#create").onclick = () => run("create");
document.querySelector("#get").onclick = () => run("get");
document.querySelector("#cancel").onclick = () => active?.abort();
</script>"""


class RelyingParty:
    def __init__(self, origin):
        self.origin = origin
        self.credential_id = self.key = self.user_id = self.pending = None
        self.resident = False
        self.counter = 0

    def options(self, kind, resident=False):
        if kind not in ("create", "get") or type(resident) is not bool:
            raise BridgeError("Invalid options request")
        if kind == "get" and self.key is None:
            raise BridgeError("Register a disposable credential first")
        challenge = secrets.token_bytes(32)
        user_id = secrets.token_bytes(32) if kind == "create" else self.user_id
        self.pending = (kind, b64(challenge), time.monotonic() + 60, resident, user_id)
        result = {"challenge": b64(challenge), "timeout": 60000}
        if kind == "create":
            result.update(
                rp={"id": "localhost", "name": "Disposable RDPEWA RP"},
                user={"id": b64(user_id), "name": "disposable",
                      "displayName": "Disposable RDPEWA test"},
                pubKeyCredParams=[{"type": "public-key", "alg": -7}],
                authenticatorSelection={
                    "authenticatorAttachment": "cross-platform",
                    "residentKey": "required" if resident else "discouraged",
                    "userVerification": "required",
                },
                attestation="none", extensions={"credProps": True},
            )
        else:
            result.update(rpId="localhost", userVerification="required")
            if not self.resident:
                result["allowCredentials"] = [
                    {"type": "public-key", "id": b64(self.credential_id)}
                ]
        return result

    def complete(self, kind, credential):
        expected, self.pending = self.pending, None
        if expected is None or kind != expected[0] or time.monotonic() > expected[2]:
            raise BridgeError("Missing, expired or wrong-kind challenge")
        if not isinstance(credential, dict) or credential.get("type") != "public-key":
            raise BridgeError("Invalid credential type")
        response = credential["response"]
        if not isinstance(response, dict):
            raise BridgeError("Invalid credential response")
        client_data = unb64(response["clientDataJSON"])
        client = json.loads(client_data)
        if (not isinstance(client, dict)
                or client.get("type") != f"webauthn.{kind}"
                or client.get("challenge") != expected[1]
                or client.get("origin") != self.origin
                or client.get("crossOrigin", False) is not False
                or "topOrigin" in client):
            raise BridgeError("Client data type/challenge/origin/context mismatch")
        credential_id = unb64(credential["rawId"])
        if credential.get("id") != b64(credential_id):
            raise BridgeError("Credential ID/rawId mismatch")
        if kind == "create":
            attestation = decode_one(unb64(response["attestationObject"]))
            if (not isinstance(attestation, dict)
                    or attestation.get("fmt") != "none" or attestation.get("attStmt") != {}):
                raise BridgeError("Only anonymous attestation is accepted")
            data = attestation["authData"]
            registered_id, key = auth_data(data, "localhost", True, registration=True)
            if credential_id != registered_id:
                raise BridgeError("Attested credential ID mismatch")
            if expected[3] and credential.get("clientExtensionResults", {}).get(
                "credProps", {}
            ).get("rk") is not True:
                raise BridgeError("Discoverable credential was not confirmed")
            self.credential_id, self.key = credential_id, key
            self.user_id = expected[4]
            self.resident = expected[3]
            self.counter = int.from_bytes(data[33:37], "big")
            return "Registration verified: localhost RP hash, ES256 key, UP=1 UV=1."
        if credential_id != self.credential_id:
            raise BridgeError("Assertion credential ID mismatch")
        data = unb64(response["authenticatorData"])
        auth_data(data, "localhost", True)
        user_handle = response.get("userHandle")
        if ((self.resident and not user_handle)
                or (user_handle and unb64(user_handle) != self.user_id)):
            raise BridgeError("Assertion user handle mismatch")
        try:
            self.key.verify(
                unb64(response["signature"]),
                data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature:
            raise BridgeError("INVALID assertion signature") from None
        counter = int.from_bytes(data[33:37], "big")
        if self.counter and counter and counter <= self.counter:
            raise BridgeError("Authenticator counter did not increase")
        self.counter = counter
        return "VERIFIED GetAssertion: signature, exact clientDataJSON, RP hash, UP=1 UV=1."


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass  # No HTTP payloads, credential IDs or challenges in logs.

    def respond(self, status, value, content_type="application/json"):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def valid_host(self):
        return self.headers.get("Host") == self.server.rp.origin.removeprefix("http://")

    def do_GET(self):
        if not self.valid_host() or self.path != "/":
            self.respond(404, {"error": "Not found"})
            return
        self.respond(200, PAGE, "text/html; charset=utf-8")

    def do_POST(self):
        if not self.valid_host() or self.headers.get("Origin") != self.server.rp.origin:
            self.respond(403, {"error": "Wrong request origin/host"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 65536:
                raise BridgeError("Invalid request size")
            message = json.loads(self.rfile.read(length))
            if self.path == "/options":
                result = self.server.rp.options(message["kind"], message.get("resident", False))
            elif self.path == "/complete":
                result = {"result": self.server.rp.complete(message["kind"], message["credential"])}
            else:
                self.respond(404, {"error": "Not found"})
                return
            self.respond(200, result)
        except (BridgeError, KeyError, TypeError, ValueError, cbor2.CBORDecodeError):
            self.respond(400, {"error": "RP verification/request failed; no payload logged"})


def main():
    server = HTTPServer(("127.0.0.1", 8765), Handler)
    server.timeout = 1
    server.rp = RelyingParty("http://localhost:8765")
    print("Disposable RP: http://localhost:8765 (Edge inside xrdp). "
          "All credentials are memory-only. Ctrl-C stops it.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
