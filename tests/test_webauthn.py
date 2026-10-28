import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hardware_test import verify_assertion
from install_native import main as install_native, write_private
from native_host import Host, check_config, encode_message
from rdpewa import (
    BridgeError, Channel, MAX_REQUEST, decode_one, rpc, start, unwrap, worker_diagnostic,
)
from rp_server import RelyingParty
from webauthn import RequestError, auth_data, b64, complete, prepare, unb64


def options(kind="get"):
    value = {
        "challenge": b64(bytes(range(32))),
        "extensions": {"remoteDesktopClientOverride": {
            "origin": "https://login.example.com",
            "sameOriginWithAncestors": True,
        }},
        "userVerification": "required",
        "rpId": "example.com", "allowCredentials": [
            {"type": "public-key", "id": b64(b"credential")}
        ],
    }
    if kind == "create":
        del value["userVerification"], value["rpId"], value["allowCredentials"]
        value.update(
            rp={"id": "example.com", "name": "Example"},
            user={"id": b64(b"user"), "name": "test", "displayName": "Test"},
            pubKeyCredParams=[{"type": "public-key", "alg": -7}],
            authenticatorSelection={"userVerification": "required"},
        )
    return value


def authenticator_data(rp="example.com", flags=5):
    return hashlib.sha256(rp.encode()).digest() + bytes([flags]) + bytes(4)


def envelope(value, **fields):
    return {"status": 0, "response": b"\0" + cbor2.dumps(value), **fields}


def attested_data(rp="example.com", key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    cose = {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big")}
    data = authenticator_data(rp, 0x45) + bytes(16) + b"\0\x0a" + b"credential" + cbor2.dumps(cose)
    return data, key


class WebAuthnTests(unittest.TestCase):
    def test_opaque_challenge_lengths_and_transport_limit(self):
        for kind in ("create", "get"):
            for size in (1, 15, 16, 128, 129, 256, 512, 1024, 4096, 8192):
                with self.subTest(kind=kind, size=size):
                    value = options(kind)
                    value["challenge"] = b64(bytes(index % 256 for index in range(size)))
                    prepared = prepare(kind, value)
                    self.assertEqual(
                        json.loads(prepared.client_data)["challenge"], value["challenge"]
                    )
                    inner = decode_one(prepared.rpc["request"][1:])
                    self.assertEqual(
                        inner[1 if kind == "create" else 2],
                        hashlib.sha256(prepared.client_data).digest(),
                    )
                    self.assertLessEqual(len(cbor2.dumps(prepared.rpc)), MAX_REQUEST)
            value = options(kind)
            value["challenge"] = b64(bytes(MAX_REQUEST))
            prepared = prepare(kind, value)
            with patch("rdpewa.subprocess.Popen") as launch:
                with self.assertRaisesRegex(BridgeError, f"{MAX_REQUEST}-byte"):
                    start(prepared.rpc)
            launch.assert_not_called()

    def test_large_request_is_one_wts_write_and_partial_write_fails(self):
        value = options()
        value["challenge"] = b64(bytes(4096))
        request = prepare("get", value).rpc
        encoded = cbor2.dumps(request)
        self.assertGreater(len(encoded), 1590)
        for partial in (False, True):
            with self.subTest(partial=partial):
                writes = []

                class Library:
                    def WTSVirtualChannelWrite(self, _handle, buffer, size, count):
                        writes.append(ctypes.string_at(buffer, size))
                        ctypes.cast(count, ctypes.POINTER(ctypes.c_uint)).contents.value = (
                            size - 1 if partial else size
                        )
                        return 1

                channel = Channel.__new__(Channel)
                channel.lib, channel.handle = Library(), 1
                if partial:
                    with self.assertRaisesRegex(BridgeError, "partial DVC message"):
                        channel.send(request)
                else:
                    channel.send(request)
                self.assertEqual(writes, [encoded])
                oversized = {**request, "clientDataJSON": bytes(MAX_REQUEST)}
                with self.assertRaisesRegex(BridgeError, f"{MAX_REQUEST}-byte"):
                    channel.send(oversized)
                self.assertEqual(writes, [encoded])

    def test_exact_client_data_and_hash(self):
        prepared = prepare("get", options())
        inner = decode_one(prepared.rpc["request"][1:])
        self.assertEqual(inner[2], hashlib.sha256(prepared.client_data).digest())
        self.assertEqual(prepared.rpc["clientDataJSON"], prepared.client_data)
        self.assertEqual(prepared.rpc["command"], 5)
        self.assertEqual(prepared.rpc["request"][0], 2)
        self.assertEqual(prepared.rpc["flags"], 0x00400000)
        self.assertEqual(inner[5], {"up": True})
        data = json.loads(prepared.client_data)
        self.assertEqual(data["origin"], "https://login.example.com")
        self.assertFalse(data["crossOrigin"])
        response = complete(prepared, envelope({
            1: {"type": "public-key", "id": b"credential"},
            2: authenticator_data(), 3: b"signature",
        }))
        self.assertEqual(unb64(response["response"]["clientDataJSON"]), prepared.client_data)
        self.assertEqual(response["id"], response["rawId"])
        self.assertNotIn("userHandle", response["response"])
        with_user = complete(prepared, envelope({
            1: {"type": "public-key", "id": b"credential"},
            2: authenticator_data(), 3: b"signature", 4: {"id": b"user"},
        }))
        self.assertEqual(unb64(with_user["response"]["userHandle"]), b"user")

    def test_context_fail_closed(self):
        mutations = (
            lambda x: x.pop("extensions"),
            lambda x: x["extensions"]["remoteDesktopClientOverride"].update(
                sameOriginWithAncestors=False),
            lambda x: x["extensions"]["remoteDesktopClientOverride"].update(
                origin="http://example.com"),
            lambda x: x.update(rpId="unrelated.com"),
            lambda x: x["extensions"].update(prf={}),
            lambda x: x.update(challenge="x"),
            lambda x: x.update(unknown=True),
        )
        for mutate in mutations:
            value = options()
            mutate(value)
            with self.subTest(value=value), self.assertRaises((RequestError, ValueError)):
                prepare("get", value)

    def test_edge_default_descriptor_transports(self):
        value = options()
        value["allowCredentials"][0]["transports"] = [
            "usb", "nfc", "ble", "hybrid", "internal", "smart-card",
        ]
        prepared = prepare("get", value)
        self.assertEqual(decode_one(prepared.rpc["request"][1:])[3][0]["transports"], 0x77)
        value["allowCredentials"][0]["transports"].append("unknown")
        with self.assertRaisesRegex(RequestError, "Unsupported credential transport"):
            prepare("get", value)

    def test_resident_and_verification_requirements(self):
        value = options("create")
        value["authenticatorSelection"]["residentKey"] = "required"
        prepared = prepare("create", value)
        self.assertTrue(prepared.rpc["webAuthNPara"]["requireResident"])
        self.assertTrue(decode_one(prepared.rpc["request"][1:])[7]["rk"])
        data, _ = attested_data()
        with self.assertRaisesRegex(BridgeError, "resident"):
            complete(prepared, envelope({2: data}))
        response = complete(prepared, envelope({2: data}, deviceInfo={"residentKey": True}))
        self.assertEqual(response["response"]["publicKeyAlgorithm"], -7)
        self.assertTrue(response["response"]["publicKey"])
        attestation = decode_one(unb64(response["response"]["attestationObject"]))
        self.assertEqual(
            unb64(response["response"]["attestationObject"]),
            cbor2.dumps(attestation, canonical=True),
        )
        self.assertEqual(attestation["fmt"], "none")
        self.assertEqual(attestation["attStmt"], {})
        self.assertEqual(attestation["authData"][37:53], bytes(16))
        for uv, flag in (("required", 0x00400000), ("preferred", 0x00800000),
                         ("discouraged", 0x01000000)):
            request = options()
            request["userVerification"] = uv
            self.assertEqual(prepare("get", request).rpc["flags"], flag)

    def test_signed_flags_rp_and_credential(self):
        prepared = prepare("get", options())
        value = {1: {"type": "public-key", "id": b"credential"},
                 2: authenticator_data(), 3: b"signature"}
        for field, invalid in (
            (2, authenticator_data(flags=1)),
            (2, authenticator_data(flags=4)),
            (2, authenticator_data(rp="wrong.example")),
            (1, {"type": "public-key", "id": b"wrong"}),
            (3, b""),
        ):
            changed = {**value, field: invalid}
            with self.subTest(field=field), self.assertRaises(BridgeError):
                complete(prepared, envelope(changed))
        with self.assertRaises(BridgeError):
            auth_data(authenticator_data() + b"x", "example.com", True)

    def test_real_crypto_verifier_and_tampering(self):
        key = ec.generate_private_key(ec.SECP256R1())
        data = b'{"test":"exact bytes"}'
        auth = authenticator_data("localhost")
        signature = key.sign(auth + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
        assertion = {1: {"type": "public-key", "id": b"credential"}, 2: auth, 3: signature}
        self.assertEqual(verify_assertion(assertion, b"credential", key.public_key(), data)[0], 5)
        with self.assertRaisesRegex(BridgeError, "INVALID"):
            verify_assertion(assertion, b"credential", key.public_key(), data + b" ")

    def test_ctap_errors_and_key_casing(self):
        self.assertEqual(unwrap({"Status": 0, "Response": b"\0\xa0"}), {})
        for outer in (
            {"status": 0, "response": b"\x2e"},
            {"status": 1, "response": b"\0\xa0"},
            {"status": 0, "Status": 0, "response": b"\0\xa0"},
        ):
            with self.assertRaises(BridgeError):
                unwrap(outer)

    def test_fragmented_transport_response(self):
        data = struct.pack("<I", 0) + cbor2.dumps(envelope({2: b"x" * 10000}))
        pieces = [data[i:i + 17] for i in range(0, len(data), 17)]

        class Library:
            def WTSVirtualChannelRead(self, _handle, _timeout, buffer, _size, count):
                chunk = pieces.pop(0)
                ctypes.memmove(buffer, chunk, len(chunk))
                ctypes.cast(count, ctypes.POINTER(ctypes.c_uint)).contents.value = len(chunk)
                return 1

        channel = Channel.__new__(Channel)
        channel.lib, channel.handle = Library(), 1
        self.assertEqual(channel.receive(5), envelope({2: b"x" * 10000}))

    def test_cancellation_command_and_identifier(self):
        channel = Channel.__new__(Channel)
        sent = []
        channel.send = sent.append
        identifier = bytes(range(16))
        with self.assertRaisesRegex(BridgeError, "canceled"):
            channel.receive(5, lambda: True, identifier)
        self.assertEqual(sent[0]["command"], 7)
        self.assertEqual(sent[0]["request"], identifier)

    def test_worker_diagnostic_preserves_stage_without_arbitrary_stderr(self):
        self.assertEqual(
            worker_diagnostic(b"stage=open\nstage=version\nERROR RPC 8: HRESULT=0x80004005\n"),
            "stage=version; ERROR RPC 8: HRESULT=0x80004005",
        )
        self.assertEqual(worker_diagnostic(b"unexpected traceback text\n"), "stage=unknown")


class NativeTests(unittest.TestCase):
    def test_browser_fixture_is_explicitly_opt_in_and_synthetic(self):
        fixture = Path(__file__).with_name("browser_native_fixture.py")
        environment = dict(os.environ)
        environment.pop("XRDP_WEBAUTHN_SYNTHETIC_TEST", None)
        result = subprocess.run(
            [sys.executable, str(fixture), "--worker"], input=cbor2.dumps(rpc(8)),
            capture_output=True, env=environment, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(result.stdout)
        environment["XRDP_WEBAUTHN_SYNTHETIC_TEST"] = "1"
        for command, expected in ((8, 9), (6, 0)):
            result = subprocess.run(
                [sys.executable, str(fixture), "--worker"], input=cbor2.dumps(rpc(command)),
                capture_output=True, env=environment, timeout=5, check=True,
            )
            self.assertEqual(decode_one(result.stdout), expected)
        result = subprocess.run(
            [sys.executable, str(fixture), "--worker"],
            input=cbor2.dumps(prepare("create", options("create")).rpc),
            capture_output=True, env=environment, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"restricted to localhost", result.stderr)
        self.assertFalse(result.stdout)

    def test_install_into_explicit_edge_profile_only(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            profile = home / "isolated-edge"
            extension_id = "a" * 32
            with patch("install_native.Path.home", return_value=home), \
                    patch("install_native.Path.exists", return_value=True), \
                    patch("install_native.session_socket", return_value=[1, 2]), \
                    patch("install_native.os.umask"), \
                    patch.dict(os.environ, DISPLAY=":10.0", XRDP_SESSION="1"), \
                    patch("install_native.sys.stdout", new_callable=io.StringIO), \
                    patch("install_native.sys.argv", [
                        "install_native.py", extension_id,
                        "--edge-user-data-dir", str(profile),
                    ]):
                install_native()
            manifest_path = profile / "NativeMessagingHosts/org.local.xrdp_webauthn.json"
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["allowed_origins"],
                             [f"chrome-extension://{extension_id}/"])
            self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(manifest_path.parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse((home / ".config/microsoft-edge").exists())
            launcher = home / ".local/lib/linux-rdpewa/native-host"
            self.assertEqual(launcher.stat().st_mode & 0o777, 0o700)
            config = launcher.with_name("session.json")
            with patch("native_host.session_socket", return_value=[1, 2]), \
                    patch.dict(os.environ, DISPLAY=":10.0", XRDP_SESSION="1"):
                check_config(config, manifest["allowed_origins"][0])

    def test_private_install_rejects_symlink_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("untouched")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                write_private(link, "replacement")
            self.assertEqual(target.read_text(), "untouched")

    def test_install_rejects_symlink_profile_directories_before_config_changes(self):
        for symlink_profile in (False, True):
            with self.subTest(profile=symlink_profile), \
                    tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                profile, target = home / "edge", home / "target"
                target.mkdir()
                if symlink_profile:
                    profile.symlink_to(target, target_is_directory=True)
                else:
                    profile.mkdir()
                    (profile / "NativeMessagingHosts").symlink_to(
                        target, target_is_directory=True)
                with patch("install_native.Path.home", return_value=home), \
                        patch("install_native.Path.exists", return_value=True), \
                        patch("install_native.os.umask"), \
                        patch.dict(os.environ, DISPLAY=":10.0", XRDP_SESSION="1"), \
                        patch("install_native.sys.argv", [
                            "install_native.py", "a" * 32,
                            "--edge-user-data-dir", str(profile),
                        ]), self.assertRaisesRegex(SystemExit, "user-owned real directory"):
                    install_native()
                self.assertFalse((home / ".local/lib/linux-rdpewa/session.json").exists())

    def test_health_queues_requests_without_extending_deadlines(self):
        host = Host()
        self.addCleanup(host.selector.close)
        host.ready = True
        host.jobs["health"] = {"kind": "health"}
        host.launch = unittest.mock.Mock()
        with patch("native_host.time.monotonic", return_value=10):
            host.message({"kind": "get", "requestId": 1, "options": options()})
        host.launch.assert_not_called()
        self.assertEqual(host.queued[1][3], 70)
        with self.assertRaisesRegex(BridgeError, "duplicate"):
            host.message({"kind": "get", "requestId": 1, "options": options()})
        del host.jobs["health"]
        with patch("native_host.time.monotonic", return_value=15):
            host.dispatch()
        args = host.launch.call_args.args
        self.assertEqual(args[:2], (1, "get"))
        self.assertEqual(args[2]["timeout"], 55000)
        self.assertEqual(args[4], 70)
        self.assertFalse(host.queued)

    def test_cancel_and_expiry_while_queued_for_health(self):
        host = Host()
        self.addCleanup(host.selector.close)
        host.ready = True
        host.jobs["health"] = {"kind": "health"}
        host.launch = unittest.mock.Mock()
        host.send = unittest.mock.Mock()
        with patch("native_host.time.monotonic", return_value=10):
            for request_id in (1, 2):
                host.message({"kind": "get", "requestId": request_id, "options": options()})
        host.message({"kind": "cancel", "requestId": 1})
        self.assertNotIn(1, host.queued)
        del host.jobs["health"]
        with patch("native_host.time.monotonic", return_value=71):
            host.dispatch()
        host.launch.assert_not_called()
        self.assertEqual(host.send.call_count, 1)
        response = host.send.call_args.args[0]
        self.assertEqual(response["requestId"], 2)
        self.assertIn("timed out", response["error"]["message"])

    def test_fragmented_input_and_invalid_lengths(self):
        host = Host()
        self.addCleanup(host.selector.close)
        host.message = unittest.mock.Mock()
        frame = encode_message({"kind": "get", "requestId": 3})
        pieces = [frame[:1], frame[1:4], frame[4:8], frame[8:]]
        with patch("native_host.os.read", side_effect=pieces):
            for _ in pieces:
                host.read_input()
        host.message.assert_called_once_with({"kind": "get", "requestId": 3})
        with patch("native_host.os.read", return_value=struct.pack("=I", 2**20 + 1)), \
                self.assertRaisesRegex(BridgeError, "frame length"):
            host.read_input()
        host.input = bytearray(b"\x01")
        with patch("native_host.os.read", return_value=b""), \
                self.assertRaisesRegex(BridgeError, "truncated"):
            host.read_input()

    def test_eof_kills_and_reaps_hung_worker(self):
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import signal,time;signal.signal(signal.SIGUSR1,signal.SIG_IGN);"
             "print('ready',flush=True);time.sleep(30)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        self.assertEqual(child.stdout.readline(), b"ready\n")
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        with os.fdopen(read_fd, "rb") as stdin, \
                patch("native_host.sys.stdin", stdin), \
                patch("native_host.start", return_value=(child, b"\xa0")):
            Host().run()
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_background_health_never_starts_during_an_operation(self):
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import signal,time;signal.signal(signal.SIGUSR1,signal.SIG_IGN);"
             "print('ready',flush=True);time.sleep(30)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        self.assertEqual(child.stdout.readline(), b"ready\n")
        host = Host()
        with patch("native_host.start", return_value=(child, b"\xa0")):
            host.launch(1, "get", {"timeout": 60000})
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        with os.fdopen(read_fd, "rb") as stdin, \
                patch("native_host.sys.stdin", stdin), \
                patch.object(host, "launch") as launch:
            host.run()
        launch.assert_not_called()
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_running_deadline_kills_reaps_and_reports_failure(self):
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import signal,time;signal.signal(signal.SIGUSR1,signal.SIG_IGN);"
             "print('ready',flush=True);time.sleep(30)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        self.assertEqual(child.stdout.readline(), b"ready\n")
        host = Host()
        messages = []

        def send(message):
            messages.append(message)
            host.stopping = True

        host.send = send
        with patch("native_host.start", return_value=(child, b"\xa0")):
            host.launch(1, "get", {"timeout": 1})
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        with os.fdopen(read_fd, "rb") as stdin, \
                patch("native_host.sys.stdin", stdin), \
                patch("native_host.sys.stderr", new_callable=io.StringIO):
            host.run()
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["requestId"], 1)
        self.assertEqual(messages[0]["error"]["name"], "NotAllowedError")
        self.assertFalse(host.jobs)
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_native_frame_byte_length(self):
        frame = encode_message({"value": "hello"})
        self.assertEqual(struct.unpack_from("=I", frame)[0], len(frame) - 4)
        self.assertEqual(json.loads(frame[4:]), {"value": "hello"})

    def test_caller_session_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({
                "origin": "chrome-extension://" + "a" * 32 + "/",
                "uid": os.getuid(), "display": ":10.0", "socketIdentity": [1, 2],
            }))
            config.chmod(0o600)
            with patch.dict(os.environ, DISPLAY=":10.0", XRDP_SESSION="1"), \
                    patch("native_host.session_socket", return_value=[1, 2]):
                check_config(config, "chrome-extension://" + "a" * 32 + "/")
                with self.assertRaises(BridgeError):
                    check_config(config, "chrome-extension://" + "b" * 32 + "/")
                with patch.dict(os.environ, DISPLAY=":11.0"), self.assertRaises(BridgeError):
                    check_config(config, "chrome-extension://" + "a" * 32 + "/")
                with patch("native_host.session_socket", return_value=[1, 3]), \
                        self.assertRaisesRegex(BridgeError, "earlier desktop"):
                    check_config(config, "chrome-extension://" + "a" * 32 + "/")
                config.chmod(0o644)
                with self.assertRaises(BridgeError):
                    check_config(config, "chrome-extension://" + "a" * 32 + "/")

    def test_cancel_suppresses_completion(self):
        host = Host()
        self.addCleanup(host.selector.close)
        process = unittest.mock.Mock()
        process.poll.return_value = None
        job = {"id": 1, "kind": "get", "process": process,
               "canceled": False, "stop_at": None}
        host.jobs[1] = job
        host.message({"kind": "cancel", "requestId": 1})
        self.assertTrue(job["canceled"])
        process.send_signal.assert_called_once_with(signal.SIGUSR1)

    def test_duplicate_request_rejected(self):
        host = Host()
        self.addCleanup(host.selector.close)
        host.jobs[1] = {}
        with self.assertRaisesRegex(BridgeError, "duplicate"):
            host.message({"kind": "get", "requestId": 1})


class RelyingPartyTests(unittest.TestCase):
    def setUp(self):
        self.rp = RelyingParty("http://localhost:8765")

    def prepared(self, kind, resident=False):
        value = self.rp.options(kind, resident)
        value.setdefault("extensions", {})["remoteDesktopClientOverride"] = {
            "origin": self.rp.origin, "sameOriginWithAncestors": True,
        }
        return prepare(kind, value)

    def register(self, resident=False):
        prepared = self.prepared("create", resident)
        data, key = attested_data("localhost")
        credential = complete(prepared, envelope({2: data}, deviceInfo={"residentKey": resident}))
        self.assertIn("Registration verified", self.rp.complete("create", credential))
        return key

    def assertion(self, key):
        prepared = self.prepared("get")
        data = authenticator_data("localhost")
        signature = key.sign(data + hashlib.sha256(prepared.client_data).digest(),
                             ec.ECDSA(hashes.SHA256()))
        outer = envelope({
            1: {"type": "public-key", "id": b"credential"},
            2: data, 3: signature, 4: {"id": self.rp.user_id},
        })
        return complete(prepared, outer)

    def test_registered_and_discoverable_signed_round_trip(self):
        for resident in (False, True):
            with self.subTest(resident=resident):
                key = self.register(resident)
                credential = self.assertion(key)
                self.assertIn("VERIFIED GetAssertion", self.rp.complete("get", credential))
                with self.assertRaisesRegex(BridgeError, "challenge"):
                    self.rp.complete("get", credential)

    def test_signature_challenge_origin_and_flags_tampering(self):
        key = self.register()
        for field, value in (
            ("signature", b64(b"invalid")),
            ("authenticatorData", b64(authenticator_data("localhost", 1))),
            ("clientDataJSON", b64(json.dumps({
                "type": "webauthn.get", "challenge": "tampered",
                "origin": self.rp.origin, "crossOrigin": False,
            }).encode())),
        ):
            credential = self.assertion(key)
            credential["response"][field] = value
            with self.subTest(field=field), self.assertRaises(BridgeError):
                self.rp.complete("get", credential)
