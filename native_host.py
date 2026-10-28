"""Per-browser native host. Private stdio only; one child/channel per request."""

import json
import os
from pathlib import Path
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time

import cbor2

from rdpewa import (
    BridgeError, MAX_RESPONSE, decode_one, rpc, session_socket, start, worker_diagnostic,
)
from webauthn import RequestError, complete, prepare


MAX_MESSAGE = 1024 * 1024
HEALTH_TIMEOUT = 20


def encode_message(value):
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > MAX_MESSAGE:
        raise BridgeError("native messaging: output exceeds 1 MiB")
    return struct.pack("=I", len(data)) + data


def check_config(path, origin):
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077):
        raise BridgeError("native host config must be a user-owned private regular file")
    config = json.loads(path.read_text())
    if origin != config["origin"]:
        raise BridgeError("native messaging caller is not the intended extension")
    if config["uid"] != os.getuid() or config["display"] != os.environ.get("DISPLAY"):
        raise BridgeError("native host is bound to a different user/desktop session")
    if os.environ.get("XRDP_SESSION") != "1":
        raise BridgeError("native host requires an xrdp desktop session")
    if config["socketIdentity"] != session_socket():
        raise BridgeError("native host is bound to an earlier desktop session; reinstall")


class Host:
    def __init__(self):
        self.selector = selectors.DefaultSelector()
        self.jobs = {}
        self.queued = {}
        self.input = bytearray()
        self.last_health = 0
        self.ready = False
        self.stopping = False

    def send(self, value):
        sys.stdout.buffer.write(encode_message(value))
        sys.stdout.buffer.flush()

    def launch(self, request_id, kind, request, prepared=None, deadline=None):
        process, encoded = start(request)
        job = {
            "id": request_id, "kind": kind, "process": process,
            "prepared": prepared, "output": bytearray(), "error": bytearray(),
            "deadline": deadline if deadline is not None else time.monotonic() + (
                request.get("timeout", 0) / 1000 or HEALTH_TIMEOUT
            ),
            "canceled": False, "stop_at": None,
        }
        self.jobs[request_id] = job
        try:
            process.stdin.write(encoded)
            process.stdin.close()
            process.stdin = None
        except OSError:
            del self.jobs[request_id]
            process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    stream.close()
            raise BridgeError("worker input pipe failed") from None
        for stream, name in ((process.stdout, "output"), (process.stderr, "error")):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, (job, name))

    def cancel(self, job):
        if job["stop_at"] is None:
            if job["process"].poll() is None:
                job["process"].send_signal(signal.SIGUSR1)
            job["stop_at"] = time.monotonic() + 1

    def dispatch(self):
        if self.stopping or "health" in self.jobs:
            return
        for request_id, (kind, request, prepared, deadline) in list(self.queued.items()):
            del self.queued[request_id]
            try:
                remaining = int((deadline - time.monotonic()) * 1000)
                if remaining <= 0:
                    raise BridgeError("Request timed out while checking session health")
                self.launch(request_id, kind, {**request, "timeout": remaining},
                            prepared, deadline)
            except BridgeError as error:
                self.send({
                    "requestId": request_id,
                    "error": {"name": "NotAllowedError", "message": str(error)},
                })

    def message(self, message):
        if not isinstance(message, dict):
            raise BridgeError("native messaging: input must be an object")
        kind = message.get("kind")
        request_id = message.get("requestId")
        if type(request_id) is not int or not -(2**31) <= request_id < 2**31:
            raise BridgeError("native messaging: invalid request ID")
        if kind == "cancel":
            self.queued.pop(request_id, None)
            job = self.jobs.get(request_id)
            if job:
                job["canceled"] = True
                self.cancel(job)
            return
        if request_id in self.jobs or request_id in self.queued:
            raise BridgeError("native messaging: duplicate request ID")
        if kind not in ("create", "get", "isUvpaa"):
            raise BridgeError("native messaging: unsupported command")
        if (not self.ready or len(self.queued)
                + sum(job["kind"] != "health" for job in self.jobs.values()) >= 4):
            self.send({
                "requestId": request_id,
                "error": {"name": "NotAllowedError", "message": "Bridge unavailable or busy"},
            })
            return
        try:
            if kind == "isUvpaa":
                prepared, request = None, rpc(6)
            else:
                prepared = prepare(kind, message.get("options"))
                request = prepared.rpc
            deadline = time.monotonic() + (request["timeout"] / 1000 or HEALTH_TIMEOUT)
            self.queued[request_id] = (kind, request, prepared, deadline)
            self.dispatch()
        except (RequestError, BridgeError, ValueError, TypeError) as error:
            self.send({
                "requestId": request_id,
                "error": {
                    "name": error.name if isinstance(error, RequestError) else "NotAllowedError",
                    "message": str(error) if isinstance(error, BridgeError) else "Invalid request",
                },
            })

    def read_input(self):
        data = os.read(sys.stdin.fileno(), 65536)
        if not data:
            if self.input:
                raise BridgeError("native messaging: truncated input on EOF")
            self.stopping = True
            return
        self.input.extend(data)
        while len(self.input) >= 4:
            length = struct.unpack_from("=I", self.input)[0]
            if not 1 <= length <= MAX_MESSAGE:
                raise BridgeError("native messaging: invalid frame length")
            if len(self.input) < length + 4:
                return
            data = bytes(self.input[4:length + 4])
            del self.input[:length + 4]
            try:
                message = json.loads(data)
            except (ValueError, UnicodeError):
                raise BridgeError("native messaging: invalid JSON") from None
            self.message(message)

    def finish(self, job):
        process = job["process"]
        try:
            if job["stop_at"] is not None:
                raise BridgeError("deadline exceeded; " + worker_diagnostic(job["error"]))
            if process.returncode:
                raise BridgeError("worker failed; " + worker_diagnostic(job["error"]))
            response = decode_one(job["output"])
            if job["kind"] == "health":
                if response != 9:
                    raise BridgeError("Incompatible WebAuthn API version")
                if not self.ready:
                    self.ready = True
                    self.send({"kind": "ready", "apiVersion": response})
            elif not job["canceled"]:
                if job["kind"] == "isUvpaa":
                    if type(response) is not int or response not in (0, 1):
                        raise BridgeError("Invalid IUVPAA response")
                    self.send({"requestId": job["id"], "isUvpaa": bool(response)})
                else:
                    credential = complete(job["prepared"], response)
                    self.send({"requestId": job["id"], "responseJson": json.dumps(credential)})
        except (BridgeError, ValueError, TypeError, KeyError, cbor2.CBORDecodeError) as error:
            if job["kind"] == "health":
                print(f"ERROR session health: {error}", file=sys.stderr)
                self.send({"kind": "disconnected"})
                self.stopping = True
            elif not job["canceled"]:
                self.send({
                    "requestId": job["id"],
                    "error": {"name": "NotAllowedError", "message": "Redirected operation failed"},
                })
                print(f"ERROR request: {error}", file=sys.stderr)

    def run(self):
        os.set_blocking(sys.stdin.fileno(), False)
        self.selector.register(sys.stdin, selectors.EVENT_READ, None)
        try:
            while not self.stopping:
                now = time.monotonic()
                if now - self.last_health >= 5 and not self.jobs and not self.queued:
                    self.launch("health", "health", rpc(8))
                    self.last_health = now
                for key, _ in self.selector.select(0.1):
                    if key.data is None:
                        self.read_input()
                        if self.stopping:
                            break
                        continue
                    job, name = key.data
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if chunk:
                        job[name].extend(chunk)
                        limit = MAX_RESPONSE + 4096 if name == "output" else 8192
                        if len(job[name]) > limit:
                            raise BridgeError("worker exceeded output limit")
                    else:
                        self.selector.unregister(key.fileobj)
                        key.fileobj.close()
                now = time.monotonic()
                for request_id, job in list(self.jobs.items()):
                    process = job["process"]
                    if now >= job["deadline"]:
                        self.cancel(job)
                    if job["stop_at"] is not None and now >= job["stop_at"] and process.poll() is None:
                        process.kill()
                    if process.poll() is not None and process.stdout.closed and process.stderr.closed:
                        del self.jobs[request_id]
                        self.finish(job)
                self.dispatch()
        finally:
            self.queued.clear()
            for job in self.jobs.values():
                self.cancel(job)
            deadline = time.monotonic() + 1
            for job in self.jobs.values():
                process = job["process"]
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                for stream in (process.stdout, process.stderr):
                    if not stream.closed:
                        stream.close()
            self.selector.close()


def main():
    if len(sys.argv) != 3:
        raise BridgeError("native host requires config path and extension origin")
    check_config(Path(sys.argv[1]), sys.argv[2])
    host = Host()

    def stop(_sig, _frame):
        host.stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    host.run()


if __name__ == "__main__":
    try:
        main()
    except (BridgeError, OSError, ValueError, KeyError) as error:
        print(f"ERROR native host: {error}", file=sys.stderr)
        sys.exit(1)
