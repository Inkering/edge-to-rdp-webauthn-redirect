"""MS-RDPEWA worker for the installed xrdp 0.9.24 ABI."""

import ctypes
import io
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

import cbor2


def library_path(root):
    for path in (root / "libxrdpapi.so", root / "build/local-api/libxrdpapi.so"):
        if path.exists():
            return str(path)
    return "/usr/lib/x86_64-linux-gnu/xrdp/libxrdpapi.so"


LIBRARY = library_path(Path(__file__).resolve().parent)
# chansrv has a 32 KiB API receive buffer and fragments DVC messages itself.
MAX_REQUEST = 16 * 1024
MAX_RESPONSE = 1024 * 1024


class BridgeError(Exception):
    pass


def session_socket():
    display = os.environ.get("DISPLAY", "").split(".")[0]
    if not display.startswith(":") or not display[1:].isdigit():
        raise BridgeError("session: expected a local xrdp DISPLAY")
    metadata = Path(f"/run/xrdp/sockdir/xrdpapi_{int(display[1:])}").lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise BridgeError("session: API endpoint is not this user's socket")
    return [metadata.st_dev, metadata.st_ino]


def decode_one(data):
    stream = io.BytesIO(data)
    value = cbor2.CBORDecoder(stream).decode()
    if stream.tell() != len(data):
        raise BridgeError("protocol: trailing bytes after CBOR object")
    return value


def rpc(command, **fields):
    return {
        "command": command,
        "flags": 0,
        "timeout": 0,
        "transactionId": uuid.uuid4().bytes_le,
        **fields,
    }


class Channel:
    def __init__(self):
        if not os.environ.get("DISPLAY"):
            raise BridgeError("session: DISPLAY is unset")
        self.lib = ctypes.CDLL(LIBRARY, use_errno=True)
        self.lib.WTSVirtualChannelOpenEx.argtypes = [
            ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint
        ]
        self.lib.WTSVirtualChannelOpenEx.restype = ctypes.c_void_p
        self.lib.WTSVirtualChannelWrite.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint)
        ]
        self.lib.WTSVirtualChannelWrite.restype = ctypes.c_int
        self.lib.WTSVirtualChannelRead.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint,
            ctypes.POINTER(ctypes.c_uint)
        ]
        self.lib.WTSVirtualChannelRead.restype = ctypes.c_int
        self.lib.WTSVirtualChannelClose.argtypes = [ctypes.c_void_p]
        self.lib.WTSVirtualChannelClose.restype = ctypes.c_int
        self.handle = self.lib.WTSVirtualChannelOpenEx(
            0xFFFFFFFF, b"WebAuthN_Channel", 1
        )
        if not self.handle:
            raise BridgeError("open: WTSVirtualChannelOpenEx returned NULL")
        self.lib.WTSVirtualChannelQuery.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint)
        ]
        self.lib.WTSVirtualChannelQuery.restype = ctypes.c_int
        self.lib.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        self.lib.WTSFreeMemory.restype = None
        pointer, size = ctypes.c_void_p(), ctypes.c_uint()
        try:
            if not self.lib.WTSVirtualChannelQuery(
                self.handle, 1, ctypes.byref(pointer), ctypes.byref(size)
            ) or size.value != ctypes.sizeof(ctypes.c_int) or not pointer.value:
                raise BridgeError("session: could not query channel socket")
            fd = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int)).contents.value
            with socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                _, uid, _ = struct.unpack(
                    "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
            if uid != os.getuid():
                raise BridgeError("session: chansrv peer belongs to another user")
        except (BridgeError, OSError):
            self.close()
            raise
        finally:
            if pointer.value:
                self.lib.WTSFreeMemory(pointer)

    def close(self):
        handle, self.handle = self.handle, None
        if handle and not self.lib.WTSVirtualChannelClose(handle):
            raise BridgeError("close: WTSVirtualChannelClose failed")

    def send(self, request):
        data = cbor2.dumps(request)
        # xrdp 0.9.24 maps each Unix socket recv() to a DVC message.
        # Keep a request below its API receive buffer size, write once.
        if len(data) > MAX_REQUEST:
            raise BridgeError(f"write: request exceeds the {MAX_REQUEST}-byte PoC limit")
        buffer = ctypes.create_string_buffer(data)
        while True:
            count = ctypes.c_uint()
            ok = self.lib.WTSVirtualChannelWrite(
                self.handle, buffer, len(data), ctypes.byref(count)
            )
            if not ok or count.value not in (0, len(data)):
                raise BridgeError("write: failed or partial DVC message")
            if count.value:
                return
            time.sleep(0.01)

    def receive(self, command, canceled=lambda: False, cancellation_id=None):
        data = bytearray()
        buffer = ctypes.create_string_buffer(4096)
        while True:
            if canceled():
                if cancellation_id is not None:
                    self.send(rpc(7, request=cancellation_id))
                raise BridgeError("canceled: operation canceled; channel closing")
            count = ctypes.c_uint()
            ok = self.lib.WTSVirtualChannelRead(
                self.handle, 100, buffer, len(buffer), ctypes.byref(count)
            )
            if not ok:
                raise BridgeError(
                    f"read: disconnected or failed after {len(data)} bytes"
                )
            if count.value > len(buffer):
                raise BridgeError("read: invalid library byte count")
            data.extend(buffer.raw[:count.value])
            if len(data) > MAX_RESPONSE:
                raise BridgeError("read: response exceeds 1 MiB limit")
            if len(data) < 4:
                continue
            hresult = struct.unpack_from("<I", data)[0]
            if hresult & 0x80000000:
                raise BridgeError(f"RPC {command}: HRESULT=0x{hresult:08x}")
            if command in (6, 8):
                if len(data) < 8:
                    continue
                if len(data) != 8:
                    raise BridgeError("protocol: simple response is not 8 bytes")
                return struct.unpack_from("<I", data, 4)[0]
            try:
                return decode_one(data[4:])
            except cbor2.CBORDecodeEOF:
                continue
            except cbor2.CBORDecodeError as exc:
                raise BridgeError("protocol: invalid response CBOR") from exc


def worker():
    canceled = False

    def cancel(_sig, _frame):
        nonlocal canceled
        canceled = True

    signal.signal(signal.SIGUSR1, cancel)
    request = decode_one(sys.stdin.buffer.read(MAX_REQUEST + 1))
    if not isinstance(request, dict) or request.get("command") not in (5, 6, 8):
        raise BridgeError("worker: invalid command")
    print("stage=open", file=sys.stderr, flush=True)
    channel = Channel()
    try:
        print("stage=version", file=sys.stderr, flush=True)
        channel.send(rpc(8))
        version = channel.receive(8, lambda: canceled)
        # API v9 is verified on this session; no guessing about older clients.
        if version != 9:
            raise BridgeError(f"version: expected tested API 9, received {version}")
        print(f"stage=RPC-{request['command']}", file=sys.stderr, flush=True)
        channel.send(request)
        cancellation_id = request.get("webAuthNPara", {}).get("cancellationId")
        response = channel.receive(
            request["command"], lambda: canceled, cancellation_id
        )
        sys.stdout.buffer.write(cbor2.dumps(response))
        sys.stdout.buffer.flush()
    finally:
        channel.close()


def start(request):
    encoded = cbor2.dumps(request)
    if len(encoded) > MAX_REQUEST:
        raise BridgeError(f"write: request exceeds the {MAX_REQUEST}-byte PoC limit")
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True,
    )
    return process, encoded


def worker_diagnostic(error):
    lines = error.decode("utf-8", "replace").splitlines()
    stage = next((line for line in reversed(lines) if line.startswith("stage=")),
                 "stage=unknown")
    failure = next((line for line in reversed(lines) if line.startswith("ERROR ")), None)
    return stage + (f"; {failure}" if failure else "")


def exchange(request, timeout=65):
    process, encoded = start(request)
    try:
        output, error = process.communicate(encoded, timeout=timeout)
    except subprocess.TimeoutExpired:
        process.send_signal(signal.SIGUSR1)
        try:
            _, error = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            _, error = process.communicate()
        raise BridgeError("deadline exceeded; " + worker_diagnostic(error)) from None
    if process.returncode:
        raise BridgeError("worker failed; " + worker_diagnostic(error))
    return decode_one(output)


def unwrap(response):
    if not isinstance(response, dict):
        raise BridgeError("protocol: WebAuthn response is not a map")
    # The normative table capitalizes these keys; published wire examples and
    # FreeRDP use lowercase. Accept either, never conflicting duplicates.
    def field(lower):
        upper = lower[0].upper() + lower[1:]
        if lower in response and upper in response:
            raise BridgeError("protocol: duplicate status/response fields")
        if lower in response:
            return response[lower]
        if upper in response:
            return response[upper]
        raise BridgeError(f"protocol: missing {lower}")

    status, payload = field("status"), field("response")
    if type(status) is not int:
        raise BridgeError("protocol: WebAuthn status is not an integer")
    if status != 0:
        raise BridgeError(f"WebAuthn operation status=0x{status:x}")
    if not isinstance(payload, bytes) or not payload:
        raise BridgeError("protocol: missing CTAP response bytes")
    if payload[0] != 0:
        raise BridgeError(f"CTAP status=0x{payload[0]:02x}")
    value = decode_one(payload[1:])
    if not isinstance(value, dict):
        raise BridgeError("protocol: CTAP response is not a map")
    return value


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--worker"]:
            raise BridgeError("this module is an internal worker; use hardware_test.py")
        worker()
    except (BridgeError, OSError, cbor2.CBORDecodeError) as error:
        print(f"ERROR {error}", file=sys.stderr, flush=True)
        sys.exit(1)
