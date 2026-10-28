# Linux Edge to RDP WebAuthn Redirect

Use a Windows-connected FIDO2 security key, such as a YubiKey, in Microsoft
Edge running **inside a Linux xrdp desktop**. The extension forwards WebAuthn
requests to a separately installed Linux native helper, which uses the RDP
client's built-in MS-RDPEWA WebAuthn redirection.

```text
Website in Linux Edge -> extension -> Linux native helper
                     -> xrdp -> Windows RDP client -> security key
```

This is WebAuthn inside the remote desktop, not Linux login, USB passthrough,
or smart-card redirection. No custom Windows client or Windows hook is needed.
Only Microsoft Edge is currently targeted; other Chromium browsers are not
claimed as supported.

**Experimental preview.** Real Edge registration and signed authentication
worked with the original helper through Windows mstsc, and Microsoft passkey
sign-in was reported working. Channel opening can still fail intermittently.
Resident-key discovery, Windows UI cancellation, and live disconnect recovery
are not yet verified end to end. This repository contains the extension and
helper extracted from the original project, without its separate browser
prototypes or investigation logs. Migration alone is not a new hardware test.

## Requirements

- Microsoft Edge on Linux exposing the Manifest V3 `webAuthenticationProxy` API.
- An xrdp desktop with dynamic virtual channels (`drdynvc`) enabled.
- A Windows RDP client supporting and permitting WebAuthn redirection.
  The original working path used stock `mstsc.exe`.
- A supported authenticator connected to the Windows client.
- Python 3 and the dependencies in `requirements.txt`; the original environment
  used Python 3.12.
- For the diagnostic probe or optional local API build: a C11 compiler, make,
  and xrdp libraries. The local API build also requires curl and patch.

The helper currently targets the xrdp **0.9.24 ABI**, the x86-64 library path
`/usr/lib/x86_64-linux-gnu/xrdp/libxrdpapi.so`, and negotiated WebAuthn **API 9**.
It is not a general xrdp-version or CPU-architecture adapter.

## Set up the Linux helper

Run the following commands **on Linux, inside the intended xrdp desktop**,
as the desktop user, without sudo. Keep the checkout in a directory writable
only by that user. The original `DISPLAY` and `XRDP_SESSION=1` must be present.

In the `.rdp` file used on Windows, enable:

```text
redirectwebauthn:i:1
```

Reconnect after editing. This cannot override a Windows or organization policy
that prohibits WebAuthn redirection.

Create the helper environment in this repository:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Build and run the standalone diagnostic probe:

```sh
make
./build/rdpewa-probe 25
```

The argument is a total deadline in seconds (1..120). Success requires a
successful version exchange, not merely an open channel. Confirm the probe
works in the current connection before using the extension.

### Optional xrdp channel-open timeout workaround

The original xrdp 0.9.24 API waited only 500 ms for the channel-open
acknowledgement; a Windows client sometimes responded much later. If this
affects your environment:

```sh
make local-api
make
./build/rdpewa-probe 25
```

This explicitly downloads a small subset of upstream xrdp sources pinned to
commit `85c863dba6b2e4863b8760475c8faa7f1b169fdd`, applies the included
500 ms -> 15 second timeout patch, and links against the installed xrdp
`libcommon`. Upstream sources retain their own license notices.
No system library or daemon is replaced. Both the probe and Python helper
select `build/local-api/libxrdpapi.so` when present; keep it in place.
Failures do not fall back silently to another transport. This workaround
does not guarantee channel-lifecycle reliability.

`make XRDP_LIBDIR=/actual/library/directory` overrides the probe's link/runtime
library directory only; the Python helper retains its library selection above.

## Install the extension

Until a store release is available, open `edge://extensions` in **Linux Edge**,
enable Developer mode, and load this checkout's `extension` directory as an
unpacked extension. Organizational policy must permit this.

Copy the displayed extension ID and register the native helper:

```sh
.venv/bin/python install_native.py YOUR_32_CHARACTER_EXTENSION_ID
```

Reload the extension. For a future store installation, register the actual
store-assigned extension ID instead. Do not use wildcard origins.

The toolbar button connects/disconnects the proxy. Its badge shows `...` while
connecting, `ON` after native readiness and proxy attachment, `OFF` when
detached, and `ERR` for extension/API failures. `ON` is not proof of a
successful authentication. Connection diagnostics appear in the extension's
service-worker console and native-helper stderr, without request payloads.

For another Edge channel or isolated user-data root:

```sh
.venv/bin/python install_native.py YOUR_32_CHARACTER_EXTENSION_ID \
  --edge-user-data-dir /absolute/path/to/edge-user-data
```

Use the same root passed to Edge via `--user-data-dir`, not its `Default` or
`Profile 1` subdirectory. The directory must be real and user-owned.

The installer writes:

```text
~/.local/lib/linux-rdpewa/session.json
~/.local/lib/linux-rdpewa/native-host
~/.config/microsoft-edge/NativeMessagingHosts/org.local.xrdp_webauthn.json
```

The last location changes when using `--edge-user-data-dir`. The existing
native-host identifier and helper directory are intentionally unchanged.
The helper binds one exact extension origin, user, desktop and xrdp socket
identity. Reinstall after a recreated desktop socket or changed extension ID.
Alternate Edge installations share the same per-user helper binding.
Keep this checkout and its `.venv` at their installed paths.

## Verify an actual authentication

Start the disposable local relying party:

```sh
.venv/bin/python rp_server.py
```

Visit **http://localhost:8765** in Linux Edge, register, then authenticate.
Use `localhost`, not its numerical IP address. The RP verifies the assertion
signature, exact client data, RP hash, user-presence/user-verification flags,
and credential/counter checks. Its state is memory-only and discarded on exit.
This is a test service, not an account store or attestation trust verifier.

Alternatively, exercise the Windows/security-key path without Edge:

```sh
.venv/bin/python hardware_test.py --run
```

The default test creates a disposable non-discoverable ES256 credential.
The RP's discoverable-passkey checkbox and
`hardware_test.py --run --resident` instead **write a discoverable credential
onto the authenticator** and remain unverified on the live Windows/key path.
Remove disposable resident credentials afterwards with a trusted management
tool. Enter any security-key PIN **only into Windows authentication UI**,
never a Linux terminal, webpage, or support report.

## Development and packaging

On a Linux development machine with xrdp libraries and GJS installed:

```sh
make test
```

This covers the probe, helper, WebAuthn conversion, packaging, and mocked
extension lifecycle. Tests of the optional local API run only when it is built.
Mocks and local tests are not evidence of Windows or hardware operation.

Build the extension-only submission ZIP with Python:

```sh
python3 tools/package_extension.py
```

Output: `build/edge-to-rdp-webauthn-redirect-0.1.1.zip`. Only the manifest,
service worker, and extension icons are included. Users must install the
Linux helper separately. Packaging does not sign, publish, or submit anything.
`make extension-icons` regenerates the committed original artwork with GJS/Cairo.

See the [publishing checklist](publishing/edge-addons.md) and
[privacy policy](PRIVACY.md). Report issues through the
[public issue tracker](https://github.com/Inkering/edge-to-rdp-webauthn-redirect/issues)
without including authentication data or unredacted logs.

## Privacy and removal

The extension requests only `webAuthenticationProxy` and `nativeMessaging`.
It has no content scripts, host permissions, analytics, or developer-operated
collection service. Authentication data still pass through the Linux helper
and Windows client; see [PRIVACY.md](PRIVACY.md) for details.

Disconnect or disable the extension to stop redirection. Uninstalling it does
not remove the separate helper, its configuration, or credentials on a key.
After disabling it, remove the native-host manifest from each Edge user-data
root where you installed it and the two files in `~/.local/lib/linux-rdpewa`
listed above if you no longer use this helper.

## License

[MIT](LICENSE). Downloaded upstream xrdp sources are separately licensed under
their included notices.
