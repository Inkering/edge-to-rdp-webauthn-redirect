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
- For the prebuilt `.deb`: **Ubuntu 24.04 amd64 with xrdp 0.9.24**, permission to
  install packages with sudo, and access to Ubuntu repositories for dependencies.
- For source development only: Python 3 and the dependencies in
  `requirements.txt`, a C11 compiler, make, and xrdp libraries. The local API
  build also requires curl and patch; JavaScript tests require GJS.

The helper currently targets the xrdp **0.9.24 ABI**, the x86-64 library path
`/usr/lib/x86_64-linux-gnu/xrdp/libxrdpapi.so`, and negotiated WebAuthn **API 9**.
It is not a general xrdp-version or CPU-architecture adapter.
In particular, xrdp 0.10.x is not currently supported by this package.

## Install the latest built artifacts

These instructions run on the **Linux desktop**, not Windows. No Git checkout,
compiler, pip, or virtual environment is needed. CI builds are experimental
snapshots; a green build verifies automated checks, not the real RDP/key path.

### 1. Download a matching extension and helper

Open [Actions: Build and release](https://github.com/Inkering/edge-to-rdp-webauthn-redirect/actions/workflows/release.yml).
Choose the **most recent successful push build for `main`**, not a pull-request
build. On its summary page, download the **`release-ubuntu-24.04-amd64`**
artifact. Downloading Actions artifacts requires signing in to GitHub; these
artifacts expire after 14 days. If none are available, a maintainer needs to
run a new build.

Extract the downloaded artifact into a new directory. It contains:

```text
edge-to-rdp-webauthn-redirect-VERSION.zip
edge-to-rdp-webauthn-redirect_VERSION-1_amd64.deb
SHA256SUMS
```

Keep all three files from the **same build** together. The outer Actions
artifact ZIP is not the extension ZIP.

When a published release is available, you can instead download these same
three files from [Releases](https://github.com/Inkering/edge-to-rdp-webauthn-redirect/releases),
including a published prerelease if appropriate. Draft releases are not
public downloads. Do not select GitHub's automatic "Source code" archives.

### 2. Enable Windows WebAuthn redirection

On Windows, add this setting to the `.rdp` file used by `mstsc.exe`:

```text
redirectwebauthn:i:1
```

Disconnect/reconnect using that file before continuing. Windows and
organization policy must also permit WebAuthn redirection; this setting
cannot override an administrative deny. The security key stays connected to
the Windows client.

### 3. Verify and install the helper

In a Linux terminal, change into the directory containing the three extracted
files, then run:

```sh
sha256sum -c SHA256SUMS &&
sudo apt update &&
sudo apt install ./edge-to-rdp-webauthn-redirect_*_amd64.deb
```

Both checksum checks must report `OK`; stop if they do not. Use a directory
containing only one build so the filename wildcard selects one `.deb`.
Checksums detect corruption or mismatched files, not independent publisher
authenticity. Do not force installation if apt reports incompatible dependencies.

The package installs Python dependencies through apt and includes a private
timeout-patched xrdp API library; it does not replace system libraries.
An apt `N: ... unsandboxed as root ... _apt ... Permission denied` notice can
occur when the download directory is inaccessible to `_apt`; that notice
alone does not mean installation failed. Confirm with
`dpkg-query -W -f='${Status}\n' edge-to-rdp-webauthn-redirect`, which should
print `install ok installed`. Do not loosen your home-directory permissions.

### 4. Load the extension in Linux Edge

Disable any previous copy in `edge://extensions` before switching builds.
Extract the **inner extension ZIP** to a persistent user-owned directory:

```sh
mkdir -p "$HOME/.local/share/edge-to-rdp-webauthn-redirect"
unzip edge-to-rdp-webauthn-redirect-*.zip \
  -d "$HOME/.local/share/edge-to-rdp-webauthn-redirect"
```

For an update in the same directory, allow unzip to replace the old extension
files. Keep the directory at the same path after installation.

#### Load the unpacked extension

In **Edge inside the Linux xrdp desktop**, not Edge on Windows:

1. Type `edge://extensions` into the address bar and press Enter.
2. Turn on **Developer mode** on the extensions page. This reveals developer
   controls such as **Load unpacked**. If your organization disables them,
   ask your administrator; do not bypass its policy.
3. Click **Load unpacked**. In the directory picker, choose
   `/home/YOUR_LINUX_USER/.local/share/edge-to-rdp-webauthn-redirect`
   (substitute your actual home directory). You can print the exact path with
   `printf '%s\n' "$HOME/.local/share/edge-to-rdp-webauthn-redirect"`.
   If hidden directories are not shown, enter the full path in the picker's
   location field; many Linux file pickers open that field with Ctrl+L.
4. Select the **directory that directly contains `manifest.json` and
   `worker.js`**, then confirm the folder selection. Do not select the
   download directory, the outer artifact directory, or either ZIP file.
5. Confirm that a **Linux Edge to RDP WebAuthn Redirect** card appears.
   The helper is not connected yet; register its ID in the next step.

For a source checkout, select its `extension` directory instead. When updating
an already loaded unpacked extension at the same path, replace the extracted
files and click **Reload** on its existing card instead of adding another copy.

#### Find and copy the extension ID

Keep **Developer mode** enabled at `edge://extensions`. On the
**Linux Edge to RDP WebAuthn Redirect** card, find **ID** and copy its value.
If the card does not show it, open **Details** for that extension and look
for its ID there. The ID is **32 lowercase letters in the range `a` through
`p`**; it is not the extension name, version, or native-host name
`org.local.xrdp_webauthn`.

Use the ID shown by **your installed copy**, not another user's ID or an
example from a guide. Keep it handy for `edge-rdp-webauthn-setup` below.
If you change the unpacked location, profile, or later switch to a store
installation, check the ID again and rerun setup if it changes.

This unpacked installation is not a signed CRX or automatic-update channel.

### 5. Register this desktop and connect

Run these commands **inside the intended xrdp desktop as your normal user,
without sudo**:

```sh
rdpewa-probe 25
edge-rdp-webauthn-setup YOUR_32_CHARACTER_EXTENSION_ID
```

Replace the placeholder with the ID copied from Edge. The probe must succeed
with WebAuthn API version **9** before proceeding; `25` is its total deadline
in seconds. It only checks the channel/version, without creating credentials
or requesting a security-key PIN.

Reload the extension in `edge://extensions`, then click its toolbar button
if needed. The badge should become **`ON`** after helper readiness and proxy
attachment. Package installation intentionally does not register any user's
desktop. Rerun setup when the extension ID or desktop socket identity changes,
including when replacing a previous source-based helper registration.

### 6. Try an authentication

In Linux Edge, sign in to a non-critical account that already has a passkey on
the Windows-connected key, keeping another sign-in/recovery method available.
Expect the authentication prompt on Windows. Enter any PIN **only in the
Windows authentication dialog**, then touch the key when requested.

`ON` and a successful probe are not proof of a successful authentication.
If it fails, note the badge state, website error, and whether a Windows prompt
appeared. Do not share PINs or authentication payloads. Disconnect or disable
the extension to stop redirection.

For controlled registration/assertion verification using a source checkout,
see [Verify an actual authentication](#verify-an-actual-authentication).
For package upgrades/removal and maintainer release instructions, see
[GitHub releases](publishing/github-releases.md).

## Set up the Linux helper from source

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
enable Developer mode, and load either this checkout's `extension` directory
or the extracted extension ZIP directory as an unpacked extension.
Organizational policy must permit this. Prebuilt-download users can follow
the [installation quickstart](#install-the-latest-built-artifacts) above.

Copy the displayed extension ID and register the native helper. For the `.deb`:

```sh
edge-rdp-webauthn-setup YOUR_32_CHARACTER_EXTENSION_ID
```

For a source checkout:

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
For a source installation, keep this checkout and its `.venv` at their
installed paths. For a packaged installation, keep the helper package installed.

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

The [GitHub release workflow](publishing/github-releases.md) builds and checks
both the ZIP and Ubuntu `.deb`; a `vVERSION` tag creates a draft prerelease.

See the [publishing checklist](publishing/edge-addons.md) and
[privacy policy](PRIVACY.md). Report issues through the
[public issue tracker](https://github.com/Inkering/edge-to-rdp-webauthn-redirect/issues)
without including authentication data or unredacted logs.

## Contributing

Bug reports, documentation improvements, focused fixes, and compatibility
testing are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for development
setup, test commands, pull-request expectations, and safe reporting guidance.

## Privacy and removal

The extension requests only `webAuthenticationProxy` and `nativeMessaging`.
It has no content scripts, host permissions, analytics, or developer-operated
collection service. Authentication data still pass through the Linux helper
and Windows client; see [PRIVACY.md](PRIVACY.md) for details.

Disconnect or disable the extension to stop redirection. Uninstalling it does
not remove the separate helper, its configuration, or credentials on a key.
Remove the packaged helper with `sudo apt remove edge-to-rdp-webauthn-redirect`.
Package removal/purge intentionally leaves per-user registrations alone.
After disabling the extension, remove the native-host manifest from each Edge user-data
root where you installed it and the two files in `~/.local/lib/linux-rdpewa`
listed above if you no longer use this helper.

## License

[MIT](LICENSE). Downloaded upstream xrdp sources are separately licensed under
their included notices.
