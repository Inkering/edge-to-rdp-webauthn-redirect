# GitHub release process

The `Build and release` workflow runs on pushes to `main`, pull requests,
manual dispatches, and `v*` tags. It builds and tests on Ubuntu 24.04 amd64,
checks package installation/removal, and uploads a workflow artifact containing:

```text
edge-to-rdp-webauthn-redirect-VERSION.zip
edge-to-rdp-webauthn-redirect_VERSION-1_amd64.deb
SHA256SUMS
```

Only a version-tag push creates a GitHub Release, initially a **draft
prerelease**. A push to `main` does not publish a release. No store submission
or machine policy change is automated.

## Repository setup

Enable GitHub Actions for the repository and allow the pinned official
`actions/checkout`, `actions/upload-artifact`, and `actions/download-artifact`
actions. The release job requests `contents: write` for its built-in
`GITHUB_TOKEN`; no personal access token or signing secret is needed.
Organization policies must allow that permission.

## Prepare a release

1. Update `extension/manifest.json` to the intended version. Add a corresponding
   `debian/changelog` entry using `VERSION-1`, and update version-specific
   documentation and the privacy policy as needed. The workflow rejects
   mismatched versions or tags.
2. Push the changes to `main` and wait for `Build and release` to pass.
3. Tag that exact commit and push the tag. For the current version:

   ```sh
   git tag -a v0.1.1 -m "Linux Edge to RDP WebAuthn Redirect 0.1.1"
   git push origin v0.1.1
   ```

4. Open the resulting draft prerelease. Download all three assets into the
   same directory and verify `sha256sum -c SHA256SUMS` on Linux.
5. Test these exact assets on Ubuntu 24.04 amd64 with xrdp 0.9.24, Windows mstsc,
   and a real authenticator. Check fresh installation, registration and signed
   authentication, browser cancellation, toolbar reconnect, and RDP disconnect
   behavior. Accurately disclose unresolved limitations; CI mocks do not prove
   hardware operation.
6. Edit the release notes with verification evidence and known limitations,
   then manually publish the prerelease when appropriate. Keep the experimental
   label until production-readiness gaps are resolved.

If a tag build fails, fix the problem and use a new version/tag rather than
moving a tag that users may already have fetched.

## Install released artifacts

On the supported Linux desktop, download the `.deb` and install with apt so
dependencies are resolved:

```sh
sudo apt install ./edge-to-rdp-webauthn-redirect_0.1.1-1_amd64.deb
```

The package installs the helper under
`/usr/lib/edge-to-rdp-webauthn-redirect`, plus `edge-rdp-webauthn-setup` and
`rdpewa-probe` in `/usr/bin`. It uses Ubuntu's Python/CBOR/cryptography
packages; no checkout, virtual environment, or install-time pip download is
needed. It depends on xrdp 0.9.24 and refuses incompatible newer ABI versions.

The included private xrdp API has only the existing 500 ms -> 15 second
channel-open timeout change. It links Ubuntu's xrdp `libcommon` and does not
replace system libraries. Upstream source notices, license, and the patch are
installed under `/usr/share/doc/edge-to-rdp-webauthn-redirect/xrdpapi`.
The helper and probe both use the private library.

Extract the extension ZIP to a persistent directory, then load that directory
through Developer mode at `edge://extensions` in **Linux Edge**, if policy
permits. The ZIP is not a signed CRX, one-click installation, or automatic-update
channel. A future Edge Add-ons installation is separate.

Inside the intended xrdp desktop, as the normal desktop user:

```sh
rdpewa-probe 25
edge-rdp-webauthn-setup YOUR_32_CHARACTER_EXTENSION_ID
```

Windows must have WebAuthn redirection enabled as described in the README.
The setup command supports `--edge-user-data-dir` for an alternate Edge
user-data root. It still authorizes only one exact extension/user/desktop
binding; rerun it after the session socket is recreated or extension ID changes.
Do not run it with sudo. Package installation intentionally performs no
per-user registration.

For source-based verification tools such as `rp_server.py`, use the matching
release's source checkout and the README's Python environment instructions.
Those test tools are not installed as production helper commands.

## Remove or upgrade

Disable the extension before removing the helper:

```sh
sudo apt remove edge-to-rdp-webauthn-redirect
```

Neither package removal nor purge deletes users' per-session config or Edge
native-host manifests. Remove your own registration files listed in the README
if no longer needed; never delete another user's files. Authenticator
credentials and website accounts are not removed.

For upgrades, install the new `.deb` with apt, reload/reconnect the extension,
and rerun setup if its ID or session socket changed. A previous source-based
registration must be replaced by running the packaged setup command once.

## Build locally on the target Linux version

Install the `Build-Depends` in `debian/control`, then run:

```sh
dpkg-buildpackage --build=binary --no-sign
python3 tools/package_extension.py
```

The build explicitly fetches pinned upstream xrdp sources, so it requires
network access. No key is required for these direct-download release assets.
SHA256SUMS provides integrity checking against the release's checksum file,
not independent publisher authentication. No apt repository is created.
