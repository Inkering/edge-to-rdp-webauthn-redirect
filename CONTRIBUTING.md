# Contributing

Thanks for helping improve Linux Edge to RDP WebAuthn Redirect. This is an
experimental project for WebAuthn inside a Linux xrdp desktop, not Linux login
or USB passthrough. Contributions should preserve its narrow purpose and
clearly distinguish automated checks from real Windows/authenticator evidence.

## Before starting

Read the [README](README.md), [privacy policy](PRIVACY.md), and known
limitations. The packaged target is currently **Ubuntu 24.04 amd64 with
xrdp 0.9.24 and WebAuthn API 9**. Other xrdp releases, architectures, browsers,
and authenticators need investigation and testing before being advertised.

For a substantial feature or compatibility change, open an
[issue](https://github.com/Inkering/edge-to-rdp-webauthn-redirect/issues) first
to discuss scope. Small documentation fixes and focused bug fixes can go
straight to a pull request.

## Development setup

Fork the repository and create a topic branch from `main`. Work in a checkout
writable only by your user. For the supported Linux development environment:

```sh
sudo apt update
sudo apt install --no-install-recommends \
  build-essential debhelper dpkg-dev curl patch gjs xrdp \
  python3 python3-venv python3-cbor2 python3-cryptography
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Do not install an incompatible xrdp version or replace a working desktop's
system libraries to make tests pass. Use a disposable VM when investigating
different distributions or xrdp versions.

The project has no Node/npm build requirement. The extension is JavaScript;
Python packages its runtime files into a ZIP. GJS runs the mocked extension
tests and regenerates the artwork.

## Run focused checks

For extension packaging only, no xrdp desktop or Python dependencies are needed:

```sh
python3 -m unittest discover -s tests -p test_extension_package.py -v
python3 tools/package_extension.py
```

For helper, probe, WebAuthn conversion, and mocked extension lifecycle checks
on the supported Linux environment:

```sh
make local-api
make test
```

`make local-api` explicitly downloads pinned upstream xrdp sources and builds
the timeout-patched API privately under `build/`; it does not replace system
libraries. Building it also enables the local API timeout test. The tests use
synthetic data and mocks, not a real Windows client or security key.

For Debian packaging, the build uses Ubuntu's system Python dependencies,
not the virtual environment:

```sh
dpkg-buildpackage --build=binary --no-sign
```

This builds the helper package and runs its tests. See
[the release guide](publishing/github-releases.md) and
[workflow](.github/workflows/release.yml) for installed-package smoke checks.
Do installation/removal testing in a disposable Ubuntu 24.04 amd64 environment.

There is no standalone formatter/linter configuration for application code.
Follow the surrounding style and run `git diff --check`. The GitHub
**Build and release** workflow checks pull requests and pushes to `main`;
its uploaded artifacts expire after 14 days. CI success does not establish
hardware compatibility or production readiness.

## Verify real authentication changes

Changes to request conversion, cancellation, native messaging, session
binding, or xrdp transport should include the relevant focused regression
tests. For live validation, follow the README's source-helper setup and
disposable relying-party instructions.

Record the distro/architecture, xrdp, Linux Edge, Windows/RDP client versions,
and authenticator capabilities used. Report which operations actually passed:
channel/version negotiation, registration, signed authentication, cancellation,
and disconnect/reconnect. If a check was not run, say so. Proxy attachment,
synthetic signatures, and a passing probe are not hardware-authentication proof.

Start with non-critical accounts and retain another sign-in method. The default
hardware test creates a disposable non-discoverable credential. Resident-key
tests explicitly write discoverable credentials onto the key; obtain consent
and remove test credentials afterwards with a trusted management tool.
Enter PINs only in Windows authentication UI.

## Pull requests

Keep each PR focused and explain the problem, change, and user-visible impact.
Include the commands/checks run and disclose untested paths. Add regression
tests for changed behavior where appropriate, and update setup, privacy, or
release documentation when the behavior changes.

Preserve these boundaries:

- Authorize one exact extension origin and retain user/desktop/socket checks;
  do not broaden native messaging access or add wildcard origins.
- Keep authentication payloads, PINs, and credential material out of logs,
  artifacts, issues, and committed test fixtures. Use synthetic test data.
- Keep the extension ZIP limited to runtime files. Do not include helper
  configuration, keys, or prototype code.
- Surface unsupported inputs and transport failures rather than silently
  substituting a response or another transport.
- Keep root package installation separate from normal-user session registration,
  and do not replace system xrdp libraries.

New platform support must include dependency/ABI investigation and appropriate
validation, not just removal of package version guards. Discuss runtime
dependencies and permission changes before adding them.

Contributions are made under the repository's [MIT license](LICENSE).
Preserve notices for upstream xrdp sources, which are separately licensed.

## Report bugs safely

Include a minimal reproduction, component versions, installation method
(source or prebuilt artifact), build commit or release version, probe result,
badge state, whether Windows showed a prompt, and sanitized error text.
Do not upload account identifiers, challenges, credential IDs, signatures,
attestation data, private keys, PINs, or unredacted authentication logs.

For a suspected vulnerability, do not post exploit details or sensitive data
in a public issue. Use GitHub's **Report a vulnerability** option on the
repository's Security page if available. If it is unavailable, ask the
maintainer to arrange a private reporting channel without posting the details.
Never commit a real secret to demonstrate a problem.

## Release changes

Maintainers follow [publishing/github-releases.md](publishing/github-releases.md).
Version tags create draft prereleases, not automatic public releases.
Do not create a release tag for a contribution unless requested. Updates for
Microsoft Edge Add-ons follow the [separate checklist](publishing/edge-addons.md).
