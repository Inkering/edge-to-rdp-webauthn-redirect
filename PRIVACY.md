# Linux Edge to RDP WebAuthn Redirect privacy policy

Linux Edge to RDP WebAuthn Redirect is an experimental browser extension and separately
installed Linux helper for WebAuthn redirection inside an xrdp desktop. This
policy describes this project's extension and Edge native helper, not Microsoft
Edge, Windows, xrdp, the authenticator, or the websites you visit.

## Data processed and purpose

While connected, the extension handles WebAuthn registration, authentication,
and authenticator-capability requests supplied by the browser. Depending on
the request, these include the requesting origin and relying-party ID,
challenges, client data, credential identifiers, account names/display names
and user identifiers, authentication requirements, and authenticator responses
such as signatures, public keys and attestation data. Some of these fields can
identify you or an account.

These data are used only to complete the WebAuthn operation you initiate.
The extension passes requests through private native-messaging pipes to the
local Linux helper. The helper forwards supported operations to your Windows
RDP client through the existing session's MS-RDPEWA WebAuthn channel.
Responses return through the helper and browser to the requesting website.
This is a transmission of authentication data, even though the project has no
developer-operated collection service.

The extension does not receive authenticator private keys or security-key
PINs. Enter a PIN only in the Windows authentication UI. The extension does
not request access to browsing history, cookies, passwords, or OAuth tokens;
it has no content scripts or general page-reading permission.

## Storage and diagnostics

The extension and native helper process authentication payloads in memory;
they do not intentionally save those payloads or credential databases to disk.
The helper installer writes a private local configuration containing the
authorized extension origin, Linux user/session identifiers and xrdp socket
identity, plus a launcher and native-host manifest. These are used to restrict
access, not to record authentication history.

The service-worker console and native-helper stderr report connection stages,
status and errors, not PINs or authentication payloads. Diagnostic messages
may remain in browser or operating-system logs according to their settings.
Do not submit account data, credential data, PINs, or unredacted authentication
logs in public support reports.

## Sharing and control

There is no project analytics, advertising, sale of user data, or transmission
to a developer-operated server. Authentication data are relayed to the
Windows client/authenticator and back to the requesting website solely for
the requested operation. Those products and websites have their own privacy
practices; this policy does not control their storage or telemetry.

Click the extension's toolbar button to disconnect redirection. Disable or
uninstall the extension to stop it running. Uninstalling the extension does not
remove the separately installed Linux helper/configuration or delete
credentials stored on your authenticator or accounts at websites.

## Contact and updates

For privacy questions, use the project's
[issue tracker](https://github.com/Inkering/edge-to-rdp-webauthn-redirect/issues)
without including sensitive information.
Policy changes are published in this file and its repository history. This
policy accompanies extension version 0.1.1.
