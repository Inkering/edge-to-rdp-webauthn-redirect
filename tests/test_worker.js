// Run with gjs: only browser/native APIs are mocked, never hardware evidence.
"use strict";
const GLib = imports.gi.GLib;
const ByteArray = imports.byteArray;
let connections = [];
let completions = [];
let attaches = 0;
let detaches = 0;
let badge = "";
let delayAttach = null;
function event() {
  const handlers = [];
  return {
    addListener(fn) { handlers.push(fn); },
    async emit(...args) {
      for (const fn of handlers) await fn(...args);
    },
  };
}
const proxy = {
  onCreateRequest: event(), onGetRequest: event(), onIsUvpaaRequest: event(),
  onRequestCanceled: event(), onRemoteSessionStateChange: event(),
  async attach() { attaches++; if (delayAttach) await delayAttach; },
  async detach() { detaches++; },
  async completeCreateRequest(value) { completions.push(["create", value]); },
  async completeGetRequest(value) { completions.push(["get", value]); },
  async completeIsUvpaaRequest(value) { completions.push(["isUvpaa", value]); },
};
globalThis.chrome = {
  webAuthenticationProxy: proxy,
  action: {
    onClicked: event(),
    setBadgeText({text}) { badge = text; },
    setBadgeBackgroundColor() {},
  },
  runtime: {
    onStartup: event(), onInstalled: event(),
    connectNative(name) {
      assert(name === "org.local.xrdp_webauthn", "native host name");
      const connection = {
        sent: [], onDisconnect: event(), onMessage: event(),
        postMessage(message) { this.sent.push(message); },
        disconnect() { void this.onDisconnect.emit(); },
      };
      connections.push(connection);
      return connection;
    },
  },
};
function assert(value, message) {
  if (!value) throw new Error(message);
}
const [, source] = GLib.file_get_contents("extension/worker.js");
const errors = [];
new Function("console", ByteArray.toString(source))({
  error: (...args) => errors.push(args.join(" ")),
});
const loop = new GLib.MainLoop(null, false);
let failed = false;
(async () => {
  assert(connections.length === 0, "worker wake must not race the toolbar toggle");
  await chrome.action.onClicked.emit();
  let connection = connections[0];
  assert(connections.length === 1, "first click on a freshly woken worker must connect");
  await chrome.runtime.onStartup.emit();
  await chrome.runtime.onInstalled.emit();
  assert(connections.length === 1, "startup/install must not duplicate an existing connection");
  assert(attaches === 0, "must wait for real native readiness");
  await connection.onMessage.emit({kind: "ready", apiVersion: 9});
  assert(attaches === 1 && badge === "ON", "attach after readiness");
  const options = {extensions: {remoteDesktopClientOverride: {
    origin: "https://example.com", sameOriginWithAncestors: true,
  }}};
  for (const [kind, method] of [["get", "onGetRequest"], ["create", "onCreateRequest"]]) {
    await proxy[method].emit({requestId: 7, requestDetailsJson: JSON.stringify(options)});
    assert(JSON.stringify(connection.sent.at(-1).options) === JSON.stringify(options),
      "trusted context must be forwarded unchanged");
    await connection.onMessage.emit({requestId: 7, responseJson: "{}"});
    assert(completions.at(-1)[0] === kind, "matching completion API");
  }
  const rejection = {name: "NotSupportedError", message: "Unsupported WebAuthn option"};
  await proxy.onGetRequest.emit({
    requestId: 10, requestDetailsJson: '{"challenge":"must-not-be-logged"}',
  });
  await connection.onMessage.emit({requestId: 10, error: rejection});
  assert(errors.length === 1 && errors[0].includes(rejection.message),
    "native rejection must be visible without a custom console listener");
  assert(!errors[0].includes("must-not-be-logged"), "never log authentication payloads");
  assert(completions.at(-1)[1].error === rejection && badge === "ON",
    "report request rejection without changing completion or attachment");
  await proxy.onIsUvpaaRequest.emit({requestId: 8});
  await connection.onMessage.emit({requestId: 8, isUvpaa: true});
  assert(completions.at(-1)[0] === "isUvpaa", "capability completion");
  await proxy.onGetRequest.emit({requestId: 9, requestDetailsJson: "{}"});
  await proxy.onRequestCanceled.emit(9);
  assert(connection.sent.at(-1).kind === "cancel", "forward cancellation");
  const count = completions.length;
  await connection.onMessage.emit({requestId: 9, responseJson: "{}"});
  assert(completions.length === count, "never complete canceled request");
  await connection.onMessage.emit({kind: "disconnected"});
  assert(detaches >= 1 && badge === "OFF", "detach on session loss");
  await chrome.runtime.onStartup.emit();
  connection = connections.at(-1);
  let resolveAttach;
  delayAttach = new Promise(resolve => { resolveAttach = resolve; });
  const oldReady = connection.onMessage.emit({kind: "ready"});
  await Promise.resolve();
  await chrome.action.onClicked.emit();
  await chrome.action.onClicked.emit();
  const newer = connections.at(-1);
  const newReady = newer.onMessage.emit({kind: "ready"});
  resolveAttach();
  await oldReady;
  await newReady;
  assert(badge === "ON", "stale attach must not detach newer session");
  print("PASS extension lifecycle, context forwarding, completion, cancel and reconnect");
})().catch(error => {
  failed = true;
  printerr(error.stack);
}).finally(() => loop.quit());
loop.run();
if (failed) imports.system.exit(1);
