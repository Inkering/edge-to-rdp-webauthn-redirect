"use strict";

const api = chrome.webAuthenticationProxy;
let port = null;
let attached = false;
let generation = 0;
let attachmentQueue = Promise.resolve();
const pending = new Map();

function status(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

async function detach() {
  const error = await api.detach();
  if (error) throw new Error(error);
}

function serializeAttachment(operation) {
  const result = attachmentQueue.then(operation);
  attachmentQueue = result.catch(() => {});
  return result;
}

async function stop() {
  const current = ++generation;
  const old = port;
  port = null;
  pending.clear();
  if (old) old.disconnect();
  try {
    // Also detaches a proxy left attached across a service-worker restart.
    await serializeAttachment(detach);
  } catch (error) {
    console.error("WebAuthn detach failed:", error.message);
  }
  if (generation === current) {
    attached = false;
    status("OFF", "#666666");
  }
}

async function connect() {
  if (port) return;
  if (!api) {
    status("ERR", "#bb0000");
    console.error("This Edge build does not expose webAuthenticationProxy.");
    return;
  }
  const current = ++generation;
  status("...", "#996600");
  const connection = chrome.runtime.connectNative("org.local.xrdp_webauthn");
  port = connection;
  connection.onDisconnect.addListener(() => {
    const message = chrome.runtime.lastError?.message;
    if (message) console.error("Native bridge disconnected:", message);
    if (port === connection) void stop();
  });
  connection.onMessage.addListener(async (message) => {
    if (port !== connection || generation !== current) return;
    if (message.kind === "disconnected") {
      await stop();
      return;
    }
    if (message.kind === "ready") {
      try {
        await serializeAttachment(async () => {
          if (port !== connection || generation !== current) return;
          const error = await api.attach();
          if (error) throw new Error(error);
          if (port !== connection || generation !== current) await detach();
        });
        if (port !== connection || generation !== current) return;
        attached = true;
        status("ON", "#008800");
      } catch (error) {
        console.error("WebAuthn attach failed:", error.message);
        if (port !== connection || generation !== current) return;
        await stop();
        status("ERR", "#bb0000");
      }
      return;
    }
    const kind = pending.get(message.requestId);
    if (!kind) return; // Canceled requests must never be completed.
    pending.delete(message.requestId);
    try {
      if (kind === "isUvpaa") {
        if (message.error || typeof message.isUvpaa !== "boolean") {
          // There is no error field for IUVPAA. Detach instead of inventing
          // an authenticator capability response after transport failure.
          throw new Error("Redirected IUVPAA could not be determined");
        }
        await api.completeIsUvpaaRequest({
          requestId: message.requestId,
          isUvpaa: message.isUvpaa,
        });
      } else {
        const details = { requestId: message.requestId };
        if (message.error) {
          console.error("WebAuthn request rejected:",
            kind, message.error.name, message.error.message);
          details.error = message.error;
        } else details.responseJson = message.responseJson;
        if (kind === "create") await api.completeCreateRequest(details);
        else await api.completeGetRequest(details);
      }
    } catch (error) {
      console.error("WebAuthn completion failed:", error.message);
      await stop();
      status("ERR", "#bb0000");
    }
  });
}

function forward(kind, request) {
  pending.set(request.requestId, kind);
  try {
    if (!attached || !port) throw new Error("Native bridge is not attached");
    port.postMessage({
      kind,
      requestId: request.requestId,
      ...(kind === "isUvpaa" ? {} : {
        options: JSON.parse(request.requestDetailsJson),
      }),
    });
  } catch (error) {
    console.error("WebAuthn dispatch failed:", error.message);
    void stop();
    status("ERR", "#bb0000");
  }
}

// Register synchronously; no content scripts, tabs permission, or page bridge.
if (api) {
  api.onCreateRequest.addListener((request) => forward("create", request));
  api.onGetRequest.addListener((request) => forward("get", request));
  api.onIsUvpaaRequest.addListener((request) => forward("isUvpaa", request));
  api.onRequestCanceled.addListener((requestId) => {
    if (pending.delete(requestId) && port) {
      try {
        port.postMessage({ kind: "cancel", requestId });
      } catch (error) {
        console.error("WebAuthn cancellation dispatch failed:", error.message);
        void stop();
      }
    }
  });
  api.onRemoteSessionStateChange.addListener(() => void connect());
}
chrome.action.onClicked.addListener(() => {
  if (port) void stop();
  else void connect();
});
chrome.runtime.onStartup.addListener(() => void connect());
chrome.runtime.onInstalled.addListener(() => void connect());
