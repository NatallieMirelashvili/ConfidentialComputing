"use strict";

// ---------------------------------------------------------------------------
// Transport-security handling. The server tells us the mode via /api/security.
//   tls    -> plain fetch over https (TLS 1.3 encrypts the wire)
//   aesgcm -> ECDH handshake, then every secure call is an {iv, ct} envelope
// These parameters MUST match server/transport/aesgcm.py + constants.py.
// ---------------------------------------------------------------------------
const HKDF_INFO = "CC-IOT-1 user-aead";

let mode = "unknown";
let sessionId = null;
let aesKey = null; // CryptoKey for aesgcm mode

// --- base64 helpers --------------------------------------------------------
function b64e(bytes) {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}
function b64d(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// --- AES-GCM mode: ECDH handshake -----------------------------------------
async function handshake() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits", "deriveKey"]
  );
  const clientPub = new Uint8Array(
    await crypto.subtle.exportKey("raw", kp.publicKey)
  );

  const res = await fetch("/api/handshake", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_pub: b64e(clientPub) }),
  });
  const j = await res.json();
  sessionId = j.session_id;
  const serverPubRaw = b64d(j.server_pub);

  const serverPub = await crypto.subtle.importKey(
    "raw",
    serverPubRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPub },
    kp.privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveKey"]
  );
  aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: concat(clientPub, serverPubRaw), // order: client || server
      info: new TextEncoder().encode(HKDF_INFO),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function seal(plaintextStr) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      new TextEncoder().encode(plaintextStr)
    )
  );
  return { iv: b64e(iv), ct: b64e(ct) };
}

async function open(env) {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64d(env.iv) },
    aesKey,
    b64d(env.ct)
  );
  return new TextDecoder().decode(pt);
}

// --- transport-agnostic API calls -----------------------------------------
async function apiGet(path) {
  if (mode === "aesgcm") {
    const res = await fetch(path, { headers: { "X-Session-Id": sessionId } });
    return JSON.parse(await open(await res.json()));
  }
  return (await fetch(path)).json();
}

async function apiPost(path, obj) {
  if (mode === "aesgcm") {
    const env = await seal(JSON.stringify(obj));
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Session-Id": sessionId },
      body: JSON.stringify(env),
    });
    return JSON.parse(await open(await res.json()));
  }
  return (
    await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(obj),
    })
  ).json();
}

// --- UI --------------------------------------------------------------------
const $ = (id) => document.getElementById(id);

function setSecBadge() {
  const el = $("secbadge");
  el.className = "secbadge " + mode;
  el.textContent =
    mode === "tls"
      ? "channel: TLS 1.3"
      : mode === "aesgcm"
      ? "channel: AES-256-GCM (app-layer)"
      : "channel: unknown";
}

async function init() {
  // /api/security is always cleartext, so plain fetch.
  const sec = await (await fetch("/api/security")).json();
  mode = sec.mode;
  setSecBadge();
  if (mode === "aesgcm") await handshake();

  const devs = await apiGet("/api/devices");
  const sel = $("device");
  (devs.devices || []).forEach((d) => {
    const o = document.createElement("option");
    o.value = d.device_id;
    o.textContent = d.device_id + (d.attested ? " ✓" : "");
    sel.appendChild(o);
  });

  $("collect").addEventListener("click", onCollect);
}

async function onCollect() {
  const btn = $("collect");
  btn.disabled = true;
  $("status").textContent = "collecting…";
  try {
    const body = {
      device_id: $("device").value,
      window: $("window").value,
      aggregation: $("aggregation").value,
    };
    const r = await apiPost("/api/collect", body);
    renderResult(r);
    $("status").textContent = "done";
  } catch (e) {
    $("status").textContent = "error: " + e;
  } finally {
    btn.disabled = false;
  }
}

function chip(label, ok) {
  return `<span class="chip ${ok ? "ok" : "bad"}">${label}: ${ok ? "ok" : "fail"}</span>`;
}

function renderResult(r) {
  $("resultCard").classList.remove("hidden");
  $("raw").textContent = JSON.stringify(r, null, 2);

  $("verdicts").innerHTML =
    chip("attested", !!r.attested) +
    chip("integrity", r.integrity === "ok") +
    chip("measurement", !!r.measurement_ok);

  const res = r.result || {};
  let html;
  if (res.kind === "raw") {
    html = `<div>${res.n} samples</div><small>${res.series
      .slice(-6)
      .map((s) => s.value)
      .join(", ")} …</small>`;
  } else if (res.value == null) {
    html = `<div>—</div><small>${res.note || "no data"}</small>`;
  } else {
    html = `<div>${res.value}</div><small>${res.kind} over ${r.window} · ${r.n_samples} samples</small>`;
  }
  $("result").innerHTML = html;
}

init().catch((e) => {
  $("status").textContent = "init failed: " + e;
});
