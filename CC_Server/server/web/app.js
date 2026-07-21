"use strict";

// ---------------------------------------------------------------------------
// Transport-security handling. The server tells us the mode via /api/security.
//   tls -> plain fetch over https (TLS 1.3 encrypts the wire); the only mode
//          implemented today. A future app-layer mode would add its own
//          handshake + envelope logic here, gated on `mode`.
// ---------------------------------------------------------------------------
let mode = "unknown";

// --- transport-agnostic API calls -----------------------------------------
async function apiGet(path) {
  return (await fetch(path)).json();
}

async function apiPost(path, obj) {
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
  el.textContent = mode === "tls" ? "channel: TLS 1.3" : "channel: unknown";
}

async function init() {
  // /api/security is always cleartext, so plain fetch.
  const sec = await (await fetch("/api/security")).json();
  mode = sec.mode;
  setSecBadge();

  const devs = await apiGet("/api/devices");
  const sel = $("device");
  (devs.devices || []).forEach((d) => {
    const o = document.createElement("option");
    o.value = d.device_id;
    o.textContent = d.device_id + (d.attested ? " ✓" : "");
    sel.appendChild(o);
  });

  $("collect").addEventListener("click", onCollect);
  $("device").addEventListener("change", applyLiveParams);
  $("window").addEventListener("change", applyLiveParams);
  $("aggregation").addEventListener("change", applyLiveParams);
  openLiveSocket();
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

  const noteEl = $("verdictNote");
  noteEl.textContent = r.note || "";
  noteEl.className = "verdictNote " + (r.attested ? "muted" : "bad");

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

// --- Live feed (WebSocket): repeats /api/collect on a timer over one socket -
let liveSocket = null;
let liveReconnectTimer = null;
let liveReconnectDelayMs = 1000;
const LIVE_RECONNECT_MAX_MS = 5000;

function liveWsUrl() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams({
    device_id: $("device").value,
    window: $("window").value,
    aggregation: $("aggregation").value,
  });
  return `${proto}//${location.host}/ws/collect?${params.toString()}`;
}

function setLiveBadge(state) {
  const el = $("livebadge");
  if (!el) return;
  el.className = "livebadge " + state;
  el.textContent =
    state === "live" ? "● live" :
    state === "connecting" ? "● connecting…" :
    state === "error" ? "● error (see status)" :
    "● offline";
}

function openLiveSocket() {
  if (liveReconnectTimer) {
    clearTimeout(liveReconnectTimer);
    liveReconnectTimer = null;
  }
  setLiveBadge("connecting");

  const ws = new WebSocket(liveWsUrl());
  liveSocket = ws;

  ws.addEventListener("open", () => {
    if (ws !== liveSocket) return;
    liveReconnectDelayMs = 1000;
    setLiveBadge("live");
  });

  ws.addEventListener("message", (ev) => {
    if (ws !== liveSocket) return;
    let r;
    try {
      r = JSON.parse(ev.data);
    } catch (e) {
      // Malformed frame (e.g. non-finite number from a bad sample) - the
      // connection is still alive, just skip this tick rather than crash.
      setLiveBadge("error");
      $("status").textContent = "live feed: bad frame (" + e + ")";
      return;
    }
    if (r.error) {
      // Server kept the socket alive but this tick failed - not a
      // disconnect, so don't claim "offline".
      setLiveBadge("error");
      $("status").textContent = "live feed: " + r.error;
      return;
    }
    setLiveBadge("live");
    renderResult(r);
  });

  ws.addEventListener("close", () => {
    // A newer socket (param change) already superseded this one - nothing to do.
    if (ws !== liveSocket) return;
    setLiveBadge("offline");
    liveReconnectTimer = setTimeout(openLiveSocket, liveReconnectDelayMs);
    liveReconnectDelayMs = Math.min(liveReconnectDelayMs * 2, LIVE_RECONNECT_MAX_MS);
  });

  ws.addEventListener("error", () => ws.close());
}

function applyLiveParams() {
  if (liveSocket) liveSocket.close();
  openLiveSocket();
}

init().catch((e) => {
  $("status").textContent = "init failed: " + e;
});
