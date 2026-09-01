/* TerDrop — Client-side JS */

// ── Theme ────────────────────────────────────────────────────────

const THEME_KEY = "td_theme";
const themes    = ["dark", "light", "eye"];

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme === "dark" ? "" : theme);
  document.querySelectorAll(".theme-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.theme === theme);
  });
  localStorage.setItem(THEME_KEY, theme);
}

function initTheme() {
  const saved = localStorage.getItem(THEME_KEY) || "dark";
  applyTheme(saved);
  document.querySelectorAll(".theme-btn").forEach(btn => {
    btn.addEventListener("click", () => applyTheme(btn.dataset.theme));
  });
}

// ── Mobile Sidebar ────────────────────────────────────────────────

function initSidebar() {
  const toggle  = document.getElementById("menuToggle");
  const sidebar  = document.getElementById("sidebar");
  const overlay  = document.getElementById("sidebarOverlay");
  if (!toggle || !sidebar) return;

  function open()  { sidebar.classList.add("open");  overlay?.classList.add("show"); }
  function close() { sidebar.classList.remove("open"); overlay?.classList.remove("show"); }

  toggle.addEventListener("click", () =>
    sidebar.classList.contains("open") ? close() : open()
  );
  overlay?.addEventListener("click", close);
}

// ── Chat auto-poll ─────────────────────────────────────────────────

let _chatLast = 0;
let _chatTimer = null;

function initChat(pollUrl, currentRole) {
  const container = document.getElementById("chatMessages");
  if (!container) return;

  // Set last timestamp from existing messages
  const msgs = container.querySelectorAll("[data-ts]");
  msgs.forEach(m => {
    const ts = parseFloat(m.dataset.ts || "0");
    if (ts > _chatLast) _chatLast = ts;
  });

  scrollChat();

  _chatTimer = setInterval(async () => {
    try {
      const res = await fetch(`${pollUrl}?since=${_chatLast}`);
      if (!res.ok) return;
      const newMsgs = await res.json();
      newMsgs.forEach(m => {
        if (m.timestamp > _chatLast) {
          _chatLast = m.timestamp;
          appendMsg(m, currentRole, container);
        }
      });
      if (newMsgs.length) scrollChat();
    } catch (_) {}
  }, 3000);
}

function appendMsg(m, myRole, container) {
  const isMe = m.sender_role === myRole;  const div = document.createElement("div");
  div.className = `chat-msg ${isMe ? "from-me" : "from-other"} fade-in`;
  div.dataset.ts = m.timestamp;
  const time = new Date(m.timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  div.innerHTML = `
    <div class="chat-bubble">${escapeHtml(m.content)}</div>
    <div class="chat-meta">${isMe ? "You" : (myRole === "admin" ? "User" : "Admin")} · ${time}</div>
  `;
  container.appendChild(div);
}

function scrollChat() {
  const c = document.getElementById("chatMessages");
  if (c) c.scrollTop = c.scrollHeight;
}

function escapeHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

// ── Notification helper ──────────────────────────────────────────────
// `new Notification()` throws "Illegal constructor" on virtually all
// mobile browsers (Chrome/Android included) — the only reliable way to
// show a notification there is via the service worker. This helper
// always prefers that path, with a same-tab fallback only for the rare
// case a service worker genuinely isn't available.
async function showNotification(title, body, tag) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;

  try {
    if ("serviceWorker" in navigator) {
      const reg = await navigator.serviceWorker.ready;
      if (reg.active) {
        reg.active.postMessage({ type: "SHOW_NOTIFICATION", title, body, tag });
        return;
      }
    }
  } catch (_) {
    // fall through to the constructor fallback below
  }

  try {
    new Notification(title, { body });
  } catch (_) {
    // Illegal constructor on this browser and no service worker available —
    // nothing more we can do; fail silently rather than throw.
  }
}

// ── Global background notification poller ───────────────────────────
// Runs on EVERY page (not just /chat) so the user gets notified of a
// new reply even while browsing Dashboard, Downloads, etc. Fires a
// real browser Notification (works even backgrounded/minimized) if the
// user has granted permission via Settings.

function initGlobalNotifier(pollUrl, myRole) {
  if (!pollUrl || !("Notification" in window)) return;

  const STORAGE_KEY = "td_notif_last_seen";
  let lastSeen = parseFloat(localStorage.getItem(STORAGE_KEY) || "0");

  async function poll() {
    if (Notification.permission !== "granted") return;
    // Don't double-notify for messages already rendered by the open chat page
    const onChatPage = !!document.getElementById("chatMessages");

    try {
      const res = await fetch(`${pollUrl}?since=${lastSeen}`);
      if (!res.ok) return;
      const msgs = await res.json();
      msgs.forEach(m => {
        if (m.timestamp > lastSeen) {
          lastSeen = m.timestamp;
          // Only notify for messages from the OTHER party, and skip if
          // the chat page is already open and visible (avoid noise).
          if (m.sender_role !== myRole && !(onChatPage && document.hasFocus())) {
            const title = myRole === "admin" ? "💬 New message" : "💬 Admin replied";
            showNotification(title, m.content.slice(0, 120), "td-chat");
          }
        }
      });
      if (msgs.length) localStorage.setItem(STORAGE_KEY, String(lastSeen));
    } catch (_) {}
  }

  poll();
  setInterval(poll, 5000);
}

// ── Tunnel control ─────────────────────────────────────────────────

function initTunnel() {
  const startBtn   = document.getElementById("tunnelStart");
  const stopBtn    = document.getElementById("tunnelStop");
  const restartBtn = document.getElementById("tunnelRestart");
  const statusDot  = document.getElementById("tunnelDot");
  const urlDisplay = document.getElementById("tunnelUrl");
  const logBox     = document.getElementById("tunnelLog");
  const qrContainer = document.getElementById("qrcode");
  // Extra elements present only on the dedicated /tunnel page — optional
  // everywhere else, so every lookup below is null-safe.
  const liveBadge  = document.getElementById("liveBadge");
  const liveUrl    = document.getElementById("liveUrl");
  const lastPoll   = document.getElementById("lastPoll");

  if (!startBtn && !stopBtn && !restartBtn && !qrContainer) return; // nothing on this page needs tunnel wiring

  let lastQrUrl = null;

  function updateQr(url) {
    if (!qrContainer || typeof QRCode === "undefined") return;
    if (lastQrUrl === url) return;  // avoid needless regeneration
    lastQrUrl = url;

    qrContainer.innerHTML = "";
    if (!url) {
      qrContainer.innerHTML = '<span class="text-sm" style="color:#999">No active link</span>';
      return;
    }
    new QRCode(qrContainer, {
      text: url,
      width: 140,
      height: 140,
      colorDark: "#0d0f14",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.M,
    });
  }

  async function tunnelAction(action) {
    [startBtn, stopBtn, restartBtn].forEach(b => b && (b.disabled = true));
    if (action === "restart" && urlDisplay) urlDisplay.textContent = "Reconnecting… please wait";

    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
    const res = await fetch(`/tunnel/${action}`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken },
    });
    const data = await res.json();
    updateTunnelUI(data.status);

    if (action === "restart") {
      let tries = 0;
      const poll = setInterval(async () => {
        const s = await pollTunnelStatus();
        if (s?.url || ++tries > 30) clearInterval(poll);
      }, 1000);
    }
  }

  function updateTunnelUI(status) {
    const running = status?.running;
    const url     = status?.url;

    if (statusDot) statusDot.className = `dot ${running ? "dot-green pulse" : "dot-red"}`;
    if (urlDisplay) {
      urlDisplay.textContent = url || (running ? "Waiting for URL…" : "Tunnel not running");
    }
    if (liveBadge) {
      liveBadge.textContent = running ? "🟢 Running" : "🔴 Stopped";
      liveBadge.className = `badge ${running ? "badge-success" : "badge-danger"}`;
    }
    if (liveUrl) liveUrl.textContent = url || "—";
    if (lastPoll) lastPoll.textContent = "Updated " + new Date().toLocaleTimeString();

    if (startBtn)   startBtn.disabled   = !!running;
    if (stopBtn)    stopBtn.disabled    = !running;
    if (restartBtn) restartBtn.disabled = false;

    updateQr(running ? url : null);
  }

  async function pollTunnelStatus() {
    try {
      const res = await fetch("/tunnel/status");
      const data = await res.json();
      updateTunnelUI(data);
      return data;
    } catch (_) { return null; }
  }

  startBtn  ?.addEventListener("click", () => tunnelAction("start"));
  stopBtn   ?.addEventListener("click", () => tunnelAction("stop"));
  restartBtn?.addEventListener("click", () => tunnelAction("restart"));

  // Initialize QR from whatever the page already knows (server-rendered
  // state via a data attribute) before the first poll lands.
  if (qrContainer) {
    updateQr(qrContainer.dataset.initialUrl || null);
  }

  // Poll every 5s
  setInterval(pollTunnelStatus, 5000);
}

// ── Copy to clipboard ──────────────────────────────────────────────

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "✓ Copied";
    setTimeout(() => { btn.textContent = orig; }, 1500);
  });
}

// ── Confirm dialogs ────────────────────────────────────────────────

function confirmAction(msg, form) {
  if (confirm(msg)) form.submit();
}

// ── Toast notifications ────────────────────────────────────────────

function showToast(msg, type = "info") {
  const wrap = document.getElementById("toastWrap") || (() => {
    const d = document.createElement("div");
    d.id = "toastWrap";
    d.style.cssText = "position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;";
    document.body.appendChild(d);
    return d;
  })();

  const t = document.createElement("div");
  t.className = `alert alert-${type} fade-in`;
  t.style.cssText = "min-width:220px;max-width:340px;box-shadow:var(--shadow-lg);";
  t.textContent = msg;
  wrap.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Init ───────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initSidebar();
  initTunnel();

  // Register PWA service worker (enables "Add to Home Screen" install prompt)
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/static/sw.js").catch(() => {});
  }

  // Global chat notifier — reads config from <body data-...> if present
  // (only rendered when the user is logged in; see base.html)
  const pollUrl = document.body.dataset.chatPollUrl;
  const myRole  = document.body.dataset.userRole;
  if (pollUrl && myRole) initGlobalNotifier(pollUrl, myRole);

  // Auto-dismiss alerts
  document.querySelectorAll(".alert[data-autodismiss]").forEach(a => {
    setTimeout(() => a.remove(), 4000);
  });
});
