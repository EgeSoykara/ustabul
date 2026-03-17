(function () {
  const liveRoot = document.getElementById("provider-panel-live-root");
  if (!liveRoot) return;

  const partialUrl = liveRoot.dataset.partialUrl || "";
  const snapshotUrl = liveRoot.dataset.snapshotUrl || "";
  const pollMs = Number(liveRoot.dataset.pollMs || 8000);
  let stateToken = liveRoot.dataset.stateToken || "";
  let refreshInFlight = false;
  let pendingRefresh = false;

  function hasActiveEditor() {
    const active = document.activeElement;
    if (!active || !liveRoot.contains(active)) return false;
    return ["INPUT", "TEXTAREA", "SELECT"].indexOf(active.tagName) >= 0;
  }

  function buildToken(payload) {
    if (!payload || typeof payload !== "object") return "";
    return [
      String(payload.signature || ""),
      Number(payload.pending_offers_count || 0),
      Number(payload.latest_pending_offer_id || 0),
      Number(payload.waiting_customer_selection_count || 0),
      Number(payload.pending_appointments_count || 0),
      Number(payload.unread_messages_count || 0),
    ].join("|");
  }

  async function refreshPanel() {
    if (!partialUrl || refreshInFlight || hasActiveEditor()) {
      pendingRefresh = true;
      return;
    }

    refreshInFlight = true;
    try {
      const response = await fetch(partialUrl, {
        method: "GET",
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
        cache: "no-store",
      });
      if (response.status === 401 || response.status === 403) {
        window.location.reload();
        return;
      }
      if (!response.ok) return;
      const payload = await response.json();
      if (!payload || typeof payload.html !== "string") return;
      liveRoot.innerHTML = payload.html;
      if (payload.snapshot) {
        stateToken = buildToken(payload.snapshot);
      }
    } catch (error) {
      void error;
    } finally {
      refreshInFlight = false;
      if (pendingRefresh && !hasActiveEditor()) {
        pendingRefresh = false;
        refreshPanel();
      }
    }
  }

  async function pollSnapshot() {
    if (document.hidden || refreshInFlight || !snapshotUrl) return;
    try {
      const response = await fetch(snapshotUrl, {
        method: "GET",
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
        cache: "no-store",
      });
      if (!response.ok) return;
      const payload = await response.json();
      const nextToken = buildToken(payload);
      if (!nextToken) return;
      if (stateToken && nextToken !== stateToken) {
        if (hasActiveEditor()) {
          pendingRefresh = true;
        } else {
          refreshPanel();
        }
        return;
      }
      stateToken = nextToken;
    } catch (error) {
      void error;
    }
  }

  document.addEventListener("focusout", function () {
    window.setTimeout(function () {
      if (pendingRefresh && !hasActiveEditor()) {
        pendingRefresh = false;
        refreshPanel();
      }
    }, 0);
  });

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      if (pendingRefresh && !hasActiveEditor()) {
        pendingRefresh = false;
        refreshPanel();
      } else {
        pollSnapshot();
      }
    }
  });

  pollSnapshot();
  window.setInterval(pollSnapshot, pollMs);
})();
