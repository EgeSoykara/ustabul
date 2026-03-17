(function () {
  const liveRoot = document.getElementById("customer-panel-live-root");
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
      Number(payload.pending_customer_requests_count || 0),
      Number(payload.matched_requests_count || 0),
      Number(payload.pending_customer_appointments_count || 0),
      Number(payload.confirmed_appointments_count || 0),
      Number(payload.accepted_offers_count || 0),
      Number(payload.unread_messages_count || 0),
    ].join("|");
  }

  function lockOfferSelection(root) {
    const offerForms = root.querySelectorAll("form[data-offer-select-form]");
    if (!offerForms.length) return;
    let selectionLocked = false;

    function lockSelection(selectedForm) {
      offerForms.forEach(function (form) {
        const submitButton = form.querySelector("[data-offer-select-submit]");
        if (!submitButton) return;
        submitButton.disabled = true;
        if (form === selectedForm) {
          submitButton.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>Seçiliyor...';
        } else {
          submitButton.textContent = "Seçim kilitlendi";
        }
      });
    }

    offerForms.forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (selectionLocked) {
          event.preventDefault();
          return;
        }
        selectionLocked = true;
        lockSelection(form);
      });
    });
  }

  function toDateTimeLocalValue(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    const hours = String(date.getHours()).padStart(2, "0");
    const minutes = String(date.getMinutes()).padStart(2, "0");
    return year + "-" + month + "-" + day + "T" + hours + ":" + minutes;
  }

  function bindAppointmentQuickButtons(root) {
    const quickButtons = root.querySelectorAll("button[data-appointment-offset-minutes]");
    quickButtons.forEach(function (button) {
      button.addEventListener("click", function () {
        const form = button.closest("form");
        if (!form) return;
        const input = form.querySelector("input[name='scheduled_for']");
        if (!input) return;
        const offset = Number(button.getAttribute("data-appointment-offset-minutes") || 0);
        const targetDate = new Date(Date.now() + Math.max(0, offset) * 60 * 1000);
        input.value = toDateTimeLocalValue(targetDate);
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      });
    });
  }

  function initCustomerPanel(root) {
    lockOfferSelection(root);
    bindAppointmentQuickButtons(root);
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
      initCustomerPanel(liveRoot);
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

  initCustomerPanel(liveRoot);
  pollSnapshot();
  window.setInterval(pollSnapshot, pollMs);
})();
