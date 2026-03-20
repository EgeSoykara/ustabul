(function () {
  const liveRoot = document.getElementById("customer-panel-live-root");
  if (!liveRoot) return;

  let partialUrl = liveRoot.dataset.partialUrl || "";
  const snapshotUrl = liveRoot.dataset.snapshotUrl || "";
  const pollMs = Number(liveRoot.dataset.pollMs || 8000);
  let stateToken = liveRoot.dataset.stateToken || "";
  let refreshInFlight = false;
  let pendingRefresh = false;
  let queuedUrl = "";
  let queuedHistoryMode = "replace";
  let queuedShouldScroll = false;

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

  function buildFetchUrl(rawUrl) {
    const url = new URL(rawUrl || partialUrl || window.location.href, window.location.origin);
    url.searchParams.set("partial", "panel");
    url.hash = "";
    return url.toString();
  }

  function buildBrowserUrl(rawUrl) {
    const url = new URL(rawUrl || window.location.href, window.location.origin);
    url.searchParams.delete("partial");
    return url;
  }

  function syncHistory(rawUrl, mode) {
    if (!mode) return;
    const nextUrl = buildBrowserUrl(rawUrl);
    const historyUrl = nextUrl.pathname + nextUrl.search + nextUrl.hash;
    if (mode === "push") {
      window.history.pushState({ panel: "customer" }, "", historyUrl);
      return;
    }
    window.history.replaceState({ panel: "customer" }, "", historyUrl);
  }

  function scrollToHash(rawUrl) {
    const nextUrl = buildBrowserUrl(rawUrl);
    if (!nextUrl.hash) return;
    window.requestAnimationFrame(function () {
      const target = document.querySelector(nextUrl.hash);
      if (target) {
        target.scrollIntoView({ block: "start", behavior: "smooth" });
      }
    });
  }

  function buildUrlFromForm(form) {
    const url = new URL(form.getAttribute("action") || window.location.href, window.location.origin);
    url.search = "";

    const formData = new FormData(form);
    formData.forEach(function (value, key) {
      if (value === null || value === undefined || value === "") return;
      url.searchParams.append(key, value);
    });

    return url.toString();
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
          submitButton.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>Seciliyor...';
        } else {
          submitButton.textContent = "Secim kilitlendi";
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

  async function fetchPanel(rawUrl, options) {
    const force = options && options.force === true;
    const historyMode =
      options && Object.prototype.hasOwnProperty.call(options, "historyMode")
        ? options.historyMode
        : "replace";
    const shouldScroll = Boolean(options && options.scrollToHash);
    const targetUrl = rawUrl || partialUrl || window.location.href;
    if (!targetUrl) return;

    if (refreshInFlight || (!force && hasActiveEditor())) {
      pendingRefresh = true;
      queuedUrl = targetUrl;
      queuedHistoryMode = historyMode || "replace";
      queuedShouldScroll = shouldScroll;
      return;
    }

    refreshInFlight = true;
    try {
      const response = await fetch(buildFetchUrl(targetUrl), {
        method: "GET",
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
        cache: "no-store",
      });
      if (response.status === 401 || response.status === 403) {
        window.location.assign(buildBrowserUrl(targetUrl).toString());
        return;
      }
      if (!response.ok) return;

      const payload = await response.json();
      if (!payload || typeof payload.html !== "string") return;

      liveRoot.innerHTML = payload.html;
      initCustomerPanel(liveRoot);
      partialUrl = buildFetchUrl(targetUrl);

      if (payload.snapshot) {
        stateToken = buildToken(payload.snapshot);
      }

      if (historyMode) {
        syncHistory(targetUrl, historyMode);
      }
      if (shouldScroll) {
        scrollToHash(targetUrl);
      }
    } catch (error) {
      void error;
    } finally {
      refreshInFlight = false;
      if (pendingRefresh && !hasActiveEditor()) {
        const nextUrl = queuedUrl || partialUrl;
        const nextHistoryMode = queuedHistoryMode;
        const nextShouldScroll = queuedShouldScroll;
        pendingRefresh = false;
        queuedUrl = "";
        queuedHistoryMode = "replace";
        queuedShouldScroll = false;
        fetchPanel(nextUrl, {
          historyMode: nextHistoryMode,
          scrollToHash: nextShouldScroll,
        });
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
          queuedUrl = partialUrl;
          queuedHistoryMode = null;
          queuedShouldScroll = false;
        } else {
          fetchPanel(partialUrl, { historyMode: null });
        }
        return;
      }
      stateToken = nextToken;
    } catch (error) {
      void error;
    }
  }

  liveRoot.addEventListener("submit", function (event) {
    const form = event.target.closest("form[data-panel-filter-form]");
    if (!form) return;
    event.preventDefault();
    fetchPanel(buildUrlFromForm(form), {
      historyMode: "push",
      force: true,
      scrollToHash: false,
    });
  });

  liveRoot.addEventListener("click", function (event) {
    const link = event.target.closest("a[data-panel-nav]");
    if (!link) return;
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey
    ) {
      return;
    }
    event.preventDefault();
    fetchPanel(link.href, {
      historyMode: "push",
      force: true,
      scrollToHash: true,
    });
  });

  document.addEventListener("focusout", function () {
    window.setTimeout(function () {
      if (pendingRefresh && !hasActiveEditor()) {
        const nextUrl = queuedUrl || partialUrl;
        const nextHistoryMode = queuedHistoryMode;
        const nextShouldScroll = queuedShouldScroll;
        pendingRefresh = false;
        queuedUrl = "";
        queuedHistoryMode = "replace";
        queuedShouldScroll = false;
        fetchPanel(nextUrl, {
          historyMode: nextHistoryMode,
          scrollToHash: nextShouldScroll,
        });
      }
    }, 0);
  });

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) {
      if (pendingRefresh && !hasActiveEditor()) {
        const nextUrl = queuedUrl || partialUrl;
        const nextHistoryMode = queuedHistoryMode;
        const nextShouldScroll = queuedShouldScroll;
        pendingRefresh = false;
        queuedUrl = "";
        queuedHistoryMode = "replace";
        queuedShouldScroll = false;
        fetchPanel(nextUrl, {
          historyMode: nextHistoryMode,
          scrollToHash: nextShouldScroll,
        });
      } else {
        pollSnapshot();
      }
    }
  });

  window.addEventListener("popstate", function () {
    fetchPanel(window.location.href, {
      historyMode: null,
      force: true,
      scrollToHash: true,
    });
  });

  initCustomerPanel(liveRoot);
  pollSnapshot();
  window.setInterval(pollSnapshot, pollMs);
})();
