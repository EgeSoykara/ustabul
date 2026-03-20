(function () {
  const liveRoot = document.getElementById("provider-panel-live-root");
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
      Number(payload.pending_offers_count || 0),
      Number(payload.latest_pending_offer_id || 0),
      Number(payload.waiting_customer_selection_count || 0),
      Number(payload.pending_appointments_count || 0),
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
      window.history.pushState({ panel: "provider" }, "", historyUrl);
      return;
    }
    window.history.replaceState({ panel: "provider" }, "", historyUrl);
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

  pollSnapshot();
  window.setInterval(pollSnapshot, pollMs);
})();
