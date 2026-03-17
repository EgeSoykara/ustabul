(function () {
  const body = document.body;
  if (!body) return;

  const isAuthenticated = body.dataset.authenticated === "1";
  if (!isAuthenticated) return;

  const isProvider = body.dataset.role === "provider";
  const snapshotUrl = body.dataset.navSnapshotUrl || "";
  const notificationsCountUrl = body.dataset.notificationsCountUrl || "";
  const panelPath = body.dataset.panelPath || "";
  const pollMs = Number(body.dataset.navPollMs || 15000);
  const badgeCountKey = body.dataset.navBadgeKey || (isProvider ? "ustabul_provider_unseen_count" : "ustabul_customer_unseen_count");
  const snapshotKey = body.dataset.navSnapshotKey || (isProvider ? "ustabul_provider_last_snapshot" : "ustabul_customer_last_snapshot");
  const navSelector = isProvider ? "[data-live-provider-nav]" : "[data-live-customer-nav]";
  const notificationSelector = "[data-live-notification-nav]";
  const currentPath = window.location.pathname || "";
  const isPanelPage = Boolean(panelPath) && currentPath === panelPath;

  function renderBadge(selector, count) {
    const targets = document.querySelectorAll(selector);
    if (!targets.length) return;
    targets.forEach(function (target) {
      let badge = target.querySelector(".nav-live-badge");
      if (!count) {
        if (badge) badge.remove();
        return;
      }
      if (!badge) {
        badge = document.createElement("span");
        badge.className = "nav-live-badge";
        target.appendChild(badge);
      }
      badge.textContent = count > 99 ? "99+" : String(count);
    });
  }

  function renderNavBadge(count) {
    renderBadge(navSelector, count);
  }

  function renderNotificationBadge(count) {
    renderBadge(notificationSelector, count);
  }

  function readNumber(key) {
    try {
      const raw = Number(localStorage.getItem(key) || 0);
      return Number.isFinite(raw) && raw > 0 ? raw : 0;
    } catch (error) {
      void error;
      return 0;
    }
  }

  function writeNumber(key, value) {
    const safeValue = Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
    try {
      localStorage.setItem(key, String(safeValue));
    } catch (error) {
      void error;
    }
    return safeValue;
  }

  function readSnapshot() {
    try {
      const raw = localStorage.getItem(snapshotKey);
      if (!raw) return null;
      return JSON.parse(raw);
    } catch (error) {
      void error;
      return null;
    }
  }

  function writeSnapshot(snapshot) {
    try {
      localStorage.setItem(snapshotKey, JSON.stringify(snapshot));
    } catch (error) {
      void error;
    }
  }

  function buildProviderSnapshot(payload) {
    return {
      pendingOffersCount: Number(payload.pending_offers_count || 0),
      latestPendingOfferId: Number(payload.latest_pending_offer_id || 0),
      pendingAppointmentsCount: Number(payload.pending_appointments_count || 0),
      unreadMessagesCount: Number(payload.unread_messages_count || 0),
    };
  }

  function buildCustomerSnapshot(payload) {
    return {
      acceptedOffersCount: Number(payload.accepted_offers_count || 0),
      pendingCustomerAppointmentsCount: Number(payload.pending_customer_appointments_count || 0),
      confirmedAppointmentsCount: Number(payload.confirmed_appointments_count || 0),
      unreadMessagesCount: Number(payload.unread_messages_count || 0),
      pendingCustomerRequestsCount: Number(payload.pending_customer_requests_count || 0),
      matchedRequestsCount: Number(payload.matched_requests_count || 0),
      signature: String(payload.signature || ""),
    };
  }

  function getProviderIncrement(previous, nextState) {
    if (!previous) return 0;
    let increment = 0;
    if (nextState.pendingOffersCount > (previous.pendingOffersCount || 0)) {
      increment += nextState.pendingOffersCount - (previous.pendingOffersCount || 0);
    } else if (
      nextState.latestPendingOfferId > (previous.latestPendingOfferId || 0) &&
      nextState.pendingOffersCount >= (previous.pendingOffersCount || 0)
    ) {
      increment += 1;
    }
    if (nextState.pendingAppointmentsCount > (previous.pendingAppointmentsCount || 0)) {
      increment += nextState.pendingAppointmentsCount - (previous.pendingAppointmentsCount || 0);
    }
    if (nextState.unreadMessagesCount > (previous.unreadMessagesCount || 0)) {
      increment += nextState.unreadMessagesCount - (previous.unreadMessagesCount || 0);
    }
    return increment;
  }

  function getCustomerIncrement(previous, nextState) {
    if (!previous) return 0;
    let increment = 0;
    if (nextState.acceptedOffersCount > (previous.acceptedOffersCount || 0)) {
      increment += nextState.acceptedOffersCount - (previous.acceptedOffersCount || 0);
    }
    if (nextState.pendingCustomerRequestsCount > (previous.pendingCustomerRequestsCount || 0)) {
      increment += nextState.pendingCustomerRequestsCount - (previous.pendingCustomerRequestsCount || 0);
    }
    if (nextState.pendingCustomerAppointmentsCount > (previous.pendingCustomerAppointmentsCount || 0)) {
      increment += nextState.pendingCustomerAppointmentsCount - (previous.pendingCustomerAppointmentsCount || 0);
    }
    if (nextState.confirmedAppointmentsCount > (previous.confirmedAppointmentsCount || 0)) {
      increment += nextState.confirmedAppointmentsCount - (previous.confirmedAppointmentsCount || 0);
    }
    if (nextState.unreadMessagesCount > (previous.unreadMessagesCount || 0)) {
      increment += nextState.unreadMessagesCount - (previous.unreadMessagesCount || 0);
    }
    if (nextState.matchedRequestsCount > (previous.matchedRequestsCount || 0)) {
      increment += nextState.matchedRequestsCount - (previous.matchedRequestsCount || 0);
    }
    if (!increment && nextState.signature !== (previous.signature || "")) {
      increment = 1;
    }
    return increment;
  }

  function setNavBadgeCount(count) {
    renderNavBadge(writeNumber(badgeCountKey, count));
  }

  function applySnapshotPayload(payload) {
    const previousSnapshot = readSnapshot();
    const nextSnapshot = isProvider ? buildProviderSnapshot(payload) : buildCustomerSnapshot(payload);
    const increment = isProvider
      ? getProviderIncrement(previousSnapshot, nextSnapshot)
      : getCustomerIncrement(previousSnapshot, nextSnapshot);
    const unreadNotificationsCount = Number(payload.unread_notifications_count || 0);

    if (isPanelPage) {
      setNavBadgeCount(0);
    } else if (increment > 0) {
      setNavBadgeCount(readNumber(badgeCountKey) + increment);
    }

    if (Number.isFinite(unreadNotificationsCount) && unreadNotificationsCount >= 0) {
      renderNotificationBadge(unreadNotificationsCount);
    }
    writeSnapshot(nextSnapshot);
  }

  async function pollSnapshot() {
    if (document.hidden || isPanelPage || !snapshotUrl) return;
    try {
      const response = await fetch(snapshotUrl, {
        method: "GET",
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
        cache: "no-store",
      });
      if (!response.ok) return;
      const payload = await response.json();
      applySnapshotPayload(payload);
    } catch (error) {
      void error;
    }
  }

  async function syncNotificationBadge() {
    if (document.hidden || !notificationsCountUrl) return;
    try {
      const response = await fetch(notificationsCountUrl, {
        method: "GET",
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
        cache: "no-store",
      });
      if (!response.ok) return;
      const payload = await response.json();
      const unreadCount = Number(payload.unread_notifications_count || 0);
      if (Number.isFinite(unreadCount) && unreadCount >= 0) {
        renderNotificationBadge(unreadCount);
      }
    } catch (error) {
      void error;
    }
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    if (isPanelPage) {
      syncNotificationBadge();
    } else {
      pollSnapshot();
    }
  });

  window.addEventListener("ustabul:notifications-read", function (event) {
    const unreadCount = Number(event && event.detail ? event.detail.unreadCount : NaN);
    if (Number.isFinite(unreadCount) && unreadCount >= 0) {
      renderNotificationBadge(unreadCount);
      return;
    }
    syncNotificationBadge();
  });

  renderNavBadge(readNumber(badgeCountKey));
  if (isPanelPage) {
    setNavBadgeCount(0);
    syncNotificationBadge();
    window.setInterval(syncNotificationBadge, pollMs);
    return;
  }

  pollSnapshot();
  window.setInterval(pollSnapshot, pollMs);
})();
