(function () {
  const thread = document.getElementById("chat-thread");
  const form = document.getElementById("chat-message-form");
  if (!thread || !form) return;

  const requestId = Number(thread.dataset.requestId || 0);
  const viewerRole = thread.dataset.viewerRole || "";
  const snapshotUrl = thread.dataset.snapshotUrl || "";
  const emptyState = document.getElementById("chat-empty-state");
  const statusBox = document.getElementById("chat-form-status");
  const connectionStatusBox = document.getElementById("chat-connection-status");
  const retryButton = document.getElementById("chat-form-retry");
  const textarea = form.querySelector("textarea[name='body']");
  const submitButton = form.querySelector("button[type='submit']");
  const realtimeEnabled = thread.dataset.realtimeEnabled === "1";
  const wsSupported = realtimeEnabled && typeof window.WebSocket !== "undefined";

  let latestId = Number(thread.dataset.latestId || 0);
  let sending = false;
  let pollingStopped = false;
  let socket = null;
  let reconnectTimer = null;
  let pingTimer = null;
  let pollTimer = null;
  let pollInFlight = false;
  let websocketHealthy = false;
  let websocketOpenedAtLeastOnce = false;
  let websocketReconnectCount = 0;
  let retryBodyText = "";

  const fallbackPollIntervalMs = Number(thread.dataset.fallbackPollMs || 5000);
  const reconnectDelayMs = 3000;
  const reconnectFallbackDelayMs = 15000;
  const pingIntervalMs = 25000;

  function buildSnapshotUrl(afterId) {
    if (!snapshotUrl) return "";
    const joiner = snapshotUrl.indexOf("?") >= 0 ? "&" : "?";
    return snapshotUrl + joiner + "after_id=" + encodeURIComponent(afterId || 0);
  }

  function buildWebSocketUrl() {
    if (!requestId) return "";
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return wsProtocol + "//" + window.location.host + "/ws/talep/" + requestId + "/mesajlar/";
  }

  function setStatus(text, isError) {
    if (!statusBox) return;
    if (!text) {
      statusBox.classList.add("d-none");
      statusBox.textContent = "";
      statusBox.classList.remove("text-danger", "text-success", "text-muted");
      return;
    }
    statusBox.textContent = text;
    statusBox.classList.remove("d-none", "text-danger", "text-success", "text-muted");
    if (isError === true) {
      statusBox.classList.add("text-danger");
    } else if (isError === false) {
      statusBox.classList.add("text-success");
    } else {
      statusBox.classList.add("text-muted");
    }
  }

  function setConnectionStatus(text, tone) {
    if (!connectionStatusBox) return;
    if (!text) {
      connectionStatusBox.classList.add("d-none");
      connectionStatusBox.textContent = "";
      connectionStatusBox.classList.remove("is-warning", "is-success");
      return;
    }
    connectionStatusBox.textContent = text;
    connectionStatusBox.classList.remove("d-none", "is-warning", "is-success");
    if (tone === "success") {
      connectionStatusBox.classList.add("is-success");
    } else {
      connectionStatusBox.classList.add("is-warning");
    }
  }

  function setRetryVisible(isVisible, bodyText) {
    retryBodyText = isVisible ? String(bodyText || "") : "";
    if (!retryButton) return;
    retryButton.classList.toggle("d-none", !isVisible);
    retryButton.disabled = !isVisible || pollingStopped || sending;
  }

  function updateSubmitState() {
    if (retryButton && !retryButton.classList.contains("d-none")) {
      retryButton.disabled = pollingStopped || sending;
    }
    if (!submitButton || !textarea) return;
    if (pollingStopped || textarea.disabled || sending) {
      submitButton.disabled = true;
      return;
    }
    submitButton.disabled = String(textarea.value || "").trim().length < 2;
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function bodyToHtml(text) {
    return escapeHtml(text).replace(/\n/g, "<br>");
  }

  function isNearBottom() {
    return thread.scrollHeight - thread.scrollTop - thread.clientHeight < 96;
  }

  function scrollToBottom() {
    thread.scrollTop = thread.scrollHeight;
  }

  function renderMessageItem(message) {
    const article = document.createElement("article");
    article.className = "chat-bubble " + (message.mine ? "mine" : "theirs");
    article.setAttribute("data-message-id", String(message.id));
    article.innerHTML =
      '<div class="chat-meta">' +
      "<strong>" + escapeHtml(message.sender_label) + "</strong>" +
      "<span>" + escapeHtml(message.created_at) + "</span>" +
      "</div>" +
      '<p class="mb-0">' + bodyToHtml(message.body) + "</p>";
    return article;
  }

  function appendMessages(messages, forceScroll) {
    if (!Array.isArray(messages) || !messages.length) return;
    const shouldStickBottom = forceScroll || isNearBottom();

    messages.forEach(function (message) {
      const messageId = Number(message.id || 0);
      if (!messageId) return;
      if (thread.querySelector('[data-message-id="' + messageId + '"]')) return;
      const normalizedMessage = Object.assign({}, message);
      if (normalizedMessage.mine === undefined) {
        normalizedMessage.mine = normalizedMessage.sender_role === viewerRole;
      }
      thread.appendChild(renderMessageItem(normalizedMessage));
      if (messageId > latestId) latestId = messageId;
    });

    if (emptyState && thread.querySelector("[data-message-id]")) {
      emptyState.hidden = true;
    }
    if (shouldStickBottom) {
      scrollToBottom();
    }
  }

  function stopPing() {
    if (!pingTimer) return;
    window.clearInterval(pingTimer);
    pingTimer = null;
  }

  function stopPolling() {
    if (!pollTimer) return;
    window.clearInterval(pollTimer);
    pollTimer = null;
  }

  function disableComposer(reasonText) {
    pollingStopped = true;
    websocketHealthy = false;
    stopPing();
    if (socket) {
      try {
        socket.close();
      } catch (error) {
        void error;
      }
    }
    if (reconnectTimer) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    stopPolling();
    if (textarea) textarea.disabled = true;
    setRetryVisible(false, "");
    updateSubmitState();
    setConnectionStatus("", "");
    setStatus(reasonText || "Mesajlaşma şu anda kapalı.", true);
  }

  function startPing() {
    stopPing();
    if (!socket || socket.readyState !== window.WebSocket.OPEN) return;
    pingTimer = window.setInterval(function () {
      if (!socket || socket.readyState !== window.WebSocket.OPEN) {
        stopPing();
        return;
      }
      try {
        socket.send(JSON.stringify({ type: "ping" }));
      } catch (error) {
        stopPing();
      }
    }, pingIntervalMs);
  }

  function startPolling() {
    if (pollingStopped || pollTimer) return;
    pollTimer = window.setInterval(pollMessages, fallbackPollIntervalMs);
  }

  async function pollMessages() {
    if (pollingStopped || document.hidden || !snapshotUrl || pollInFlight) return;
    pollInFlight = true;
    try {
      const response = await fetch(buildSnapshotUrl(latestId), {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "X-Requested-With": "XMLHttpRequest" },
      });
      if (response.status === 409) {
        disableComposer("Bu talepte mesajlaşma kapatıldı.");
        return;
      }
      if (!response.ok) return;
      const payload = await response.json();
      appendMessages(payload.messages || [], false);
      const payloadLatestId = Number(payload.latest_id || 0);
      if (payloadLatestId > latestId) {
        latestId = payloadLatestId;
      }
    } catch (error) {
      void error;
    } finally {
      pollInFlight = false;
    }
  }

  function connectWebSocket() {
    if (!wsSupported || pollingStopped) return;
    const wsUrl = buildWebSocketUrl();
    if (!wsUrl) return;

    try {
      socket = new window.WebSocket(wsUrl);
    } catch (error) {
      void error;
      return;
    }

    socket.addEventListener("open", function () {
      websocketHealthy = true;
      websocketOpenedAtLeastOnce = true;
      websocketReconnectCount = 0;
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      setStatus("", null);
      setConnectionStatus("", "");
      stopPolling();
      startPing();
      pollMessages();
    });

    socket.addEventListener("message", function (event) {
      try {
        const payload = JSON.parse(event.data || "{}");
        if (payload.type === "pong") return;
        if (payload.type === "message.created" && payload.message) {
          appendMessages([payload.message], false);
        }
      } catch (error) {
        void error;
      }
    });

    socket.addEventListener("close", function (event) {
      socket = null;
      websocketHealthy = false;
      stopPing();
      if (pollingStopped) return;
      if ([4401, 4403, 4404, 4409].indexOf(event.code) >= 0) {
        disableComposer("Bu konuşma artık erişilebilir değil.");
        return;
      }
      websocketReconnectCount += 1;
      startPolling();
      pollMessages();
      if (!document.hidden) {
        if (websocketOpenedAtLeastOnce) {
          setConnectionStatus("Canlı bağlantı koptu. Mesajlar otomatik yenileniyor.", "warning");
        } else {
          setConnectionStatus("Canlı bağlantı kurulamadı. Mesajlar otomatik yenileniyor.", "warning");
        }
      }
      reconnectTimer = window.setTimeout(
        connectWebSocket,
        websocketReconnectCount >= 3 ? reconnectFallbackDelayMs : reconnectDelayMs
      );
    });
  }

  form.addEventListener("submit", async function (event) {
    if (pollingStopped) return;
    event.preventDefault();
    if (sending || !textarea || !submitButton) return;

    const bodyText = String(textarea.value || "").trim();
    if (bodyText.length < 2) {
      setStatus("Mesaj en az 2 karakter olmalı.", true);
      return;
    }

    sending = true;
    updateSubmitState();
    setRetryVisible(false, "");
    setStatus("Gönderiliyor...", null);

    try {
      const response = await fetch(form.action || window.location.href, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
      });
      const payload = await response.json();
      if (response.status === 409) {
        disableComposer(payload.error || "Bu talepte mesajlaşma kapatıldı.");
        return;
      }
      if (!response.ok || !payload.ok || !payload.message) {
        setRetryVisible(true, bodyText);
        setStatus(payload.error || "Mesaj gönderilemedi.", true);
        return;
      }
      appendMessages([payload.message], true);
      textarea.value = "";
      setRetryVisible(false, "");
      setStatus("Mesaj gönderildi.", false);
    } catch (error) {
      setRetryVisible(true, bodyText);
      setStatus("Mesaj gönderilemedi. Bağlantını kontrol edip tekrar dene.", true);
      return;
    } finally {
      sending = false;
      updateSubmitState();
    }
  });

  if (retryButton) {
    retryButton.addEventListener("click", function () {
      if (!textarea || !retryBodyText || sending || pollingStopped) return;
      textarea.value = retryBodyText;
      updateSubmitState();
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
        return;
      }
      form.dispatchEvent(new Event("submit", { cancelable: true }));
    });
  }

  if (textarea) {
    textarea.addEventListener("input", function () {
      if (statusBox && statusBox.classList.contains("text-success")) {
        setStatus("", null);
      }
      if (retryBodyText && String(textarea.value || "").trim() !== retryBodyText.trim()) {
        setRetryVisible(false, "");
      }
      updateSubmitState();
    });
  }

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    if (!wsSupported || !websocketHealthy) {
      pollMessages();
      if (wsSupported && !reconnectTimer && !pollingStopped) {
        connectWebSocket();
      }
    }
  });

  scrollToBottom();
  updateSubmitState();
  startPolling();
  if (wsSupported) {
    connectWebSocket();
  } else if (!realtimeEnabled) {
    setConnectionStatus("Canlı bağlantı kapalı. Mesajlar otomatik yenileniyor.", "warning");
  }
  pollMessages();
})();
