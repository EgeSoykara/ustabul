(function () {
  const initialSearchForm = document.getElementById("search-form");
  if (!initialSearchForm) return;

  const initialSearchSection = initialSearchForm.closest("section");
  const initialHeroSection = initialSearchSection
    ? initialSearchSection.previousElementSibling
    : null;
  const initialResultsSection = initialSearchSection
    ? initialSearchSection.nextElementSibling
    : null;

  if (!initialHeroSection || !initialSearchSection || !initialResultsSection) {
    return;
  }

  let cityDistrictMap = parseCityDistrictMap(document);
  let liveRoot = ensureLiveRoot(
    initialHeroSection,
    initialSearchSection,
    initialResultsSection
  );
  let refreshInFlight = false;

  function parseCityDistrictMap(doc) {
    const source = doc.getElementById("global-city-district-map");
    if (!source) return {};
    try {
      return JSON.parse(source.textContent || "{}");
    } catch (error) {
      void error;
      return {};
    }
  }

  function ensureLiveRoot(heroSection, searchSection, resultsSection) {
    const existing = document.getElementById("home-search-live-runtime-root");
    if (existing) {
      return existing;
    }
    const root = document.createElement("div");
    root.id = "home-search-live-runtime-root";
    heroSection.parentNode.insertBefore(root, heroSection);
    root.append(heroSection, searchSection, resultsSection);
    return root;
  }

  function getSearchForm() {
    return liveRoot.querySelector("#search-form");
  }

  function getResultsSection() {
    const sections = liveRoot.querySelectorAll("section");
    return sections.length >= 3 ? sections[2] : null;
  }

  function buildUrlFromForm(form) {
    const url = new URL(form.getAttribute("action") || window.location.href, window.location.origin);
    url.search = "";

    const formData = new FormData(form);
    formData.forEach(function (value, key) {
      if (value === null || value === undefined || value === "") {
        return;
      }
      url.searchParams.append(key, value);
    });

    return url;
  }

  function syncDistrictOptions(citySelect, districtSelect) {
    if (!citySelect || !districtSelect) return;

    const selectedCity = citySelect.value || "";
    const currentDistrict = districtSelect.value || "";
    const districts = cityDistrictMap[selectedCity] || [];

    districtSelect.innerHTML = "";

    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "İlçe seçin";
    districtSelect.appendChild(placeholder);

    const anyOption = document.createElement("option");
    anyOption.value = "Herhangi";
    anyOption.textContent = "Herhangi";
    districtSelect.appendChild(anyOption);

    districts.forEach(function (district) {
      const option = document.createElement("option");
      option.value = district;
      option.textContent = district;
      districtSelect.appendChild(option);
    });

    if (
      Array.from(districtSelect.options).some(function (option) {
        return option.value === currentDistrict;
      })
    ) {
      districtSelect.value = currentDistrict;
    } else {
      districtSelect.value = "";
    }
  }

  function bindSearchForm() {
    const searchForm = getSearchForm();
    if (!searchForm) return;

    const citySelect = searchForm.querySelector("select[name='city']");
    const districtSelect = searchForm.querySelector("select[name='district']");
    if (!citySelect || !districtSelect) return;

    syncDistrictOptions(citySelect, districtSelect);
    citySelect.addEventListener("change", function () {
      syncDistrictOptions(citySelect, districtSelect);
    });
  }

  function normalizeWhatsappPhone(rawPhone) {
    const digits = String(rawPhone || "").replace(/\D/g, "");
    if (!digits) return "";
    if (digits.startsWith("00")) return digits.slice(2);
    if (digits.startsWith("90")) return digits;
    if (digits.length === 10) return "90" + digits;
    if (digits.length === 11 && digits.startsWith("0")) return "90" + digits.slice(1);
    return digits;
  }

  function setUpWhatsappLinks() {
    const links = liveRoot.querySelectorAll(".js-whatsapp-link");
    links.forEach(function (link) {
      const rawPhone = link.dataset.phone || "";
      const normalizedPhone = normalizeWhatsappPhone(rawPhone);
      if (!normalizedPhone) {
        link.classList.add("disabled");
        link.setAttribute("aria-disabled", "true");
        link.removeAttribute("href");
        return;
      }
      link.href =
        "https://wa.me/" +
        normalizedPhone +
        "?text=" +
        encodeURIComponent("Merhaba, Ustabul üzerinden ulaşıyorum.");
      link.target = "_blank";
      link.rel = "noopener noreferrer";
    });
  }

  async function copyPhoneToClipboard(rawPhone) {
    if (!rawPhone) return false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(rawPhone);
      return true;
    }

    const tempInput = document.createElement("input");
    tempInput.value = rawPhone;
    document.body.appendChild(tempInput);
    tempInput.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(tempInput);
    return copied;
  }

  function initLiveRoot() {
    bindSearchForm();
    setUpWhatsappLinks();
  }

  function shouldInterceptLink(link) {
    if (!link || !liveRoot.contains(link)) return false;
    const url = new URL(link.href, window.location.origin);
    const samePage = url.pathname === window.location.pathname;
    if (!samePage) return false;

    if (link.closest("#search-form")) {
      return true;
    }

    const resultsSection = getResultsSection();
    if (resultsSection && resultsSection.contains(link)) {
      return url.searchParams.has("provider_page");
    }

    return false;
  }

  function updateHistory(url, mode) {
    const historyUrl = url.pathname + url.search + url.hash;
    if (mode === "push") {
      window.history.pushState({ page: "home-search" }, "", historyUrl);
      return;
    }
    window.history.replaceState({ page: "home-search" }, "", historyUrl);
  }

  function scrollToAnchor(url) {
    if (!url.hash) return;
    let target = document.querySelector(url.hash);
    if (!target && url.hash === "#provider-results-section") {
      target = getResultsSection();
    }
    if (!target) return;
    window.requestAnimationFrame(function () {
      target.scrollIntoView({ block: "start", behavior: "smooth" });
    });
  }

  async function refreshHomeSearch(urlLike, options) {
    if (refreshInFlight) return;

    const url = new URL(urlLike || window.location.href, window.location.origin);
    const shouldScroll = Boolean(options && options.scrollToAnchor);
    const historyMode = options && options.historyMode ? options.historyMode : "replace";

    refreshInFlight = true;
    try {
      const response = await fetch(url.toString(), {
        method: "GET",
        credentials: "same-origin",
        headers: { "X-Requested-With": "XMLHttpRequest" },
        cache: "no-store",
      });

      if (!response.ok) {
        window.location.assign(url.toString());
        return;
      }

      const html = await response.text();
      const parser = new DOMParser();
      const nextDocument = parser.parseFromString(html, "text/html");
      cityDistrictMap = parseCityDistrictMap(nextDocument);

      const nextSearchForm = nextDocument.getElementById("search-form");
      if (!nextSearchForm) {
        window.location.assign(url.toString());
        return;
      }

      const nextSearchSection = nextSearchForm.closest("section");
      const nextHeroSection = nextSearchSection
        ? nextSearchSection.previousElementSibling
        : null;
      const nextResultsSection = nextSearchSection
        ? nextSearchSection.nextElementSibling
        : null;

      if (!nextHeroSection || !nextSearchSection || !nextResultsSection) {
        window.location.assign(url.toString());
        return;
      }

      liveRoot.replaceChildren(
        document.importNode(nextHeroSection, true),
        document.importNode(nextSearchSection, true),
        document.importNode(nextResultsSection, true)
      );

      initLiveRoot();
      updateHistory(url, historyMode);

      if (shouldScroll) {
        scrollToAnchor(url);
      }
    } catch (error) {
      void error;
      window.location.assign(url.toString());
    } finally {
      refreshInFlight = false;
    }
  }

  liveRoot.addEventListener("submit", function (event) {
    const form = event.target.closest("#search-form");
    if (!form) return;
    event.preventDefault();
    const url = buildUrlFromForm(form);
    if (!url.hash) {
      url.hash = "#provider-results-section";
    }
    refreshHomeSearch(url.toString(), {
      historyMode: "push",
      scrollToAnchor: false,
    });
  });

  liveRoot.addEventListener("click", function (event) {
    const copyButton = event.target.closest(".js-copy-phone");
    if (copyButton) {
      event.preventDefault();
      const rawPhone = copyButton.dataset.phone || "";
      const originalLabel = copyButton.textContent;
      copyPhoneToClipboard(rawPhone)
        .then(function (copied) {
          copyButton.textContent = copied ? "Kopyalandi" : "Kopyalanamadi";
          window.setTimeout(function () {
            copyButton.textContent = originalLabel;
          }, 1500);
        })
        .catch(function () {
          copyButton.textContent = "Kopyalanamadi";
          window.setTimeout(function () {
            copyButton.textContent = originalLabel;
          }, 1500);
        });
      return;
    }

    const link = event.target.closest("a");
    if (!shouldInterceptLink(link)) return;
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
    const url = new URL(link.href, window.location.origin);
    if (!url.hash) {
      url.hash = "#provider-results-section";
    }
    refreshHomeSearch(url.toString(), {
      historyMode: "push",
      scrollToAnchor: true,
    });
  });

  window.addEventListener("popstate", function () {
    refreshHomeSearch(window.location.href, {
      historyMode: null,
      scrollToAnchor: true,
    });
  });

  initLiveRoot();
})();
