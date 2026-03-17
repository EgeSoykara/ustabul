(function () {
  const modalElement = document.getElementById("app-confirm-modal");
  const messageElement = document.getElementById("app-confirm-modal-message");
  const approveButton = document.getElementById("app-confirm-modal-approve");
  if (!modalElement || !messageElement || !approveButton) return;

  let modalInstance = null;
  let pendingForm = null;

  function getModalInstance() {
    if (modalInstance) return modalInstance;
    if (!window.bootstrap || !window.bootstrap.Modal) return null;
    modalInstance = new window.bootstrap.Modal(modalElement, {
      backdrop: "static",
      keyboard: false,
    });
    return modalInstance;
  }

  approveButton.addEventListener("click", function () {
    if (!pendingForm) return;
    const form = pendingForm;
    pendingForm = null;
    form.dataset.confirmApproved = "1";
    const instance = getModalInstance();
    if (instance) {
      instance.hide();
    }
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
      return;
    }
    form.submit();
  });

  modalElement.addEventListener("hidden.bs.modal", function () {
    pendingForm = null;
  });

  document.addEventListener("submit", function (event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.confirmApproved === "1") {
      delete form.dataset.confirmApproved;
      return;
    }
    const confirmMessage = form.getAttribute("data-confirm-message");
    if (!confirmMessage) return;
    event.preventDefault();

    const instance = getModalInstance();
    if (!instance) {
      if (window.confirm(confirmMessage)) {
        form.dataset.confirmApproved = "1";
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
          return;
        }
        form.submit();
      }
      return;
    }

    pendingForm = form;
    messageElement.textContent = confirmMessage;
    instance.show();
  }, true);
})();
