from importlib import import_module

from .core_views import *  # noqa: F401,F403
from . import core_views as _core_views

send_mail = _core_views.send_mail
requests = _core_views.requests
queue_mobile_push_for_activity = _core_views.queue_mobile_push_for_activity
refresh_marketplace_lifecycle = _core_views.refresh_marketplace_lifecycle


def _sync_core_bindings():
    _core_views.send_mail = send_mail
    _core_views.requests = requests
    _core_views.queue_mobile_push_for_activity = queue_mobile_push_for_activity
    _core_views.refresh_marketplace_lifecycle = refresh_marketplace_lifecycle


def _dispatch(module_name, function_name, *args, **kwargs):
    _sync_core_bindings()
    module = import_module(f".web.{module_name}", package=__package__)
    return getattr(module, function_name)(*args, **kwargs)


def index(request):
    return _dispatch("site", "index", request)


def request_form_page(request):
    return _dispatch("site", "request_form_page", request)


def create_request(request):
    return _dispatch("site", "create_request", request)


def contact(request):
    return _dispatch("site", "contact", request)


def offline(request):
    return _dispatch("site", "offline", request)


def service_worker(request):
    return _dispatch("site", "service_worker", request)


def rate_request(request, request_id):
    return _dispatch("site", "rate_request", request, request_id)


def signup_view(request):
    return _dispatch("auth", "signup_view", request)


def provider_signup_view(request):
    return _dispatch("auth", "provider_signup_view", request)


def signup_email_verify_view(request):
    return _dispatch("auth", "signup_email_verify_view", request)


def login_view(request):
    return _dispatch("auth", "login_view", request)


def provider_login_view(request):
    return _dispatch("auth", "provider_login_view", request)


def password_reset_request_view(request):
    return _dispatch("auth", "password_reset_request_view", request)


def password_reset_sent_view(request):
    return _dispatch("auth", "password_reset_sent_view", request)


def password_reset_confirm_view(request, uidb64, token):
    return _dispatch("auth", "password_reset_confirm_view", request, uidb64, token)


def password_reset_complete_view(request):
    return _dispatch("auth", "password_reset_complete_view", request)


def logout_view(request):
    return _dispatch("auth", "logout_view", request)


def provider_profile_view(request):
    return _dispatch("auth", "provider_profile_view", request)


def account_settings(request):
    return _dispatch("auth", "account_settings", request)


def delete_account(request):
    return _dispatch("auth", "delete_account", request)


def request_messages(request, request_id):
    return _dispatch("messages", "request_messages", request, request_id)


def request_messages_snapshot(request, request_id):
    return _dispatch("messages", "request_messages_snapshot", request, request_id)


def notifications_view(request):
    return _dispatch("notifications", "notifications_view", request)


def notifications_mark_all_read(request):
    return _dispatch("notifications", "notifications_mark_all_read", request)


def notifications_mark_entry_read(request, entry_id):
    return _dispatch("notifications", "notifications_mark_entry_read", request, entry_id)


def notifications_open_entry(request, entry_id):
    return _dispatch("notifications", "notifications_open_entry", request, entry_id)


def notifications_unread_count(request):
    return _dispatch("notifications", "notifications_unread_count", request)


def mobile_shell_context(request):
    return _dispatch("notifications", "mobile_shell_context", request)


def mobile_shell_register_device(request):
    return _dispatch("notifications", "mobile_shell_register_device", request)


def mobile_shell_unregister_device(request):
    return _dispatch("notifications", "mobile_shell_unregister_device", request)


def operations_dashboard(request):
    return _dispatch("operations", "operations_dashboard", request)


def nav_live_stream(request):
    return _dispatch("operations", "nav_live_stream", request)


def lifecycle_health(request):
    return _dispatch("operations", "lifecycle_health", request)


def build_customer_panel_context(request):
    return _dispatch("customer", "build_customer_panel_context", request)


def my_requests(request):
    return _dispatch("customer", "my_requests", request)


def agreement_history(request):
    return _dispatch("customer", "agreement_history", request)


def customer_requests_snapshot(request):
    return _dispatch("customer", "customer_requests_snapshot", request)


def complete_request(request, request_id):
    return _dispatch("customer", "complete_request", request, request_id)


def create_appointment(request, request_id):
    return _dispatch("customer", "create_appointment", request, request_id)


def cancel_appointment(request, request_id):
    return _dispatch("customer", "cancel_appointment", request, request_id)


def cancel_request(request, request_id):
    return _dispatch("customer", "cancel_request", request, request_id)


def delete_cancelled_request(request, request_id):
    return _dispatch("customer", "delete_cancelled_request", request, request_id)


def delete_all_cancelled_requests(request):
    return _dispatch("customer", "delete_all_cancelled_requests", request)


def select_provider_offer(request, request_id, offer_id):
    return _dispatch("customer", "select_provider_offer", request, request_id, offer_id)


def build_provider_panel_context(request, provider):
    return _dispatch("provider", "build_provider_panel_context", request, provider)


def provider_requests(request):
    return _dispatch("provider", "provider_requests", request)


def provider_panel_snapshot(request):
    return _dispatch("provider", "provider_panel_snapshot", request)


def provider_detail(request, provider_id):
    return _dispatch("provider", "provider_detail", request, provider_id)


def provider_confirm_appointment(request, appointment_id):
    return _dispatch("provider", "provider_confirm_appointment", request, appointment_id)


def provider_complete_appointment(request, appointment_id):
    return _dispatch("provider", "provider_complete_appointment", request, appointment_id)


def provider_reject_appointment(request, appointment_id):
    return _dispatch("provider", "provider_reject_appointment", request, appointment_id)


def provider_accept_offer(request, offer_id):
    return _dispatch("provider", "provider_accept_offer", request, offer_id)


def provider_reject_offer(request, offer_id):
    return _dispatch("provider", "provider_reject_offer", request, offer_id)


def provider_withdraw_offer(request, offer_id):
    return _dispatch("provider", "provider_withdraw_offer", request, offer_id)


def provider_release_request(request, request_id):
    return _dispatch("provider", "provider_release_request", request, request_id)
