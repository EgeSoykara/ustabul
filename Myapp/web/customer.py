from ._compat import forward


build_customer_panel_context = forward("build_customer_panel_context")
my_requests = forward("my_requests")
agreement_history = forward("agreement_history")
customer_requests_snapshot = forward("customer_requests_snapshot")
complete_request = forward("complete_request")
create_appointment = forward("create_appointment")
cancel_appointment = forward("cancel_appointment")
cancel_request = forward("cancel_request")
delete_cancelled_request = forward("delete_cancelled_request")
delete_all_cancelled_requests = forward("delete_all_cancelled_requests")
select_provider_offer = forward("select_provider_offer")
