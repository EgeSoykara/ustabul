from ._compat import forward


signup_view = forward("signup_view")
provider_signup_view = forward("provider_signup_view")
signup_email_verify_view = forward("signup_email_verify_view")
login_view = forward("login_view")
provider_login_view = forward("provider_login_view")
password_reset_request_view = forward("password_reset_request_view")
password_reset_sent_view = forward("password_reset_sent_view")
password_reset_confirm_view = forward("password_reset_confirm_view")
password_reset_complete_view = forward("password_reset_complete_view")
logout_view = forward("logout_view")
provider_profile_view = forward("provider_profile_view")
account_settings = forward("account_settings")
delete_account = forward("delete_account")
