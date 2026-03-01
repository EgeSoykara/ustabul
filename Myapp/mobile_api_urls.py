from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .mobile_api_views import (
    MobileCustomerRequestsView,
    MobileDeviceRegisterView,
    MobileLoginView,
    MobileMeView,
    MobileProviderDashboardView,
    MobileRequestMessagesView,
)


urlpatterns = [
    path("auth/login/", MobileLoginView.as_view(), name="mobile_login"),
    path("auth/refresh/", TokenRefreshView.as_view(), name="mobile_token_refresh"),
    path("me/", MobileMeView.as_view(), name="mobile_me"),
    path("customer/requests/", MobileCustomerRequestsView.as_view(), name="mobile_customer_requests"),
    path("provider/dashboard/", MobileProviderDashboardView.as_view(), name="mobile_provider_dashboard"),
    path("requests/<int:request_id>/messages/", MobileRequestMessagesView.as_view(), name="mobile_request_messages"),
    path("devices/register/", MobileDeviceRegisterView.as_view(), name="mobile_device_register"),
]
