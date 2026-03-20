from django.urls import re_path

from .consumers import MobileLiveUpdatesConsumer, RequestMessagesConsumer

websocket_urlpatterns = [
    re_path(r"^ws/talep/(?P<request_id>\d+)/mesajlar/$", RequestMessagesConsumer.as_asgi()),
    re_path(r"^ws/mobile/live/$", MobileLiveUpdatesConsumer.as_asgi()),
]
