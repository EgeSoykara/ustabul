from django.conf import settings


def realtime_channels_enabled():
    return bool(getattr(settings, "REALTIME_CHANNELS_ENABLED", False))


def request_lifecycle_refresh_enabled():
    return bool(getattr(settings, "REQUEST_LIFECYCLE_REFRESH_ENABLED", False))
