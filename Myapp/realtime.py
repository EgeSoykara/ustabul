from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction
from django.utils import timezone

from .services.runtime import realtime_channels_enabled


def mobile_live_group_name(user_id):
    return f"mobile_live_user_{int(user_id)}"


def _normalize_user_ids(user_ids):
    normalized = []
    seen = set()
    for raw_user_id in user_ids:
        try:
            user_id = int(raw_user_id)
        except (TypeError, ValueError):
            continue
        if user_id <= 0 or user_id in seen:
            continue
        seen.add(user_id)
        normalized.append(user_id)
    return normalized


def publish_mobile_refresh_for_user_ids(
    user_ids,
    *,
    areas=None,
    reason="request.updated",
    request_id=None,
    defer=True,
):
    if not realtime_channels_enabled():
        return

    normalized_user_ids = _normalize_user_ids(user_ids)
    if not normalized_user_ids:
        return

    payload = {
        "type": "refresh.hint",
        "areas": list(areas or ("dashboard", "notifications")),
        "reason": reason,
        "sent_at": timezone.now().isoformat(),
    }
    if request_id is not None:
        payload["request_id"] = int(request_id)

    def _send():
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return
        for user_id in normalized_user_ids:
            try:
                async_to_sync(channel_layer.group_send)(
                    mobile_live_group_name(user_id),
                    {
                        "type": "mobile_refresh_hint",
                        "event": payload,
                    },
                )
            except Exception:
                continue

    if defer:
        transaction.on_commit(_send)
    else:
        _send()


def publish_mobile_refresh_for_request(
    service_request,
    *,
    reason="request.updated",
    areas=None,
    include_provider=True,
    include_customer=True,
    defer=True,
):
    if service_request is None:
        return

    user_ids = []
    if include_customer and getattr(service_request, "customer_id", None):
        user_ids.append(service_request.customer_id)

    provider = getattr(service_request, "matched_provider", None)
    provider_user_id = getattr(provider, "user_id", None)
    if include_provider and provider_user_id:
        user_ids.append(provider_user_id)

    publish_mobile_refresh_for_user_ids(
        user_ids,
        areas=areas or ("dashboard", "notifications", "request_detail"),
        reason=reason,
        request_id=getattr(service_request, "id", None),
        defer=defer,
    )

