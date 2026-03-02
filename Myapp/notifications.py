from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db.models import Max, Q
from django.urls import reverse
from django.utils import timezone

from .models import NotificationCursor, Provider, ServiceAppointment, ServiceMessage, ServiceRequest, WorkflowEvent


REQUEST_STATUS_LABELS = dict(ServiceRequest.STATUS_CHOICES)
APPOINTMENT_STATUS_LABELS = dict(ServiceAppointment.STATUS_CHOICES)
PROVIDER_CACHE_ATTR = "_provider_profile_cache"


def _truncate(text, max_len=180):
    value = str(text or "").strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


def get_notification_retention_days():
    try:
        configured = int(getattr(settings, "NOTIFICATION_RETENTION_DAYS", 60))
    except (TypeError, ValueError):
        configured = 60
    return max(7, configured)


def get_notification_cutoff(now=None):
    reference = now or timezone.now()
    return reference - timedelta(days=get_notification_retention_days())


def get_provider_for_user(user):
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if hasattr(user, PROVIDER_CACHE_ATTR):
        return getattr(user, PROVIDER_CACHE_ATTR)
    provider = Provider.objects.filter(user_id=user.id).only("id").first()
    setattr(user, PROVIDER_CACHE_ATTR, provider)
    return provider


def get_notification_cursor(user, *, create=False):
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if create:
        cursor, _created = NotificationCursor.objects.get_or_create(user=user, defaults={"workflow_seen_at": None})
        return cursor
    return NotificationCursor.objects.filter(user=user).only("id", "workflow_seen_at").first()


def invalidate_unread_notifications_cache(*user_refs):
    cache_keys = []
    seen_user_ids = set()
    for ref in user_refs:
        if ref is None:
            continue
        user_id = getattr(ref, "id", ref)
        try:
            normalized_id = int(user_id)
        except (TypeError, ValueError):
            continue
        if normalized_id <= 0 or normalized_id in seen_user_ids:
            continue
        seen_user_ids.add(normalized_id)
        cache_keys.append(f"notif:unread:{normalized_id}")
    if cache_keys:
        cache.delete_many(cache_keys)


def get_incoming_message_queryset(user, provider=None, now=None):
    cutoff = get_notification_cutoff(now)
    if provider:
        return ServiceMessage.objects.filter(
            service_request__matched_provider=provider,
            service_request__matched_offer__isnull=False,
            service_request__matched_offer__provider=provider,
            service_request__status="matched",
            created_at__gte=cutoff,
        ).exclude(sender_role="provider")
    return ServiceMessage.objects.filter(
        service_request__customer=user,
        service_request__matched_offer__isnull=False,
        service_request__status="matched",
        created_at__gte=cutoff,
    ).exclude(sender_role="customer")


def get_workflow_event_queryset(user, provider=None, now=None):
    cutoff = get_notification_cutoff(now)
    if provider:
        return WorkflowEvent.objects.filter(
            Q(service_request__matched_provider=provider)
            | Q(appointment__provider=provider)
            | Q(service_request__provider_offers__provider=provider),
            created_at__gte=cutoff,
        ).distinct()
    return WorkflowEvent.objects.filter(service_request__customer=user, created_at__gte=cutoff)


def get_total_unread_notifications_count(user):
    if not user or not getattr(user, "is_authenticated", False):
        return 0

    cache_seconds = max(1, int(getattr(settings, "NOTIFICATION_UNREAD_CACHE_SECONDS", 6)))
    cache_key = f"notif:unread:{user.id}"
    cached = cache.get(cache_key)
    if cached is not None:
        return int(cached)

    now = timezone.now()
    provider = get_provider_for_user(user)
    cursor = get_notification_cursor(user, create=False)

    unread_messages_count = get_incoming_message_queryset(user, provider=provider, now=now).filter(read_at__isnull=True).count()
    workflow_qs = get_workflow_event_queryset(user, provider=provider, now=now).exclude(actor_user=user)
    workflow_seen_at = cursor.workflow_seen_at if cursor else None
    if workflow_seen_at:
        workflow_qs = workflow_qs.filter(created_at__gt=workflow_seen_at)
    unread_workflow_count = (
        workflow_qs.values("target_type", "service_request_id", "appointment_id", "to_status").distinct().count()
    )
    total_unread = unread_messages_count + unread_workflow_count
    cache.set(cache_key, total_unread, timeout=cache_seconds)
    return total_unread


def mark_all_notifications_read(user):
    if not user or not getattr(user, "is_authenticated", False):
        return

    provider = get_provider_for_user(user)
    now = timezone.now()
    workflow_qs = get_workflow_event_queryset(user, provider=provider, now=now).exclude(actor_user=user)
    latest_workflow_at = workflow_qs.aggregate(latest=Max("created_at")).get("latest")
    seen_at = latest_workflow_at if latest_workflow_at and latest_workflow_at > now else now

    get_incoming_message_queryset(user, provider=provider, now=now).filter(read_at__isnull=True).update(read_at=seen_at)
    cursor = get_notification_cursor(user, create=True)
    cursor.workflow_seen_at = seen_at
    cursor.save(update_fields=["workflow_seen_at", "updated_at"])
    cache.set(f"notif:unread:{user.id}", 0, timeout=max(1, int(getattr(settings, "NOTIFICATION_UNREAD_CACHE_SECONDS", 6))))


def _event_status_label(event, raw_status):
    if event.target_type == "appointment":
        return APPOINTMENT_STATUS_LABELS.get(raw_status, raw_status or "-")
    return REQUEST_STATUS_LABELS.get(raw_status, raw_status or "-")


def build_notification_entries(user, *, limit=180):
    if not user or not getattr(user, "is_authenticated", False):
        return []

    now = timezone.now()
    provider = get_provider_for_user(user)
    cursor = get_notification_cursor(user, create=False)
    workflow_seen_at = cursor.workflow_seen_at if cursor else None
    panel_url = reverse("provider_requests") if provider else reverse("my_requests")

    entries = []

    messages = list(
        get_incoming_message_queryset(user, provider=provider, now=now)
        .select_related("service_request")
        .order_by("-created_at")[:limit]
    )
    for item in messages:
        request_code = item.service_request.display_code if item.service_request_id else "-"
        entries.append(
            {
                "entry_id": f"msg-{item.id}",
                "kind": "message",
                "category": "Mesaj",
                "title": f"Talep {request_code} için yeni mesaj",
                "body": _truncate(item.body, 220),
                "link": reverse("request_messages", args=[item.service_request_id]),
                "created_at": item.created_at,
                "is_unread": item.read_at is None,
            }
        )

    events = list(
        get_workflow_event_queryset(user, provider=provider, now=now)
        .select_related("service_request", "appointment", "actor_user")
        .order_by("-created_at")[:limit]
    )
    deduped_events = []
    seen_event_keys = set()
    for event in events:
        event_key = (
            event.target_type,
            event.service_request_id,
            event.appointment_id,
            event.to_status,
        )
        if event_key in seen_event_keys:
            continue
        seen_event_keys.add(event_key)
        deduped_events.append(event)
    for event in deduped_events:
        to_label = _event_status_label(event, event.to_status)
        from_label = _event_status_label(event, event.from_status)
        target_label = "Randevu" if event.target_type == "appointment" else "Talep"
        if event.note:
            body = _truncate(event.note, 220)
        else:
            body = f"{from_label} -> {to_label}"
        entries.append(
            {
                "entry_id": f"wf-{event.id}",
                "kind": "workflow",
                "category": target_label,
                "title": f"{target_label} durumu güncellendi: {to_label}",
                "body": body,
                "link": panel_url,
                "created_at": event.created_at,
                "is_unread": bool(event.actor_user_id != user.id and (not workflow_seen_at or event.created_at > workflow_seen_at)),
            }
        )

    entries.sort(key=lambda item: item["created_at"], reverse=True)
    return entries[:limit]
