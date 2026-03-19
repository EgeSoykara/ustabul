import hashlib
import json
from datetime import timedelta

from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .constants import NC_CITY_DISTRICT_MAP
from .forms import (
    AppointmentCreateForm,
    MIN_RATING_CHOICES,
    MIN_REVIEW_CHOICES,
    ProviderRatingForm,
    SEARCH_SORT_CHOICES,
    SERVICE_REQUEST_DETAILS_MAX_LENGTH,
    ServiceRequestForm,
    ServiceSearchForm,
)
from .mobile_api_serializers import (
    MobileDeviceRegistrationSerializer,
    MobileLoginSerializer,
    MobileNotificationPreferenceSerializer,
    MobileProviderRatingSerializer,
    MobileServiceRequestSerializer,
)
from .models import (
    CustomerProfile,
    MobileDevice,
    Provider,
    ProviderOffer,
    ServiceAppointment,
    ServiceMessage,
    ServiceRequest,
    ServiceType,
    WorkflowEvent,
)
from .core_views import (
    build_create_request_fingerprint,
    build_customer_snapshot_payload,
    build_provider_membership_context,
    build_provider_snapshot_payload,
    build_request_form_initial,
    build_unread_message_map,
    create_activity_log,
    create_workflow_event,
    dispatch_next_provider_offer,
    dispatch_preferred_provider_offer,
    evaluate_appointment_cancel_policy,
    get_client_ip,
    get_action_rate_limit_max_attempts,
    get_action_rate_limit_window_seconds,
    get_create_request_daily_limit,
    get_create_request_duplicate_cooldown_seconds,
    get_create_request_ip_burst_limit,
    get_create_request_ip_burst_window_seconds,
    get_create_request_ip_daily_limit,
    get_create_request_min_interval_seconds,
    get_create_request_open_limit,
    get_create_request_rate_limit_max_attempts,
    get_create_request_rate_limit_window_seconds,
    get_preferred_provider,
    get_provider_for_user,
    get_request_display_code,
    get_last_minute_cancel_hours,
    get_no_show_grace_minutes,
    get_short_note_max_chars,
    infer_actor_role,
    is_calendar_enabled,
    normalize_request_text,
    publish_service_message_event,
    purge_request_messages,
    reroute_service_request_after_provider_exit,
    resolve_request_message_access,
    serialize_service_message,
    transition_appointment_status,
    transition_service_request_status,
)
from .services.flow import (
    build_customer_flow_state,
    build_provider_pending_appointment_flow_state,
    build_provider_pending_offer_flow_state,
    build_provider_thread_flow_state,
    build_provider_waiting_selection_flow_state,
    provider_can_release_request_match,
    score_accepted_offers,
)
from .notifications import (
    NOTIFICATION_CENTER_LIMIT,
    build_notification_entries,
    get_notification_cursor,
    get_total_unread_notifications_count,
    mark_all_notifications_read,
    mark_notification_entry_read,
    normalize_notification_category,
)


def build_identity_payload(user):
    provider = get_provider_for_user(user)
    payload = {
        "id": user.id,
        "username": user.username,
        "email": user.email or "",
        "role": "provider" if provider else "customer",
        "provider": None,
        "customer_profile": None,
    }
    if provider:
        payload["provider"] = {
            "id": provider.id,
            "full_name": provider.full_name,
            "city": provider.city,
            "district": provider.district,
            "phone": provider.phone,
            "is_verified": bool(provider.is_verified),
            "rating": float(provider.rating or 0.0),
        }
    else:
        profile = getattr(user, "customer_profile", None)
        payload["customer_profile"] = {
            "phone": getattr(profile, "phone", "") if profile else "",
            "city": getattr(profile, "city", "") if profile else "",
            "district": getattr(profile, "district", "") if profile else "",
        }
    return payload


def drf_response_from_django_response(raw_response):
    if raw_response is None:
        return None
    if isinstance(raw_response, JsonResponse):
        try:
            decoded = raw_response.content.decode("utf-8") if raw_response.content else "{}"
            data = json.loads(decoded or "{}")
        except Exception:
            data = {"detail": "error"}
        return Response(data, status=raw_response.status_code)
    if isinstance(raw_response, HttpResponse):
        return Response({"detail": "error"}, status=raw_response.status_code)
    return Response({"detail": "error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def serialize_service_type_option(service_type):
    return {
        "id": service_type.id,
        "name": service_type.name,
        "slug": service_type.slug,
    }


def serialize_provider_summary(provider):
    service_types = [service.name for service in provider.service_types.all()]
    return {
        "id": provider.id,
        "full_name": provider.full_name,
        "city": provider.city,
        "district": provider.district,
        "phone": provider.phone,
        "rating": float(provider.rating or 0.0),
        "ratings_count": int(getattr(provider, "ratings_count", 0) or 0),
        "description": provider.description or "",
        "service_types": service_types,
        "service_types_line": ", ".join(service_types),
        "is_available": bool(provider.is_available),
        "is_verified": bool(provider.is_verified),
    }


def serialize_provider_rating(rating):
    return {
        "id": rating.id,
        "customer_username": rating.customer.username,
        "score": int(rating.score),
        "comment": rating.comment or "",
        "updated_at": rating.updated_at.isoformat() if rating.updated_at else None,
    }


def serialize_request_rating(rating):
    if not rating:
        return None
    return {
        "id": rating.id,
        "score": int(rating.score),
        "comment": rating.comment or "",
        "updated_at": rating.updated_at.isoformat() if rating.updated_at else None,
    }


def build_customer_rating_state(service_request, appointment):
    can_rate = False
    rate_block_reason = ""
    calendar_enabled = bool(is_calendar_enabled())
    has_confirmed_appointment = False

    if calendar_enabled and service_request.id:
        has_confirmed_appointment = WorkflowEvent.objects.filter(
            target_type="appointment",
            service_request=service_request,
            to_status="confirmed",
        ).exists()

    if calendar_enabled:
        can_rate = (
            service_request.status == "completed"
            and bool(service_request.matched_provider_id)
            and bool(appointment)
            and appointment.status == "completed"
            and has_confirmed_appointment
        )
    else:
        can_rate = service_request.status == "completed" and bool(service_request.matched_provider_id)

    if calendar_enabled and service_request.status == "completed" and service_request.matched_provider_id and not can_rate:
        if appointment is None:
            rate_block_reason = "Randevu oluşturulmadan kapanan işlerde puanlama kapalıdır."
        elif not has_confirmed_appointment:
            rate_block_reason = "Randevu müşteri onayı olmadan kapatıldığı için puanlama kapalıdır."
        elif appointment.status != "completed":
            rate_block_reason = "Puanlama için randevunun tamamlanması gerekir."

    return {
        "can_rate": can_rate,
        "rate_block_reason": rate_block_reason,
    }


def serialize_mobile_notification_entry(entry):
    created_at = entry.get("created_at")
    counterparty = entry.get("counterparty") or {}
    return {
        "entry_id": entry.get("entry_id"),
        "kind": entry.get("kind"),
        "category_key": entry.get("category_key"),
        "category": entry.get("category"),
        "title": entry.get("title"),
        "body": entry.get("body"),
        "link": entry.get("link"),
        "created_at": created_at.isoformat() if created_at else None,
        "is_unread": bool(entry.get("is_unread")),
        "counterparty_line": counterparty.get("line", ""),
        "service_request_id": entry.get("service_request_id"),
        "appointment_id": entry.get("appointment_id"),
        "target_type": entry.get("target_type"),
        "target_status": entry.get("target_status"),
    }


def serialize_flow_state_fields(flow_state):
    return {
        "flow_step": flow_state.get("step", ""),
        "flow_title": flow_state.get("title", ""),
        "flow_hint": flow_state.get("hint", ""),
        "flow_next_action": flow_state.get("next_action", ""),
        "flow_tone": flow_state.get("tone", "muted"),
    }


def serialize_provider_offer_card(offer):
    flow_state = build_provider_pending_offer_flow_state()
    if (
        offer.status == "accepted"
        and offer.service_request_id
        and offer.service_request.status == "pending_customer"
        and offer.service_request.matched_provider_id is None
    ):
        flow_state = build_provider_waiting_selection_flow_state()

    return {
        "id": offer.id,
        "service_request_id": offer.service_request_id,
        "request_code": offer.service_request.display_code if offer.service_request_id else "",
        "service_type": offer.service_request.service_type.name if offer.service_request_id else "",
        "customer_name": offer.service_request.customer_name if offer.service_request_id else "",
        "customer_phone": offer.service_request.customer_phone if offer.service_request_id else "",
        "city": offer.service_request.city if offer.service_request_id else "",
        "district": offer.service_request.district if offer.service_request_id else "",
        "details": offer.service_request.details if offer.service_request_id else "",
        "request_status": offer.service_request.status if offer.service_request_id else "",
        "status": offer.status,
        "sent_at": offer.sent_at.isoformat() if offer.sent_at else None,
        "responded_at": offer.responded_at.isoformat() if offer.responded_at else None,
        "quote_note": offer.quote_note or "",
        "can_accept": offer.status == "pending",
        "can_reject": offer.status == "pending",
        "can_withdraw": (
            offer.status == "accepted"
            and offer.service_request.status == "pending_customer"
            and offer.service_request.matched_provider_id is None
        ),
        **serialize_flow_state_fields(flow_state),
    }


def serialize_provider_appointment_card(appointment):
    flow_state = build_provider_pending_appointment_flow_state()
    if appointment.status != "pending":
        flow_state = build_provider_thread_flow_state(
            appointment,
            calendar_enabled=is_calendar_enabled(),
        )

    return {
        "id": appointment.id,
        "service_request_id": appointment.service_request_id,
        "request_code": appointment.service_request.display_code if appointment.service_request_id else "",
        "service_type": appointment.service_request.service_type.name if appointment.service_request_id else "",
        "customer_name": appointment.service_request.customer_name if appointment.service_request_id else "",
        "customer_phone": appointment.service_request.customer_phone if appointment.service_request_id else "",
        "city": appointment.service_request.city if appointment.service_request_id else "",
        "district": appointment.service_request.district if appointment.service_request_id else "",
        "details": appointment.service_request.details if appointment.service_request_id else "",
        "scheduled_for": appointment.scheduled_for.isoformat() if appointment.scheduled_for else None,
        "status": appointment.status,
        "customer_note": appointment.customer_note or "",
        "provider_note": appointment.provider_note or "",
        "can_confirm": appointment.status == "pending",
        "can_reject": appointment.status == "pending",
        "can_complete": appointment.status in {"confirmed", "pending_customer"},
        **serialize_flow_state_fields(flow_state),
    }


def serialize_provider_reference(provider):
    if not provider:
        return None
    return {
        "id": provider.id,
        "full_name": provider.full_name,
        "city": provider.city,
        "district": provider.district,
        "phone": provider.phone,
        "rating": float(provider.rating or 0.0),
        "is_verified": bool(provider.is_verified),
        "is_available": bool(provider.is_available),
    }


def serialize_appointment_detail(appointment):
    if not appointment:
        return None
    return {
        "id": appointment.id,
        "status": appointment.status,
        "scheduled_for": appointment.scheduled_for.isoformat() if appointment.scheduled_for else None,
        "customer_note": appointment.customer_note or "",
        "provider_note": appointment.provider_note or "",
    }


def serialize_customer_offer_option(offer, *, recommended_offer_id=None):
    return {
        "id": offer.id,
        "status": offer.status,
        "sequence": int(offer.sequence or 1),
        "quote_note": offer.quote_note or "",
        "responded_at": offer.responded_at.isoformat() if offer.responded_at else None,
        "comparison_score": getattr(offer, "comparison_score", None),
        "rating_score": getattr(offer, "rating_score", None),
        "speed_score": getattr(offer, "speed_score", None),
        "is_recommended": bool(recommended_offer_id and offer.id == recommended_offer_id),
        "provider": serialize_provider_reference(offer.provider),
    }


def build_customer_request_actions(service_request, appointment):
    actions = {
        "can_cancel_request": False,
        "can_select_offer": False,
        "can_create_appointment": False,
        "can_cancel_appointment": False,
        "can_complete_request": False,
        "can_open_messages": service_request.status == "matched",
        "complete_block_reason": "",
    }

    if service_request.status in {"new", "pending_provider", "pending_customer"} and service_request.matched_provider_id is None:
        actions["can_cancel_request"] = True
        actions["can_select_offer"] = service_request.status == "pending_customer"
        return actions

    if service_request.status != "matched":
        return actions

    if not is_calendar_enabled():
        actions["can_complete_request"] = True
        return actions

    now = timezone.now()
    if appointment is None or appointment.status in {"rejected", "cancelled"}:
        actions["can_cancel_request"] = True
        actions["can_create_appointment"] = bool(service_request.matched_provider_id)
        return actions
    if appointment.status == "pending":
        actions["can_cancel_appointment"] = True
        actions["complete_block_reason"] = "Bekleyen randevu talebi varken is tamamlanamaz."
        return actions
    if appointment.status in {"confirmed", "pending_customer"}:
        actions["can_cancel_appointment"] = True
        if appointment.scheduled_for and appointment.scheduled_for > now:
            actions["complete_block_reason"] = "Onayli randevu zamani gelmeden is tamamlanamaz."
        else:
            actions["can_complete_request"] = True
    return actions


def build_provider_request_actions(*, provider, service_request, offer, appointment, membership):
    is_matched_provider = service_request.matched_provider_id == provider.id
    return {
        "can_accept_offer": bool(
            offer
            and offer.status == "pending"
            and service_request.status not in {"matched", "completed", "cancelled"}
            and membership.get("can_receive_new_requests")
        ),
        "can_reject_offer": bool(
            offer
            and offer.status == "pending"
            and service_request.status not in {"matched", "completed", "cancelled"}
        ),
        "can_withdraw_offer": bool(
            offer
            and offer.status == "accepted"
            and service_request.status == "pending_customer"
            and service_request.matched_provider_id is None
        ),
        "can_confirm_appointment": bool(appointment and appointment.provider_id == provider.id and appointment.status == "pending"),
        "can_reject_appointment": bool(appointment and appointment.provider_id == provider.id and appointment.status == "pending"),
        "can_complete_appointment": bool(
            appointment
            and appointment.provider_id == provider.id
            and appointment.status in {"confirmed", "pending_customer"}
        ),
        "can_release_request": bool(
            is_matched_provider
            and provider_can_release_request_match(
                service_request,
                appointment,
                calendar_enabled=is_calendar_enabled(),
            )
        ),
        "can_open_messages": bool(
            service_request.status == "matched"
            and service_request.matched_offer_id is not None
            and service_request.matched_offer.provider_id == provider.id
        ),
    }


def build_mobile_flow_state_payload(
    *,
    viewer_role,
    service_request,
    appointment,
    provider=None,
    provider_offer=None,
    has_accepted_offers=False,
):
    calendar_enabled = bool(is_calendar_enabled())

    if viewer_role == "customer":
        return build_customer_flow_state(
            service_request,
            appointment,
            has_accepted_offers=bool(has_accepted_offers),
            now=timezone.now(),
            calendar_enabled=calendar_enabled,
            last_minute_cancel_hours=get_last_minute_cancel_hours(),
            no_show_grace_minutes=get_no_show_grace_minutes(),
        )

    if service_request.status == "cancelled":
        return {
            "step": "Kapalı",
            "title": "Talep kapandı",
            "hint": "Bu iş artık aktif değil.",
            "next_action": "Gerekirse yeni talepleri takip edin.",
            "tone": "muted",
        }

    if service_request.status == "completed":
        return {
            "step": "Tamamlandı",
            "title": "İş tamamlandı",
            "hint": "Bu iş başarıyla kapatıldı.",
            "next_action": "Gerekirse mesajlardan son detayları kontrol edin.",
            "tone": "success",
        }

    if provider_offer and provider_offer.status == "pending":
        return build_provider_pending_offer_flow_state()

    if (
        provider_offer
        and provider_offer.status == "accepted"
        and service_request.status == "pending_customer"
        and service_request.matched_provider_id is None
    ):
        return build_provider_waiting_selection_flow_state()

    if appointment and provider and appointment.provider_id == provider.id and appointment.status == "pending":
        return build_provider_pending_appointment_flow_state()

    if service_request.status == "matched" or appointment is not None:
        return build_provider_thread_flow_state(
            appointment,
            calendar_enabled=calendar_enabled,
        )

    return {
        "step": "Aktif",
        "title": "Süreç devam ediyor",
        "hint": "Bu talep üzerinde yeni hareketler olabilir.",
        "next_action": "Talebin güncel durumunu takip edin.",
        "tone": "info",
    }


def build_mobile_request_detail_payload(service_request, *, viewer_role, request_user, provider=None):
    appointment = (
        ServiceAppointment.objects.filter(service_request=service_request)
        .select_related("provider")
        .first()
    )
    unread_map = build_unread_message_map([service_request.id], viewer_role)
    request_payload = MobileServiceRequestSerializer(
        service_request,
        context={
            "unread_map": unread_map,
            "appointment_map": {service_request.id: appointment} if appointment else {},
        },
    ).data
    request_payload["matched_provider_id"] = service_request.matched_provider_id
    request_payload["matched_provider_phone"] = (
        service_request.matched_provider.phone if service_request.matched_provider_id else ""
    )
    current_rating = getattr(service_request, "provider_rating", None)

    payload = {
        "viewer_role": viewer_role,
        "request": request_payload,
        "matched_provider": serialize_provider_reference(service_request.matched_provider),
        "matched_offer_id": service_request.matched_offer_id,
        "appointment": serialize_appointment_detail(appointment),
        "calendar_enabled": bool(is_calendar_enabled()),
        "short_note_max_length": int(get_short_note_max_chars()),
        "rating": None,
        "rating_state": {"can_rate": False, "rate_block_reason": ""},
        "actions": {},
    }

    if viewer_role == "customer":
        verified_accepted_offers = [
            offer
            for offer in service_request.provider_offers.select_related("provider")
            .filter(status="accepted")
            if offer.provider_id and getattr(offer.provider, "is_verified", False)
        ]
        accepted_offers = score_accepted_offers(list(verified_accepted_offers))
        recommended_offer_id = accepted_offers[0].id if accepted_offers else None
        payload["accepted_offers"] = [
            serialize_customer_offer_option(item, recommended_offer_id=recommended_offer_id)
            for item in accepted_offers
        ]
        if service_request.matched_offer_id:
            payload["matched_offer"] = next(
                (
                    item
                    for item in payload["accepted_offers"]
                    if item["id"] == service_request.matched_offer_id
                ),
                None,
            )
        else:
            payload["matched_offer"] = None
        payload["actions"] = build_customer_request_actions(service_request, appointment)
        payload["rating"] = serialize_request_rating(current_rating)
        payload["rating_state"] = build_customer_rating_state(service_request, appointment)
        payload["actions"]["can_rate"] = payload["rating_state"]["can_rate"]
        payload["flow_state"] = build_mobile_flow_state_payload(
            viewer_role="customer",
            service_request=service_request,
            appointment=appointment,
            has_accepted_offers=bool(accepted_offers),
        )
        payload["snapshot"] = build_customer_snapshot_payload(request_user)
        return payload

    membership = build_provider_membership_context(provider)
    provider_offer = (
        ProviderOffer.objects.select_related("provider")
        .filter(service_request=service_request, provider=provider)
        .order_by("-id")
        .first()
    )
    payload["provider_offer"] = serialize_provider_offer_card(provider_offer) if provider_offer else None
    payload["provider_membership"] = membership
    payload["actions"] = build_provider_request_actions(
        provider=provider,
        service_request=service_request,
        offer=provider_offer,
        appointment=appointment,
        membership=membership,
    )
    payload["flow_state"] = build_mobile_flow_state_payload(
        viewer_role="provider",
        service_request=service_request,
        appointment=appointment,
        provider=provider,
        provider_offer=provider_offer,
    )
    payload["snapshot"] = build_provider_snapshot_payload(provider)
    return payload


def get_mobile_request_for_customer(request_user, request_id):
    return get_object_or_404(
        ServiceRequest.objects.select_related(
            "service_type",
            "matched_provider",
            "matched_offer",
            "matched_offer__provider",
            "customer",
        ).prefetch_related("provider_offers__provider"),
        id=request_id,
        customer=request_user,
    )


def get_mobile_request_for_provider(provider, request_id):
    service_request = get_object_or_404(
        ServiceRequest.objects.select_related(
            "service_type",
            "matched_provider",
            "matched_offer",
            "matched_offer__provider",
            "customer",
        ).prefetch_related("provider_offers__provider"),
        id=request_id,
    )
    has_offer = service_request.provider_offers.filter(provider=provider).exists()
    has_appointment = ServiceAppointment.objects.filter(service_request=service_request, provider=provider).exists()
    if not has_offer and service_request.matched_provider_id != provider.id and not has_appointment:
        return None
    return service_request


def build_mobile_action_rate_limit_message(request, scope, *, identity=""):
    return build_mobile_rate_limit_message(
        request,
        scope,
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
        identity=identity,
    )


def serialize_form_errors(form):
    errors = {}
    for field_name, field_errors in form.errors.get_json_data().items():
        errors[field_name] = [entry.get("message", "") for entry in field_errors]
    return errors


def build_mobile_rate_limit_message(request, scope, *, max_attempts, window_seconds, identity=""):
    if not request.session.session_key:
        request.session.save()
    session_key = request.session.session_key or "no-session"
    ip_address = get_client_ip(request)
    user_marker = f"user:{request.user.id}" if request.user.is_authenticated else "anon"
    normalized_identity = (identity or "").strip().lower()
    raw_key = json.dumps(
        {
            "scope": scope,
            "path": request.path,
            "ip": ip_address,
            "session": session_key,
            "user": user_marker,
            "identity": normalized_identity,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    cache_key = f"rl:{hashlib.sha256(raw_key.encode('utf-8')).hexdigest()}"

    try:
        is_new = cache.add(cache_key, 1, timeout=window_seconds)
        if is_new:
            hit_count = 1
        else:
            try:
                hit_count = cache.incr(cache_key)
            except ValueError:
                previous = int(cache.get(cache_key) or 0)
                hit_count = previous + 1
                cache.set(cache_key, hit_count, timeout=window_seconds)
    except Exception:
        return None

    if hit_count > max_attempts:
        return (
            f"Çok kısa sürede çok fazla istek gönderdiniz. "
            f"Lütfen {window_seconds} saniye sonra tekrar deneyin."
        )
    return None


def validate_mobile_request_creation(request, *, cleaned_data):
    now = timezone.now()
    ip_address = get_client_ip(request)[:64]
    user = request.user if request.user.is_authenticated else None

    if user and user.id:
        open_request_count = ServiceRequest.objects.filter(
            customer=user,
            status__in=["new", "pending_provider", "pending_customer", "matched"],
        ).count()
        if open_request_count >= get_create_request_open_limit():
            return (
                "Çok fazla açık talebiniz var. Önce mevcut talepleri tamamlayın veya iptal edin.",
                "",
            )

        recent_count = ServiceRequest.objects.filter(customer=user, created_at__gte=now - timedelta(days=1)).count()
        if recent_count >= get_create_request_daily_limit():
            return ("Günlük talep sınırına ulaştınız. Lütfen bir süre sonra tekrar deneyin.", "")

        latest_request_at = (
            ServiceRequest.objects.filter(customer=user)
            .order_by("-created_at")
            .values_list("created_at", flat=True)
            .first()
        )
        if latest_request_at:
            elapsed_seconds = int((now - latest_request_at).total_seconds())
            if elapsed_seconds < get_create_request_min_interval_seconds():
                wait_seconds = max(1, get_create_request_min_interval_seconds() - elapsed_seconds)
                return (f"Yeni talep açmadan önce {wait_seconds} saniye bekleyin.", "")

    ip_daily_count = ServiceRequest.objects.filter(created_ip=ip_address, created_at__gte=now - timedelta(days=1)).count()
    if ip_daily_count >= get_create_request_ip_daily_limit():
        return ("Bu ağdan günlük talep sınırına ulaşıldı. Lütfen daha sonra tekrar deneyin.", "")

    ip_burst_count = ServiceRequest.objects.filter(
        created_ip=ip_address,
        created_at__gte=now - timedelta(seconds=get_create_request_ip_burst_window_seconds()),
    ).count()
    if ip_burst_count >= get_create_request_ip_burst_limit():
        return ("Bu ağdan çok kısa sürede çok fazla talep gönderildi. Lütfen daha sonra tekrar deneyin.", "")

    identity = f"user:{user.id}" if user and user.id else f"ip:{ip_address}"
    fingerprint = build_create_request_fingerprint(
        identity=identity,
        customer_name=cleaned_data.get("customer_name"),
        customer_phone=cleaned_data.get("customer_phone"),
        service_type=getattr(cleaned_data.get("service_type"), "id", cleaned_data.get("service_type")),
        city=cleaned_data.get("city"),
        district=cleaned_data.get("district"),
        details=cleaned_data.get("details"),
    )
    if fingerprint:
        duplicate_exists = ServiceRequest.objects.filter(
            request_fingerprint=fingerprint,
            created_at__gte=now - timedelta(seconds=get_create_request_duplicate_cooldown_seconds()),
        ).exists()
        if duplicate_exists:
            return ("Aynı içerikte talep çok sık gönderilemez. Lütfen kısa bir süre sonra tekrar deneyin.", "")

    return (None, fingerprint)


def build_mobile_create_request_success_message(dispatch_result, preferred_provider):
    result = dispatch_result.get("result")
    if result == "offers-created":
        if preferred_provider:
            return f"Talebiniz alındı. Öncelikli olarak {preferred_provider.full_name} ustasına iletildi."
        offer_count = len(dispatch_result.get("offers", []))
        return f"Talebiniz alındı. {offer_count} ustaya teklif vermesi için iletildi."
    if result == "no-candidates":
        if preferred_provider:
            return "Talebiniz alındı ancak seçilen usta şu an bu kriterlerde müsait değil."
        return "Talebiniz alındı ancak şu an şehir/ilçe kriterlerinde müsait usta bulunamadı."
    return "Talebiniz kaydedildi fakat şu an sıradaki uygun usta bulunamadı."


class MobileLoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "mobile_login"

    def post(self, request):
        serializer = MobileLoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        provider = get_provider_for_user(user)

        if provider and not provider.is_verified:
            return Response(
                {"detail": "pending-approval", "message": "Usta hesabı admin onayı bekliyor."},
                status=status.HTTP_403_FORBIDDEN,
            )

        refresh = RefreshToken.for_user(user)
        payload = {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": build_identity_payload(user),
        }
        if provider:
            payload["snapshot"] = build_provider_snapshot_payload(provider)
        else:
            payload["snapshot"] = build_customer_snapshot_payload(user)
        return Response(payload, status=status.HTTP_200_OK)


class MobileMeView(APIView):
    def get(self, request):
        provider = get_provider_for_user(request.user)
        if provider and not provider.is_verified:
            return Response(
                {"detail": "pending-approval", "message": "Usta hesabı admin onayı bekliyor."},
                status=status.HTTP_403_FORBIDDEN,
            )

        payload = {"user": build_identity_payload(request.user)}
        if provider:
            payload["snapshot"] = build_provider_snapshot_payload(provider)
        else:
            payload["snapshot"] = build_customer_snapshot_payload(request.user)
        return Response(payload, status=status.HTTP_200_OK)


class MobileMarketplaceBootstrapView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        preferred_provider = get_preferred_provider(request.GET.get("preferred_provider_id"))
        is_provider_user = bool(get_provider_for_user(request.user)) if request.user.is_authenticated else False
        request_form = ServiceRequestForm(
            initial=build_request_form_initial(request),
            preferred_provider=preferred_provider,
        )
        request_service_types = request_form.fields["service_type"].queryset.order_by("name")

        initial_data = {
            "customer_name": request_form.initial.get("customer_name", ""),
            "customer_phone": request_form.initial.get("customer_phone", ""),
            "city": request_form.initial.get("city", ""),
            "district": request_form.initial.get("district", ""),
            "service_type_id": request_form.initial.get("service_type"),
        }
        if preferred_provider:
            initial_data["preferred_provider_id"] = preferred_provider.id

        return Response(
            {
                "user_context": {
                    "is_authenticated": bool(request.user.is_authenticated),
                    "is_provider_user": is_provider_user,
                    "can_create_request": bool(request.user.is_authenticated and not is_provider_user),
                },
                "search": {
                    "service_types": [
                        serialize_service_type_option(item) for item in ServiceType.objects.order_by("name")
                    ],
                    "sort_choices": [{"value": value, "label": label} for value, label in SEARCH_SORT_CHOICES],
                    "min_rating_choices": [{"value": value, "label": label} for value, label in MIN_RATING_CHOICES],
                    "min_review_choices": [{"value": value, "label": label} for value, label in MIN_REVIEW_CHOICES],
                    "city_district_map": NC_CITY_DISTRICT_MAP,
                },
                "request_form": {
                    "initial": initial_data,
                    "service_types": [serialize_service_type_option(item) for item in request_service_types],
                    "preferred_provider": serialize_provider_summary(preferred_provider) if preferred_provider else None,
                    "locked_city": request_form.initial.get("preferred_provider_locked_city", ""),
                    "locked_district": request_form.initial.get("preferred_provider_locked_district", ""),
                    "details_max_length": SERVICE_REQUEST_DETAILS_MAX_LENGTH,
                },
            },
            status=status.HTTP_200_OK,
        )


class MobileProvidersView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        search_form = ServiceSearchForm(request.GET or None)
        if not search_form.is_valid():
            return Response(
                {"detail": "validation-error", "errors": serialize_form_errors(search_form)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        limit_raw = (request.GET.get("limit") or "20").strip()
        offset_raw = (request.GET.get("offset") or "0").strip()
        limit = min(100, max(1, int(limit_raw) if limit_raw.isdigit() else 20))
        offset = max(0, int(offset_raw) if offset_raw.isdigit() else 0)

        query_text = (search_form.cleaned_data.get("query") or "").strip()
        service_type = search_form.cleaned_data.get("service_type")
        city = (search_form.cleaned_data.get("city") or "").strip()
        district = (search_form.cleaned_data.get("district") or "").strip()
        sort_by = (search_form.cleaned_data.get("sort_by") or "relevance").strip() or "relevance"
        min_rating = search_form.cleaned_data.get("min_rating")
        min_reviews = search_form.cleaned_data.get("min_reviews")

        providers_qs = Provider.objects.accepting_new_requests().prefetch_related("service_types").annotate(
            ratings_count=Count("ratings", distinct=True)
        )
        requires_distinct = False

        if service_type:
            providers_qs = providers_qs.filter(service_types=service_type)
        if query_text:
            providers_qs = providers_qs.filter(
                Q(full_name__icontains=query_text)
                | Q(description__icontains=query_text)
                | Q(service_types__name__icontains=query_text)
            )
            requires_distinct = True
        if city:
            providers_qs = providers_qs.filter(city__iexact=city)
        if district:
            providers_qs = providers_qs.filter(district__iexact=district)
        if min_rating is not None:
            providers_qs = providers_qs.filter(rating__gte=min_rating)
        if min_reviews is not None:
            providers_qs = providers_qs.filter(ratings_count__gte=min_reviews)
        if requires_distinct:
            providers_qs = providers_qs.distinct()

        if sort_by == "reviews_desc":
            providers_qs = providers_qs.order_by("-ratings_count", "-rating", "full_name", "id")
        elif sort_by == "newest":
            providers_qs = providers_qs.order_by("-created_at", "-rating", "full_name", "id")
        elif sort_by == "name_asc":
            providers_qs = providers_qs.order_by("full_name", "-rating", "id")
        else:
            providers_qs = providers_qs.order_by("-rating", "-ratings_count", "full_name", "id")

        total_count = providers_qs.count()
        page_items = list(providers_qs[offset : offset + limit])

        return Response(
            {
                "count": total_count,
                "offset": offset,
                "limit": limit,
                "has_more": offset + len(page_items) < total_count,
                "selected_sort": sort_by,
                "selected_sort_label": dict(search_form.fields["sort_by"].choices).get(sort_by, "Önerilen"),
                "results": [serialize_provider_summary(item) for item in page_items],
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderDetailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, provider_id):
        provider = get_object_or_404(
            Provider.objects.accepting_new_requests()
            .prefetch_related("service_types")
            .annotate(ratings_count=Count("ratings", distinct=True)),
            id=provider_id,
        )
        recent_ratings = list(provider.ratings.select_related("customer").order_by("-updated_at")[:10])
        completed_jobs = provider.service_requests.filter(status="completed").count()
        successful_quotes = provider.offers.filter(status="accepted").count()

        return Response(
            {
                "provider": serialize_provider_summary(provider),
                "recent_ratings": [serialize_provider_rating(item) for item in recent_ratings],
                "completed_jobs": completed_jobs,
                "successful_quotes": successful_quotes,
                "can_create_request": bool(request.user.is_authenticated and not get_provider_for_user(request.user)),
            },
            status=status.HTTP_200_OK,
        )


class MobileCreateRequestView(APIView):
    def post(self, request):
        if get_provider_for_user(request.user):
            return Response(
                {"detail": "Usta hesabı ile talep oluşturamazsınız."},
                status=status.HTTP_403_FORBIDDEN,
            )

        rate_limit_identity = "|".join(
            [
                str(request.data.get("service_type") or "").strip(),
                normalize_request_text(request.data.get("city")),
                normalize_request_text(request.data.get("district")),
            ]
        )
        rate_limit_message = build_mobile_rate_limit_message(
            request,
            "create-request",
            max_attempts=get_create_request_rate_limit_max_attempts(),
            window_seconds=get_create_request_rate_limit_window_seconds(),
            identity=rate_limit_identity,
        )
        if rate_limit_message:
            return Response(
                {"detail": rate_limit_message},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        preferred_provider = get_preferred_provider(request.data.get("preferred_provider_id"))
        request_form = ServiceRequestForm(request.data, preferred_provider=preferred_provider)
        if not request_form.is_valid():
            return Response(
                {
                    "detail": "validation-error",
                    "errors": serialize_form_errors(request_form),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        abuse_message, fingerprint = validate_mobile_request_creation(
            request,
            cleaned_data=request_form.cleaned_data,
        )
        if abuse_message:
            return Response(
                {"detail": abuse_message},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        actor_role = infer_actor_role(request.user)
        preferred_provider = request_form.cleaned_data.get("preferred_provider")

        with transaction.atomic():
            service_request = request_form.save(commit=False)
            service_request.preferred_provider = preferred_provider
            service_request.customer = request.user
            service_request.created_ip = get_client_ip(request)[:64]
            service_request.request_fingerprint = fingerprint
            service_request.save()
            create_workflow_event(
                service_request,
                from_status="created",
                to_status=service_request.status,
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Müşteri talebi oluşturuldu",
            )
            CustomerProfile.objects.update_or_create(
                user=request.user,
                defaults={
                    "phone": service_request.customer_phone,
                    "city": service_request.city,
                    "district": service_request.district,
                },
            )
            if preferred_provider:
                dispatch_result = dispatch_preferred_provider_offer(
                    service_request,
                    preferred_provider,
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Talep seçilen ustaya öncelikli olarak iletildi",
                )
            else:
                dispatch_result = dispatch_next_provider_offer(
                    service_request,
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Talep için uygun ustalara teklif gönderildi",
                )

        request_payload = MobileServiceRequestSerializer(
            service_request,
            context={"unread_map": {}, "appointment_map": {}},
        ).data
        return Response(
            {
                "ok": True,
                "message": build_mobile_create_request_success_message(dispatch_result, preferred_provider),
                "dispatch_result": dispatch_result.get("result"),
                "request": request_payload,
                "snapshot": build_customer_snapshot_payload(request.user),
            },
            status=status.HTTP_201_CREATED,
        )


class MobileCustomerRequestsView(APIView):
    def get(self, request):
        if get_provider_for_user(request.user):
            return Response({"detail": "forbidden-provider"}, status=status.HTTP_403_FORBIDDEN)

        status_filter = (request.GET.get("status") or "").strip()
        limit_raw = (request.GET.get("limit") or "20").strip()
        offset_raw = (request.GET.get("offset") or "0").strip()
        limit = min(100, max(1, int(limit_raw) if limit_raw.isdigit() else 20))
        offset = max(0, int(offset_raw) if offset_raw.isdigit() else 0)

        qs = (
            ServiceRequest.objects.filter(customer=request.user)
            .select_related("service_type", "matched_provider")
            .prefetch_related("provider_offers__provider")
            .order_by("-created_at")
        )
        if status_filter:
            qs = qs.filter(status=status_filter)

        total_count = qs.count()
        page_items = list(qs[offset : offset + limit])
        request_ids = [item.id for item in page_items]
        unread_map = build_unread_message_map(request_ids, "customer")
        appointment_map = {
            item.service_request_id: item
            for item in ServiceAppointment.objects.filter(service_request_id__in=request_ids)
        }
        serialized = MobileServiceRequestSerializer(
            page_items,
            many=True,
            context={"unread_map": unread_map, "appointment_map": appointment_map},
        ).data
        calendar_enabled = bool(is_calendar_enabled())
        now = timezone.now()
        for service_request, item in zip(page_items, serialized):
            appointment = appointment_map.get(service_request.id)
            has_accepted_offers = any(
                offer.status == "accepted"
                and offer.provider_id
                and getattr(offer.provider, "is_verified", False)
                for offer in service_request.provider_offers.all()
            )
            flow_state = build_customer_flow_state(
                service_request,
                appointment,
                has_accepted_offers=has_accepted_offers,
                now=now,
                calendar_enabled=calendar_enabled,
                last_minute_cancel_hours=get_last_minute_cancel_hours(),
                no_show_grace_minutes=get_no_show_grace_minutes(),
            )
            item.update(serialize_flow_state_fields(flow_state))
        return Response(
            {
                "count": total_count,
                "offset": offset,
                "limit": limit,
                "results": serialized,
            },
            status=status.HTTP_200_OK,
        )


class MobileRequestDetailView(APIView):
    def get(self, request, request_id):
        provider = get_provider_for_user(request.user)
        if provider:
            if not provider.is_verified:
                return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)
            service_request = get_mobile_request_for_provider(provider, request_id)
            if service_request is None:
                return Response({"detail": "not-found"}, status=status.HTTP_404_NOT_FOUND)
            payload = build_mobile_request_detail_payload(
                service_request,
                viewer_role="provider",
                request_user=request.user,
                provider=provider,
            )
            return Response(payload, status=status.HTTP_200_OK)

        service_request = get_mobile_request_for_customer(request.user, request_id)
        payload = build_mobile_request_detail_payload(
            service_request,
            viewer_role="customer",
            request_user=request.user,
        )
        return Response(payload, status=status.HTTP_200_OK)


class MobileCustomerCancelRequestView(APIView):
    def post(self, request, request_id):
        if get_provider_for_user(request.user):
            return Response({"detail": "forbidden-provider"}, status=status.HTTP_403_FORBIDDEN)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "cancel-request",
            identity=str(request_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        service_request = get_mobile_request_for_customer(request.user, request_id)
        if service_request.status not in {"new", "pending_provider", "pending_customer"} or service_request.matched_provider_id:
            return Response(
                {"detail": "Bu talep artik iptal edilemez."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        now = timezone.now()
        service_request.provider_offers.filter(status__in=["pending", "accepted"]).update(
            status="expired",
            responded_at=now,
        )
        service_request.matched_provider = None
        service_request.matched_offer = None
        service_request.matched_at = None
        if not transition_service_request_status(
            service_request,
            "cancelled",
            extra_update_fields=["matched_provider", "matched_offer", "matched_at"],
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Musteri talebi iptal etti",
        ):
            return Response(
                {"detail": "Talep durumu guncellenemedi."},
                status=status.HTTP_409_CONFLICT,
            )

        return Response(
            {
                "ok": True,
                "message": "Talep iptal edildi.",
                "snapshot": build_customer_snapshot_payload(request.user),
            },
            status=status.HTTP_200_OK,
        )


class MobileCustomerSelectOfferView(APIView):
    def post(self, request, request_id, offer_id):
        if get_provider_for_user(request.user):
            return Response({"detail": "forbidden-provider"}, status=status.HTTP_403_FORBIDDEN)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "select-provider-offer",
            identity=f"{request_id}:{offer_id}",
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        service_request = get_mobile_request_for_customer(request.user, request_id)
        if (
            service_request.status not in {"pending_provider", "pending_customer"}
            or service_request.matched_provider_id is not None
            or service_request.matched_offer_id is not None
        ):
            return Response(
                {"detail": "Bu talep icin usta secimi artik yapilamaz."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            service_request = ServiceRequest.objects.select_for_update().filter(id=service_request.id).first()
            if (
                not service_request
                or service_request.status not in {"pending_provider", "pending_customer"}
                or service_request.matched_provider_id is not None
                or service_request.matched_offer_id is not None
            ):
                return Response(
                    {"detail": "Bu talep zaten eslestirilmis."},
                    status=status.HTTP_409_CONFLICT,
                )

            selected_offer = (
                ProviderOffer.objects.select_for_update()
                .select_related("provider")
                .filter(
                    id=offer_id,
                    service_request=service_request,
                    status="accepted",
                    provider_id__in=Provider.objects.accepting_new_requests().values("id"),
                )
                .first()
            )
            if not selected_offer:
                return Response(
                    {"detail": "Bu teklif artik secilemez."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            now = timezone.now()
            ProviderOffer.objects.filter(service_request=service_request).exclude(id=selected_offer.id).filter(
                status__in=["pending", "accepted"]
            ).update(status="expired", responded_at=now)
            service_request.matched_provider = selected_offer.provider
            service_request.matched_offer = selected_offer
            service_request.matched_at = now
            if not transition_service_request_status(
                service_request,
                "matched",
                extra_update_fields=["matched_provider", "matched_offer", "matched_at"],
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Musteri teklif secti ve usta eslesti",
            ):
                return Response(
                    {"detail": "Talep durumu eslestirme icin uygun degil."},
                    status=status.HTTP_409_CONFLICT,
                )

        return Response(
            {
                "ok": True,
                "message": f"{selected_offer.provider.full_name} secildi.",
                "snapshot": build_customer_snapshot_payload(request.user),
            },
            status=status.HTTP_200_OK,
        )


class MobileCustomerCreateAppointmentView(APIView):
    def post(self, request, request_id):
        if get_provider_for_user(request.user):
            return Response({"detail": "forbidden-provider"}, status=status.HTTP_403_FORBIDDEN)
        if not is_calendar_enabled():
            return Response({"detail": "Randevu ozelligi su an kapali."}, status=status.HTTP_400_BAD_REQUEST)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "create-appointment",
            identity=str(request_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        service_request = get_mobile_request_for_customer(request.user, request_id)
        if service_request.status != "matched" or service_request.matched_provider is None:
            return Response(
                {"detail": "Randevu sadece eslesen talepler icin olusturulabilir."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not service_request.matched_provider.is_verified:
            return Response(
                {"detail": "Bu usta henuz onayli olmadigi icin randevu olusturulamaz."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        existing = ServiceAppointment.objects.filter(service_request=service_request).first()
        if existing and existing.status == "completed":
            return Response(
                {"detail": "Tamamlanan bir talep icin yeni randevu olusturulamaz."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        form = AppointmentCreateForm(
            request.data,
            provider=service_request.matched_provider,
            current_appointment_id=existing.id if existing else None,
        )
        if not form.is_valid():
            return Response(
                {"detail": "validation-error", "errors": serialize_form_errors(form)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scheduled_for = form.cleaned_data["scheduled_for"]
        customer_note = form.cleaned_data.get("customer_note", "")
        if existing:
            existing.provider = service_request.matched_provider
            existing.customer = request.user
            existing.scheduled_for = scheduled_for
            existing.customer_note = customer_note
            existing.provider_note = ""
            if not transition_appointment_status(
                existing,
                "pending",
                extra_update_fields=[
                    "provider",
                    "customer",
                    "scheduled_for",
                    "customer_note",
                    "provider_note",
                    "updated_at",
                ],
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Musteri randevuyu yeniden planladi",
            ):
                return Response(
                    {"detail": "Bu randevu durumu yeniden planlama icin uygun degil."},
                    status=status.HTTP_409_CONFLICT,
                )
            message = "Randevu talebiniz guncellendi ve ustaya iletildi."
        else:
            new_appointment = ServiceAppointment.objects.create(
                service_request=service_request,
                customer=request.user,
                provider=service_request.matched_provider,
                scheduled_for=scheduled_for,
                customer_note=customer_note,
                status="pending",
            )
            create_workflow_event(
                new_appointment,
                from_status="created",
                to_status=new_appointment.status,
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Musteri yeni randevu talebi olusturdu",
            )
            message = "Randevu talebiniz ustaya iletildi."

        return Response(
            {
                "ok": True,
                "message": message,
                "snapshot": build_customer_snapshot_payload(request.user),
            },
            status=status.HTTP_200_OK,
        )


class MobileCustomerCancelAppointmentView(APIView):
    def post(self, request, request_id):
        if get_provider_for_user(request.user):
            return Response({"detail": "forbidden-provider"}, status=status.HTTP_403_FORBIDDEN)
        if not is_calendar_enabled():
            return Response({"detail": "Randevu ozelligi su an kapali."}, status=status.HTTP_400_BAD_REQUEST)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "cancel-appointment",
            identity=str(request_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        service_request = get_mobile_request_for_customer(request.user, request_id)
        appointment = get_object_or_404(ServiceAppointment, service_request=service_request)
        if appointment.status not in {"pending", "pending_customer", "confirmed"}:
            return Response(
                {"detail": "Bu randevu artik iptal edilemez."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        cancel_policy = evaluate_appointment_cancel_policy(appointment)
        if appointment.status == "pending":
            cancel_policy = {
                "category": "standard",
                "result_message": "Randevu iptal edildi.",
                "workflow_suffix": "",
            }
        workflow_note = "Musteri randevuyu iptal etti"
        if cancel_policy.get("workflow_suffix"):
            workflow_note = f"{workflow_note}. {cancel_policy['workflow_suffix']}"
        transition_appointment_status(
            appointment,
            "cancelled",
            extra_update_fields=["updated_at"],
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note=workflow_note,
        )
        return Response(
            {
                "ok": True,
                "message": cancel_policy.get("result_message") or "Randevu iptal edildi.",
                "snapshot": build_customer_snapshot_payload(request.user),
            },
            status=status.HTTP_200_OK,
        )


class MobileCustomerCompleteRequestView(APIView):
    def post(self, request, request_id):
        if get_provider_for_user(request.user):
            return Response({"detail": "forbidden-provider"}, status=status.HTTP_403_FORBIDDEN)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "complete-request",
            identity=str(request_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        service_request = get_mobile_request_for_customer(request.user, request_id)
        if service_request.status != "matched":
            return Response(
                {"detail": "Sadece eslesen talepler tamamlanabilir."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        calendar_enabled = is_calendar_enabled()
        appointment = ServiceAppointment.objects.filter(service_request=service_request).first()
        if calendar_enabled and (appointment is None or appointment.status in {"rejected", "cancelled"}):
            if not transition_service_request_status(
                service_request,
                "cancelled",
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note=(
                    "Musteri randevu secmeden eslesmeyi iptal etti"
                    if appointment is None
                    else "Musteri aktif olmayan randevu sonrasi talebi iptal etti"
                ),
            ):
                return Response(
                    {"detail": "Talep durumu guncellenemedi."},
                    status=status.HTTP_409_CONFLICT,
                )
            purge_request_messages(service_request.id)
            return Response(
                {
                    "ok": True,
                    "message": "Talep iptal edildi.",
                    "snapshot": build_customer_snapshot_payload(request.user),
                },
                status=status.HTTP_200_OK,
            )

        if calendar_enabled and appointment and appointment.status == "pending":
            return Response(
                {"detail": "Bekleyen randevu talebi varken talep tamamlanamaz."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if (
            calendar_enabled
            and appointment
            and appointment.status in {"confirmed", "pending_customer"}
            and appointment.scheduled_for > timezone.now()
        ):
            return Response(
                {"detail": "Onayli randevu zamani gelmeden talep tamamlanamaz."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not transition_service_request_status(
            service_request,
            "completed",
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Musteri talebi tamamladi",
        ):
            return Response(
                {"detail": "Talep durumu guncellenemedi."},
                status=status.HTTP_409_CONFLICT,
            )

        if calendar_enabled and appointment and appointment.status in {"confirmed", "pending_customer"}:
            if appointment.status == "pending_customer":
                transition_appointment_status(
                    appointment,
                    "confirmed",
                    extra_update_fields=["updated_at"],
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Bekleyen eski randevu kaydi tamamlanmadan once onaylandi",
                )
            transition_appointment_status(
                appointment,
                "completed",
                extra_update_fields=["updated_at"],
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Talep tamamlandi, randevu da tamamlandi",
            )

        purge_request_messages(service_request.id)
        return Response(
            {
                "ok": True,
                "message": "Talep tamamlandi.",
                "snapshot": build_customer_snapshot_payload(request.user),
            },
            status=status.HTTP_200_OK,
        )


class MobileCustomerRateRequestView(APIView):
    def post(self, request, request_id):
        if get_provider_for_user(request.user):
            return Response({"detail": "forbidden-provider"}, status=status.HTTP_403_FORBIDDEN)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "rate-request",
            identity=str(request_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        service_request = get_mobile_request_for_customer(request.user, request_id)
        appointment = ServiceAppointment.objects.filter(service_request=service_request).first()
        rating_state = build_customer_rating_state(service_request, appointment)
        if not rating_state["can_rate"]:
            return Response(
                {
                    "detail": rating_state["rate_block_reason"]
                    or "Puanlama sadece tamamlanmis ve uygun isler icin aciktir."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = MobileProviderRatingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        current_rating = getattr(service_request, "provider_rating", None)
        form = ProviderRatingForm(serializer.validated_data, instance=current_rating)
        if not form.is_valid():
            return Response(
                {
                    "detail": "Puan kaydedilemedi. Lutfen gecerli bir puan secin.",
                    "errors": serialize_form_errors(form),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        rating = form.save(commit=False)
        rating.service_request = service_request
        rating.provider = service_request.matched_provider
        rating.customer = request.user
        rating.save()

        return Response(
            {
                "ok": True,
                "message": (
                    f"{service_request.matched_provider.full_name} için puanınız kaydedildi."
                    if current_rating is None
                    else f"{service_request.matched_provider.full_name} için yorumunuz güncellendi."
                ),
                "rating": serialize_request_rating(rating),
                "snapshot": build_customer_snapshot_payload(request.user),
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderDashboardView(APIView):
    def get(self, request):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)

        thread_limit_raw = (request.GET.get("thread_limit") or "20").strip()
        thread_limit = min(100, max(1, int(thread_limit_raw) if thread_limit_raw.isdigit() else 20))

        active_threads = list(
            provider.service_requests.filter(
                status="matched",
                matched_offer__isnull=False,
                matched_offer__provider=provider,
            )
            .select_related("service_type", "customer")
            .order_by("-created_at")[:thread_limit]
        )
        thread_ids = [item.id for item in active_threads]
        unread_map = build_unread_message_map(thread_ids, "provider")
        calendar_enabled = bool(is_calendar_enabled())
        appointment_map = {}
        if calendar_enabled and thread_ids:
            appointment_map = {
                item.service_request_id: item
                for item in ServiceAppointment.objects.filter(
                    service_request_id__in=thread_ids,
                    provider=provider,
                )
            }
        pending_offers = list(
            provider.offers.filter(status="pending")
            .select_related("service_request", "service_request__service_type")
            .order_by("-sent_at")[:10]
        )
        waiting_customer_selection = list(
            provider.offers.filter(
                status="accepted",
                service_request__status="pending_customer",
                service_request__matched_provider__isnull=True,
            )
            .select_related("service_request", "service_request__service_type")
            .order_by("-responded_at", "-sent_at")[:10]
        )
        pending_appointments = []
        if calendar_enabled:
            pending_appointments = list(
                provider.appointments.filter(status="pending")
                .select_related("service_request", "service_request__service_type")
                .order_by("scheduled_for")[:10]
            )
        membership = build_provider_membership_context(provider)

        return Response(
            {
                "snapshot": build_provider_snapshot_payload(provider),
                "membership": membership,
                "pending_offers": [serialize_provider_offer_card(item) for item in pending_offers],
                "waiting_customer_selection": [serialize_provider_offer_card(item) for item in waiting_customer_selection],
                "pending_appointments": [serialize_provider_appointment_card(item) for item in pending_appointments],
                "active_threads": [
                    {
                        "id": item.id,
                        "request_code": item.display_code,
                        "service_type": item.service_type.name,
                        "city": item.city,
                        "district": item.district,
                        "details": item.details,
                        "customer_name": item.customer_name,
                        "customer_phone": item.customer_phone,
                        "status": item.status,
                        "created_at": item.created_at,
                        "unread_messages": int(unread_map.get(item.id, 0)),
                        **serialize_flow_state_fields(
                            build_provider_thread_flow_state(
                                appointment_map.get(item.id),
                                calendar_enabled=calendar_enabled,
                            )
                        ),
                    }
                    for item in active_threads
                ],
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderAcceptOfferView(APIView):
    def post(self, request, offer_id):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)

        membership = build_provider_membership_context(provider)
        if not membership.get("can_receive_new_requests"):
            return Response(
                {"detail": membership.get("message") or "Yeni is kabulune su an izin verilmiyor."},
                status=status.HTTP_403_FORBIDDEN,
            )

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "provider-accept-offer",
            identity=str(offer_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        with transaction.atomic():
            offer = (
                ProviderOffer.objects.select_for_update()
                .select_related("service_request")
                .filter(id=offer_id, provider=provider)
                .first()
            )
            if not offer:
                return Response({"detail": "Teklif bulunamadi."}, status=status.HTTP_404_NOT_FOUND)

            service_request = ServiceRequest.objects.select_for_update().filter(id=offer.service_request_id).first()
            if not service_request:
                return Response({"detail": "Talep artik mevcut degil."}, status=status.HTTP_404_NOT_FOUND)

            if offer.status != "pending":
                return Response({"detail": "Bu teklif artik acik degil."}, status=status.HTTP_400_BAD_REQUEST)
            if service_request.status in {"matched", "completed", "cancelled"}:
                offer.status = "expired"
                offer.responded_at = timezone.now()
                offer.save(update_fields=["status", "responded_at"])
                return Response({"detail": "Bu talep artik acik degil."}, status=status.HTTP_400_BAD_REQUEST)

            quote_note = (request.data.get("quote_note") or "").strip()
            max_short_note_chars = get_short_note_max_chars()
            if len(quote_note) > max_short_note_chars:
                return Response(
                    {"detail": f"Teklif notu en fazla {max_short_note_chars} karakter olabilir."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            now = timezone.now()
            offer.status = "accepted"
            offer.responded_at = now
            offer.quote_note = quote_note
            offer.save(update_fields=["status", "responded_at", "quote_note"])

            is_preferred_request_match = bool(
                service_request.preferred_provider_id and service_request.preferred_provider_id == offer.provider_id
            )
            if is_preferred_request_match:
                ProviderOffer.objects.filter(service_request=service_request).exclude(id=offer.id).filter(
                    status__in=["pending", "accepted"]
                ).update(status="expired", responded_at=now)
                service_request.matched_provider = provider
                service_request.matched_offer = offer
                service_request.matched_at = now
                if not transition_service_request_status(
                    service_request,
                    "matched",
                    extra_update_fields=["matched_provider", "matched_offer", "matched_at"],
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Ozel usta talebi kabul edildi ve dogrudan eslesti",
                ):
                    return Response(
                        {"detail": "Talep durumu eslesme icin guncellenemedi."},
                        status=status.HTTP_409_CONFLICT,
                    )
                message = "Talep sizinle dogrudan eslesti."
            else:
                if not transition_service_request_status(
                    service_request,
                    "pending_customer",
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Usta teklif verdi, musteri secimi bekleniyor",
                ):
                    return Response(
                        {"detail": "Talep durumu teklif sonrasi guncellenemedi."},
                        status=status.HTTP_409_CONFLICT,
                    )
                message = "Teklifiniz musteriye gonderildi."

        return Response(
            {
                "ok": True,
                "message": message,
                "snapshot": build_provider_snapshot_payload(provider),
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderRejectOfferView(APIView):
    def post(self, request, offer_id):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "provider-reject-offer",
            identity=str(offer_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        offer = get_object_or_404(
            ProviderOffer.objects.select_related("service_request"),
            id=offer_id,
            provider=provider,
            status="pending",
        )
        service_request = offer.service_request
        now = timezone.now()
        offer.status = "rejected"
        offer.responded_at = now
        offer.save(update_fields=["status", "responded_at"])

        if service_request.preferred_provider_id and service_request.preferred_provider_id == offer.provider_id:
            service_request.preferred_provider = None
            service_request.save(update_fields=["preferred_provider"])

        has_accepted_offer = service_request.provider_offers.filter(status="accepted").exists()
        if service_request.provider_offers.filter(status="pending").exists():
            if has_accepted_offer:
                transition_service_request_status(
                    service_request,
                    "pending_customer",
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Reddedilen teklif sonrasi musteri secimi bekleniyor",
                )
            message = "Teklif reddedildi. Diger ustalardan yanit bekleniyor."
            return Response(
                {"ok": True, "message": message, "snapshot": build_provider_snapshot_payload(provider)},
                status=status.HTTP_200_OK,
            )

        if has_accepted_offer:
            transition_service_request_status(
                service_request,
                "pending_customer",
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Reddedilen teklif sonrasi musteri secimi bekleniyor",
            )
            return Response(
                {
                    "ok": True,
                    "message": "Teklif reddedildi. Musterinin secimi bekleniyor.",
                    "snapshot": build_provider_snapshot_payload(provider),
                },
                status=status.HTTP_200_OK,
            )

        dispatch_result = dispatch_next_provider_offer(
            service_request,
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Usta teklifi reddetti, siradaki adaylara gecildi",
        )
        if dispatch_result["result"] == "offers-created":
            message = f"Teklif reddedildi. {len(dispatch_result['offers'])} yeni ustaya teklif acildi."
        else:
            message = "Teklif reddedildi. Yeni aday bulunamadi."
        return Response(
            {
                "ok": True,
                "message": message,
                "snapshot": build_provider_snapshot_payload(provider),
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderWithdrawOfferView(APIView):
    def post(self, request, offer_id):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "provider-withdraw-offer",
            identity=str(offer_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        with transaction.atomic():
            offer = (
                ProviderOffer.objects.select_for_update()
                .select_related("service_request")
                .filter(id=offer_id, provider=provider)
                .first()
            )
            if not offer:
                return Response({"detail": "Teklif bulunamadi."}, status=status.HTTP_404_NOT_FOUND)
            service_request = ServiceRequest.objects.select_for_update().filter(id=offer.service_request_id).first()
            if (
                not service_request
                or offer.status != "accepted"
                or service_request.status != "pending_customer"
                or service_request.matched_provider_id is not None
            ):
                return Response(
                    {"detail": "Bu teklif artik geri cekilemez."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            now = timezone.now()
            offer.status = "expired"
            offer.responded_at = now
            offer.save(update_fields=["status", "responded_at"])
            reroute_result = reroute_service_request_after_provider_exit(
                service_request,
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Usta musteri secimi bekleyen teklifini geri cekti",
            )
            if reroute_result["result"] == "invalid-state":
                return Response(
                    {"detail": "Talep durumu guncellenemedi."},
                    status=status.HTTP_409_CONFLICT,
                )

        return Response(
            {
                "ok": True,
                "message": "Teklif geri cekildi.",
                "snapshot": build_provider_snapshot_payload(provider),
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderConfirmAppointmentView(APIView):
    def post(self, request, appointment_id):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)
        if not is_calendar_enabled():
            return Response({"detail": "Randevu ozelligi su an kapali."}, status=status.HTTP_400_BAD_REQUEST)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "provider-confirm-appointment",
            identity=str(appointment_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        appointment = get_object_or_404(
            ServiceAppointment.objects.select_related("service_request"),
            id=appointment_id,
            provider=provider,
        )
        if appointment.status != "pending":
            return Response(
                {"detail": "Bu randevu talebi artik acik degil."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        provider_note = (request.data.get("provider_note") or "").strip()
        max_short_note_chars = get_short_note_max_chars()
        if len(provider_note) > max_short_note_chars:
            return Response(
                {"detail": f"Usta notu en fazla {max_short_note_chars} karakter olabilir."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        appointment.provider_note = provider_note
        if not transition_appointment_status(
            appointment,
            "confirmed",
            extra_update_fields=["provider_note", "updated_at"],
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Usta randevuyu onayladi",
        ):
            return Response(
                {"detail": "Randevu durumu usta onayi icin uygun degil."},
                status=status.HTTP_409_CONFLICT,
            )

        return Response(
            {
                "ok": True,
                "message": "Randevu onaylandi.",
                "snapshot": build_provider_snapshot_payload(provider),
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderRejectAppointmentView(APIView):
    def post(self, request, appointment_id):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)
        if not is_calendar_enabled():
            return Response({"detail": "Randevu ozelligi su an kapali."}, status=status.HTTP_400_BAD_REQUEST)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "provider-reject-appointment",
            identity=str(appointment_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        appointment = get_object_or_404(
            ServiceAppointment.objects.select_related("service_request"),
            id=appointment_id,
            provider=provider,
        )
        if appointment.status != "pending":
            return Response(
                {"detail": "Bu randevu talebi artik acik degil."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        provider_note = (request.data.get("provider_note") or "").strip()
        max_short_note_chars = get_short_note_max_chars()
        if len(provider_note) > max_short_note_chars:
            return Response(
                {"detail": f"Usta notu en fazla {max_short_note_chars} karakter olabilir."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        appointment.provider_note = provider_note
        if not transition_appointment_status(
            appointment,
            "rejected",
            extra_update_fields=["provider_note", "updated_at"],
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Usta randevu talebini reddetti",
        ):
            return Response(
                {"detail": "Randevu durumu red icin uygun degil."},
                status=status.HTTP_409_CONFLICT,
            )

        return Response(
            {
                "ok": True,
                "message": "Randevu reddedildi.",
                "snapshot": build_provider_snapshot_payload(provider),
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderCompleteAppointmentView(APIView):
    def post(self, request, appointment_id):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)
        if not is_calendar_enabled():
            return Response({"detail": "Randevu ozelligi su an kapali."}, status=status.HTTP_400_BAD_REQUEST)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "provider-complete-appointment",
            identity=str(appointment_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        appointment = get_object_or_404(
            ServiceAppointment.objects.select_related("service_request"),
            id=appointment_id,
            provider=provider,
        )
        if appointment.status not in {"confirmed", "pending_customer"}:
            return Response(
                {"detail": "Sadece onayli randevular tamamlanabilir."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if appointment.status == "pending_customer":
            transition_appointment_status(
                appointment,
                "confirmed",
                extra_update_fields=["updated_at"],
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Bekleyen eski randevu kaydi tamamlanmadan once onaylandi",
            )

        if not transition_appointment_status(
            appointment,
            "completed",
            extra_update_fields=["updated_at"],
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Usta randevuyu tamamladi",
        ):
            return Response(
                {"detail": "Randevu durumu tamamlamaya uygun degil."},
                status=status.HTTP_409_CONFLICT,
            )

        service_request = appointment.service_request
        if service_request.status != "completed":
            if service_request.matched_provider_id is None:
                service_request.matched_provider = provider
                transition_service_request_status(
                    service_request,
                    "completed",
                    extra_update_fields=["matched_provider"],
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Randevu tamamlandi, talep kapatildi",
                )
            else:
                transition_service_request_status(
                    service_request,
                    "completed",
                    actor_user=request.user,
                    actor_role=actor_role,
                    source="user",
                    note="Randevu tamamlandi, talep kapatildi",
                )

        purge_request_messages(service_request.id)
        return Response(
            {
                "ok": True,
                "message": "Is tamamlandi.",
                "snapshot": build_provider_snapshot_payload(provider),
            },
            status=status.HTTP_200_OK,
        )


class MobileProviderReleaseRequestView(APIView):
    def post(self, request, request_id):
        provider = get_provider_for_user(request.user)
        if not provider:
            return Response({"detail": "forbidden"}, status=status.HTTP_403_FORBIDDEN)
        if not provider.is_verified:
            return Response({"detail": "pending-approval"}, status=status.HTTP_403_FORBIDDEN)

        rate_limit_message = build_mobile_action_rate_limit_message(
            request,
            "provider-release-request",
            identity=str(request_id),
        )
        if rate_limit_message:
            return Response({"detail": rate_limit_message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        actor_role = infer_actor_role(request.user)
        with transaction.atomic():
            service_request = ServiceRequest.objects.select_for_update().filter(
                id=request_id,
                matched_provider=provider,
            ).first()
            if not service_request:
                return Response({"detail": "Aktif is bulunamadi."}, status=status.HTTP_404_NOT_FOUND)

            appointment = None
            if is_calendar_enabled():
                appointment = ServiceAppointment.objects.select_for_update().filter(
                    service_request=service_request
                ).first()

            if not provider_can_release_request_match(
                service_request,
                appointment,
                calendar_enabled=is_calendar_enabled(),
            ):
                return Response(
                    {"detail": "Bu is icin sonlandirma aksiyonu su anda uygun degil."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            now = timezone.now()
            matched_offer = None
            if service_request.matched_offer_id:
                matched_offer = ProviderOffer.objects.select_for_update().filter(id=service_request.matched_offer_id).first()
            if matched_offer and matched_offer.provider_id == provider.id and matched_offer.status == "accepted":
                matched_offer.status = "expired"
                matched_offer.responded_at = now
                matched_offer.save(update_fields=["status", "responded_at"])

            purge_request_messages(service_request.id)
            reroute_result = reroute_service_request_after_provider_exit(
                service_request,
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Usta musteriden yanit bekledigi eslesmeyi sonlandirdi",
            )
            if reroute_result["result"] == "invalid-state":
                return Response(
                    {"detail": "Talep durumu guncellenemedi."},
                    status=status.HTTP_409_CONFLICT,
                )

        return Response(
            {
                "ok": True,
                "message": "Eslesme sonlandirildi.",
                "snapshot": build_provider_snapshot_payload(provider),
            },
            status=status.HTTP_200_OK,
        )


class MobileRequestMessagesView(APIView):
    def get(self, request, request_id):
        service_request, viewer_role, _back_url, blocked_response = resolve_request_message_access(
            request, request_id, api=True
        )
        if blocked_response:
            return drf_response_from_django_response(blocked_response)

        after_id_raw = (request.GET.get("after_id") or "").strip()
        after_id = int(after_id_raw) if after_id_raw.isdigit() else 0

        ServiceMessage.objects.filter(service_request=service_request, read_at__isnull=True).exclude(
            sender_role=viewer_role
        ).update(read_at=timezone.now())

        thread_qs = service_request.messages.select_related("sender_user").order_by("id")
        if after_id > 0:
            thread_qs = thread_qs.filter(id__gt=after_id)
        thread_messages = list(thread_qs[:100])
        latest_id = (
            thread_messages[-1].id
            if thread_messages
            else service_request.messages.order_by("-id").values_list("id", flat=True).first() or 0
        )
        return Response(
            {
                "messages": [serialize_service_message(item, viewer_role) for item in thread_messages],
                "latest_id": latest_id,
                "thread_closed": False,
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request, request_id):
        service_request, viewer_role, _back_url, blocked_response = resolve_request_message_access(
            request, request_id, api=True
        )
        if blocked_response:
            return drf_response_from_django_response(blocked_response)

        body = (request.data.get("body") or "").strip()
        if len(body) < 2:
            return Response({"detail": "Mesaj en az 2 karakter olmalıdır."}, status=status.HTTP_400_BAD_REQUEST)
        if len(body) > 1000:
            return Response({"detail": "Mesaj en fazla 1000 karakter olabilir."}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            message_item = ServiceMessage.objects.create(
                service_request=service_request,
                sender_user=request.user,
                sender_role=viewer_role,
                body=body,
            )
            create_activity_log(
                action_type="message_sent",
                service_request=service_request,
                message_item=message_item,
                actor_user=request.user,
                actor_role=viewer_role,
                source="user",
                summary=f"Talep {get_request_display_code(service_request)} için yeni mesaj",
                note=body,
            )
        publish_service_message_event(message_item)
        return Response(
            {
                "ok": True,
                "message": serialize_service_message(message_item, viewer_role),
            },
            status=status.HTTP_201_CREATED,
        )


class MobileDeviceRegisterView(APIView):
    def post(self, request):
        serializer = MobileDeviceRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        platform = validated["platform"]
        device_id = validated["device_id"]
        push_token = validated.get("push_token")
        app_version = (validated.get("app_version") or "").strip()
        locale = (validated.get("locale") or "").strip()
        timezone_value = (validated.get("timezone") or "").strip()

        with transaction.atomic():
            if push_token:
                MobileDevice.objects.filter(push_token=push_token).exclude(
                    user=request.user,
                    platform=platform,
                    device_id=device_id,
                ).update(push_token=None)

            device, created = MobileDevice.objects.update_or_create(
                user=request.user,
                platform=platform,
                device_id=device_id,
                defaults={
                    "push_token": push_token,
                    "app_version": app_version,
                    "locale": locale,
                    "timezone": timezone_value,
                },
            )

        return Response(
            {
                "ok": True,
                "created": created,
                "device": {
                    "id": device.id,
                    "platform": device.platform,
                    "device_id": device.device_id,
                    "app_version": device.app_version,
                    "locale": device.locale,
                    "timezone": device.timezone,
                    "last_seen_at": device.last_seen_at,
                },
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class MobileNotificationsView(APIView):
    def get(self, request):
        selected_category = normalize_notification_category(request.GET.get("category"))
        limit_raw = (request.GET.get("limit") or str(NOTIFICATION_CENTER_LIMIT)).strip()
        limit = min(100, max(1, int(limit_raw) if limit_raw.isdigit() else NOTIFICATION_CENTER_LIMIT))
        entries = build_notification_entries(request.user, limit=limit, unread_only=True)
        if selected_category != "all":
            entries = [item for item in entries if item.get("category_key") == selected_category]
        return Response(
            {
                "count": len(entries),
                "unread_count": get_total_unread_notifications_count(request.user),
                "results": [serialize_mobile_notification_entry(item) for item in entries],
            },
            status=status.HTTP_200_OK,
        )


class MobileNotificationsReadAllView(APIView):
    def post(self, request):
        return Response(mark_all_notifications_read(request.user), status=status.HTTP_200_OK)


class MobileNotificationReadView(APIView):
    def post(self, request, entry_id):
        result = mark_notification_entry_read(request.user, entry_id)
        if not result:
            return Response({"detail": "not-found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(result, status=status.HTTP_200_OK)


class MobileNotificationPreferencesView(APIView):
    def get(self, request):
        cursor = get_notification_cursor(request.user, create=True)
        serializer = MobileNotificationPreferenceSerializer(cursor)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        cursor = get_notification_cursor(request.user, create=True)
        serializer = MobileNotificationPreferenceSerializer(cursor, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    patch = put
