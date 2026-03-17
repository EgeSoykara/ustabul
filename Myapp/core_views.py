import json
import hashlib
import logging
import requests
import smtplib
import socket
import time
import traceback
import unicodedata
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from email.utils import parseaddr
from secrets import randbelow
from urllib.parse import urlencode
from uuid import uuid4
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from django.contrib import messages
from django.conf import settings
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, Max, Prefetch, Q
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.views.decorators.http import require_POST

from .constants import NC_CITY_DISTRICT_MAP
from .forms import (
    AccountIdentityForm,
    AccountPasswordChangeForm,
    AccountPasswordResetConfirmForm,
    AccountPasswordResetRequestForm,
    ANY_DISTRICT_VALUE,
    AppointmentCreateForm,
    CustomerContactSettingsForm,
    EmailVerificationCodeForm,
    CustomerLoginForm,
    CustomerSignupForm,
    NotificationPreferenceForm,
    ProviderAvailabilitySlotForm,
    ProviderProfileForm,
    ProviderLoginForm,
    ProviderSignupForm,
    ProviderRatingForm,
    ServiceRequestForm,
    ServiceSearchForm,
    ServiceMessageForm,
)
from .mobile_api_serializers import MobileDeviceRegistrationSerializer
from .notifications import (
    NOTIFICATION_CENTER_LIMIT,
    build_notification_sections,
    build_notification_entries,
    get_notification_cursor,
    get_notification_preferences,
    get_notification_retention_days,
    get_total_unread_notifications_count,
    invalidate_unread_notifications_cache,
    mark_all_notifications_read,
    mark_notification_entry_read,
    normalize_notification_category,
    resolve_notification_entry,
)
from .mobile_push import queue_mobile_push_for_activity
from .models import (
    ActivityLog,
    CustomerProfile,
    EmailVerificationCode,
    ErrorLog,
    IdempotencyRecord,
    MobileDevice,
    Provider,
    ProviderAvailabilitySlot,
    ProviderOffer,
    ProviderPayment,
    ProviderRating,
    SchedulerHeartbeat,
    ServiceAppointment,
    ServiceMessage,
    ServiceRequest,
    ServiceType,
    WorkflowEvent,
)
from .services.flow import (
    assign_recent_change_state,
    build_customer_flow_state,
    build_provider_pending_appointment_flow_state,
    build_provider_pending_offer_flow_state,
    build_provider_thread_flow_state,
    build_provider_waiting_selection_flow_state,
    get_service_request_status_ui,
    provider_can_release_request_match,
    score_accepted_offers,
)
from .services.runtime import realtime_channels_enabled, request_lifecycle_refresh_enabled

logger = logging.getLogger(__name__)

PROVIDER_PENDING_APPROVAL_MESSAGE = "Usta hesabınız admin onayı bekliyor."
PROVIDER_PENDING_APPROVAL_FLASH_FLAG = "_provider_pending_approval_warned"
PROVIDER_CACHE_ATTR = "_provider_profile_cache"
PENDING_SIGNUP_SESSION_KEY = "pending_email_signup"
EMAIL_VERIFICATION_CODE_LENGTH = 6
EMAIL_VERIFICATION_PURPOSE_META = {
    "customer-signup": {
        "account_type": "customer",
        "badge_label": "MÜŞTERİ KAYDI",
        "title": "Kodunu Gir",
        "description": "Kodu girince müşteri hesabın oluşturulacak.",
        "back_url": "customer_signup",
        "login_after_verify": True,
        "success_message": "E-posta doğrulandı. Hesabınız oluşturuldu ve giriş yapıldı.",
        "redirect_url": "index",
        "mail_subject": "Müşteri kayıt doğrulama kodunuz",
    },
    "provider-signup": {
        "account_type": "provider",
        "badge_label": "USTA KAYDI",
        "title": "Kodunu Gir",
        "description": "Kodu girince usta hesabın oluşturulacak.",
        "back_url": "provider_signup",
        "login_after_verify": False,
        "success_message": "E-posta doğrulandı. Usta hesabın oluşturuldu. Admin onayı sonrası giriş yapabilirsin.",
        "redirect_url": "provider_login",
        "mail_subject": "Usta kayıt doğrulama kodunuz",
    },
}


def build_request_form_initial(request):
    if not request.user.is_authenticated:
        return {}

    profile = getattr(request.user, "customer_profile", None)
    return {
        "customer_name": request.user.get_full_name() or request.user.username,
        "customer_phone": profile.phone if profile else "",
        "city": profile.city if profile else "",
        "district": profile.district if profile else "",
    }


def get_preferred_provider(raw_provider_id):
    raw_value = str(raw_provider_id or "").strip()
    if not raw_value.isdigit():
        return None
    return (
        Provider.objects.accepting_new_requests().filter(id=int(raw_value))
        .prefetch_related("service_types")
        .first()
    )


def build_service_request_form(request, *, preferred_provider, is_provider_user):
    request_form_initial = build_request_form_initial(request)
    if preferred_provider and request.user.is_authenticated and not is_provider_user:
        request_form_initial["preferred_provider_id"] = preferred_provider.id
        request_form_initial["city"] = preferred_provider.city
        request_form_initial["district"] = preferred_provider.district
        request_form_initial["preferred_provider_locked_city"] = preferred_provider.city
        request_form_initial["preferred_provider_locked_district"] = preferred_provider.district
        provider_service_ids = list(preferred_provider.service_types.values_list("id", flat=True))
        if provider_service_ids:
            selected_service_id = request_form_initial.get("service_type")
            if selected_service_id not in provider_service_ids:
                selected_service_id = provider_service_ids[0]
            request_form_initial["service_type"] = selected_service_id
    return ServiceRequestForm(initial=request_form_initial, preferred_provider=preferred_provider)


def paginate_items(request, items, *, per_page=12, page_param="page"):
    paginator = Paginator(items, per_page)
    return paginator.get_page(request.GET.get(page_param))


def build_page_query_suffix(request, page_param):
    params = request.GET.copy()
    params.pop(page_param, None)
    encoded = params.urlencode()
    return f"&{encoded}" if encoded else ""


def build_query_url(request, *, updates=None, remove=None):
    params = request.GET.copy()
    for key in remove or []:
        params.pop(key, None)
    for key, value in (updates or {}).items():
        if value in (None, "", False):
            params.pop(key, None)
            continue
        params[key] = value
    encoded = params.urlencode()
    return f"{request.path}?{encoded}" if encoded else request.path


def get_request_display_code(service_request):
    if not service_request:
        return "-"
    display_code = getattr(service_request, "display_code", "")
    if display_code:
        return display_code
    request_code = getattr(service_request, "request_code", "")
    if request_code:
        return request_code
    request_id = getattr(service_request, "id", None)
    return f"TLP-{request_id}" if request_id else "-"


def build_request_search_query(search_text, *, prefix="", include_matched_provider=False):
    normalized = str(search_text or "").strip()
    if not normalized:
        return Q()

    fields = [
        f"{prefix}request_code__icontains",
        f"{prefix}customer_name__icontains",
        f"{prefix}customer_phone__icontains",
        f"{prefix}service_type__name__icontains",
        f"{prefix}city__icontains",
        f"{prefix}district__icontains",
        f"{prefix}details__icontains",
    ]
    if include_matched_provider:
        fields.append(f"{prefix}matched_provider__full_name__icontains")

    query = Q()
    for field_name in fields:
        query |= Q(**{field_name: normalized})
    return query


def parse_float(value):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _normalize_choice_text(value):
    normalized = unicodedata.normalize("NFKD", str(value or "").strip().lower())
    without_marks = "".join(char for char in normalized if not unicodedata.combining(char))
    return "".join(char for char in without_marks if char.isalnum())


def _strip_diacritics(value):
    normalized = unicodedata.normalize("NFKD", str(value or "").strip())
    return "".join(char for char in normalized if not unicodedata.combining(char))


def _canonical_city(city_value):
    target = _normalize_choice_text(city_value)
    if not target:
        return ""
    for city_key in NC_CITY_DISTRICT_MAP.keys():
        if _normalize_choice_text(city_key) == target:
            return city_key
    return str(city_value or "").strip()


def _canonical_district(city_value, district_value):
    target = _normalize_choice_text(district_value)
    if not target:
        return ""
    city_key = _canonical_city(city_value)
    for district in NC_CITY_DISTRICT_MAP.get(city_key, []):
        if _normalize_choice_text(district) == target:
            return district
    return str(district_value or "").strip()


def _build_iexact_query(field_name, values):
    unique_values = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_values.append(text)
    if not unique_values:
        return Q(pk__in=[])
    query = Q()
    for value in unique_values:
        query |= Q(**{f"{field_name}__iexact": value})
    return query


def _build_city_variants(city_value):
    canonical = _canonical_city(city_value)
    raw = str(city_value or "").strip()
    variants = [raw, canonical, _strip_diacritics(raw), _strip_diacritics(canonical)]
    return [item for item in variants if item]


def _build_district_variants(city_value, district_value):
    canonical = _canonical_district(city_value, district_value)
    raw = str(district_value or "").strip()
    variants = [raw, canonical, _strip_diacritics(raw), _strip_diacritics(canonical)]
    return [item for item in variants if item]


def sort_providers_by_distance(providers, latitude, longitude):
    def squared_distance(provider):
        if provider.latitude is None or provider.longitude is None:
            return float("inf")
        lat_delta = float(provider.latitude) - latitude
        lon_delta = float(provider.longitude) - longitude
        return (lat_delta * lat_delta) + (lon_delta * lon_delta)

    return sorted(
        providers,
        key=lambda provider: (
            squared_distance(provider),
            -float(provider.rating),
            provider.full_name.lower(),
            provider.id,
        ),
    )


def get_provider_for_user(user):
    if not user.is_authenticated:
        return None
    if hasattr(user, PROVIDER_CACHE_ATTR):
        return getattr(user, PROVIDER_CACHE_ATTR)
    provider = Provider.objects.filter(user_id=user.id).first()
    setattr(user, PROVIDER_CACHE_ATTR, provider)
    return provider


def resolve_provider_user_id(provider_obj=None, provider_id=None):
    if provider_obj is not None:
        cached_user_id = getattr(provider_obj, "user_id", None)
        if cached_user_id:
            return cached_user_id
    if provider_id:
        return Provider.objects.filter(id=provider_id).values_list("user_id", flat=True).first()
    return None


def invalidate_notification_cache_for_instance(instance, *, actor_user=None):
    user_ids = set()

    if actor_user and getattr(actor_user, "id", None):
        user_ids.add(actor_user.id)

    if isinstance(instance, ServiceRequest):
        if instance.customer_id:
            user_ids.add(instance.customer_id)
        matched_provider_user_id = resolve_provider_user_id(
            provider_obj=getattr(instance, "matched_provider", None),
            provider_id=instance.matched_provider_id,
        )
        if matched_provider_user_id:
            user_ids.add(matched_provider_user_id)
        if instance.id:
            offer_provider_user_ids = Provider.objects.filter(offers__service_request_id=instance.id).values_list(
                "user_id", flat=True
            )
            user_ids.update(int(user_id) for user_id in offer_provider_user_ids if user_id)

    elif isinstance(instance, ServiceAppointment):
        if instance.customer_id:
            user_ids.add(instance.customer_id)
        appointment_provider_user_id = resolve_provider_user_id(
            provider_obj=getattr(instance, "provider", None),
            provider_id=instance.provider_id,
        )
        if appointment_provider_user_id:
            user_ids.add(appointment_provider_user_id)

        service_request = getattr(instance, "service_request", None)
        if service_request is not None:
            if service_request.customer_id:
                user_ids.add(service_request.customer_id)
            matched_provider_user_id = resolve_provider_user_id(
                provider_obj=getattr(service_request, "matched_provider", None),
                provider_id=service_request.matched_provider_id,
            )
            if matched_provider_user_id:
                user_ids.add(matched_provider_user_id)
        elif instance.service_request_id:
            request_row = ServiceRequest.objects.filter(id=instance.service_request_id).values(
                "customer_id",
                "matched_provider_id",
            ).first()
            if request_row:
                if request_row.get("customer_id"):
                    user_ids.add(int(request_row["customer_id"]))
                matched_provider_user_id = resolve_provider_user_id(
                    provider_id=request_row.get("matched_provider_id")
                )
                if matched_provider_user_id:
                    user_ids.add(matched_provider_user_id)

    if user_ids:
        invalidate_unread_notifications_cache(*user_ids)


def is_calendar_enabled():
    return bool(getattr(settings, "CALENDAR_FEATURE_ENABLED", False))


def is_provider_availability_enabled():
    return bool(getattr(settings, "PROVIDER_AVAILABILITY_ENABLED", False))


def calendar_disabled_redirect(request, redirect_name):
    messages.info(request, "Takvim özelliği şu anda devre dışı.")
    return redirect(redirect_name)


def queue_provider_pending_approval_warning(request):
    request.session[PROVIDER_PENDING_APPROVAL_FLASH_FLAG] = True
    messages.warning(request, PROVIDER_PENDING_APPROVAL_MESSAGE)


def get_verified_provider_or_redirect(request, *, redirect_name="provider_login", api=False):
    provider = get_provider_for_user(request.user)
    if not provider:
        if api:
            return None, JsonResponse({"detail": "forbidden"}, status=403)
        messages.error(request, "Bu alan sadece usta hesapları içindir.")
        return None, redirect(redirect_name)
    if not provider.is_verified:
        if api:
            return None, JsonResponse({"detail": "pending-approval"}, status=403)
        queue_provider_pending_approval_warning(request)
        return None, redirect(redirect_name)
    return provider, None


def build_provider_membership_context(provider, *, now=None):
    reference_time = now or timezone.now()
    state = provider.get_membership_state(now=reference_time)
    expires_at = provider.membership_expires_at
    grace_until = provider.membership_grace_until
    context = {
        "state": state,
        "can_receive_new_requests": provider.can_receive_new_requests(now=reference_time),
        "expires_at": expires_at,
        "grace_until": grace_until,
        "last_cash_payment_at": provider.last_cash_payment_at,
        "note": (provider.membership_note or "").strip(),
        "tone": "success",
        "title": "Üyeliğiniz aktif",
        "message": "Yeni talepler almaya devam edebilirsiniz.",
    }
    if state == "trial":
        context["tone"] = "info"
        context["title"] = "Deneme üyeliği aktif"
        context["message"] = (
            f"Son görünürlük tarihi: {timezone.localtime(expires_at).strftime('%d.%m.%Y %H:%M')}."
            if expires_at
            else "Admin panelinden ilk son ödeme tarihi tanımlanana kadar görünürsünüz."
        )
    elif state == "active":
        if expires_at:
            context["message"] = f"Üyeliğiniz {timezone.localtime(expires_at).strftime('%d.%m.%Y %H:%M')} tarihine kadar aktif."
    elif state == "grace":
        context["tone"] = "warning"
        context["title"] = "Ödeme yenilemesi gerekiyor"
        context["message"] = (
            f"Son ödeme tarihiniz geçti. {timezone.localtime(grace_until).strftime('%d.%m.%Y %H:%M')} tarihine kadar görünürlüğünüz korunuyor."
            if grace_until
            else "Son ödeme tarihiniz geçti. Lütfen üyeliğinizi yenileyin."
        )
    else:
        context["tone"] = "danger"
        context["title"] = "Üyeliğiniz askıda"
        context["message"] = "Yeni talep alamazsınız. Mevcut işlerinizi tamamlayabilir, yenileme için yönetime başvurabilirsiniz."
    return context


def require_provider_membership_for_new_requests(request, provider, *, redirect_name="provider_requests"):
    if provider.can_receive_new_requests():
        return None
    membership = build_provider_membership_context(provider)
    messages.warning(request, membership["message"])
    return redirect(redirect_name)


def get_provider_membership_trial_days():
    return max(1, int(getattr(settings, "PROVIDER_MEMBERSHIP_TRIAL_DAYS", 30)))


def get_provider_membership_state_label(state):
    labels = {
        "trial": "Deneme",
        "active": "Aktif",
        "grace": "Ek Süre",
        "suspended": "Askıda",
    }
    return labels.get(state, "-")


def get_provider_membership_state_rank(state):
    ranks = {
        "suspended": 0,
        "grace": 1,
        "trial": 2,
        "active": 3,
    }
    return ranks.get(state, 9)


def build_provider_membership_remaining_label(provider, membership, *, now=None):
    reference_time = now or timezone.now()
    expires_at = membership.get("expires_at")
    grace_until = membership.get("grace_until")
    state = membership.get("state")

    if state in {"active", "trial"}:
        if not expires_at:
            return "Tarih tanımlı değil"
        remaining = expires_at - reference_time
        if remaining.total_seconds() <= 0:
            return "Bugün bitiyor"
        days = max(0, int(remaining.total_seconds() // 86400))
        hours = max(0, int((remaining.total_seconds() % 86400) // 3600))
        if days > 0:
            return f"{days} gün kaldı"
        if hours > 0:
            return f"{hours} saat kaldı"
        return "1 saatten az kaldı"

    if state == "grace":
        if not grace_until:
            return "Ek sürede"
        remaining = grace_until - reference_time
        if remaining.total_seconds() <= 0:
            return "Ek süre doldu"
        days = max(0, int(remaining.total_seconds() // 86400))
        hours = max(0, int((remaining.total_seconds() % 86400) // 3600))
        if days > 0:
            return f"Ek sürede, {days} gün kaldı"
        if hours > 0:
            return f"Ek sürede, {hours} saat kaldı"
        return "Ek sürede, son saatler"

    if expires_at and expires_at < reference_time:
        overdue = reference_time - expires_at
        overdue_days = max(1, int(overdue.total_seconds() // 86400) or 0)
        return f"{overdue_days} gün gecikmiş"
    return "Askıda"


def build_waiting_duration_label(reference_at, *, now=None):
    if not reference_at:
        return "-"
    reference_time = now or timezone.now()
    elapsed_seconds = max(0, int((reference_time - reference_at).total_seconds()))
    if elapsed_seconds < 60:
        return "Az önce"

    minutes = max(1, elapsed_seconds // 60)
    if minutes < 60:
        return f"{minutes} dk bekliyor"

    hours = max(1, elapsed_seconds // 3600)
    if hours < 48:
        return f"{hours} saattir bekliyor"

    days = max(1, elapsed_seconds // 86400)
    return f"{days} gündür bekliyor"


def build_operations_dashboard_redirect_url(request, selected_day):
    params = {}
    if selected_day:
        params["day"] = selected_day.isoformat()
    membership_page_raw = str(request.POST.get("membership_page") or request.GET.get("membership_page") or "").strip()
    if membership_page_raw.isdigit():
        params["membership_page"] = membership_page_raw
    activity_page_raw = str(request.POST.get("activity_page") or request.GET.get("activity_page") or "").strip()
    if activity_page_raw.isdigit():
        params["activity_page"] = activity_page_raw
    attention_page_raw = str(request.POST.get("attention_page") or request.GET.get("attention_page") or "").strip()
    if attention_page_raw.isdigit():
        params["attention_page"] = attention_page_raw
    membership_query = str(request.POST.get("membership_q") or request.GET.get("membership_q") or "").strip()
    if membership_query:
        params["membership_q"] = membership_query
    membership_state = str(request.POST.get("membership_state") or request.GET.get("membership_state") or "").strip()
    if membership_state and membership_state != "all":
        params["membership_state"] = membership_state
    attention_view = str(request.POST.get("attention") or request.GET.get("attention") or "").strip()
    if attention_view == "all":
        params["attention"] = attention_view
    base_url = reverse("operations_dashboard")
    if not params:
        return base_url
    return f"{base_url}?{urlencode(params)}"


def get_city_district_map_json():
    return json.dumps(NC_CITY_DISTRICT_MAP)


def get_popular_service_types(limit=6):
    return list(
        ServiceType.objects.annotate(request_count=Count("requests", distinct=True))
        .order_by("-request_count", "name")[:limit]
    )


def get_first_form_error(form):
    for field_errors in form.errors.values():
        if field_errors:
            return field_errors[0]
    return "Formdaki alanlari kontrol edip tekrar deneyin."


def get_email_verification_code_ttl_minutes():
    return max(3, int(getattr(settings, "EMAIL_VERIFICATION_CODE_TTL_MINUTES", 10)))


def get_email_verification_resend_cooldown_seconds():
    return max(10, int(getattr(settings, "EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS", 60)))


def get_email_verification_max_attempts():
    return max(3, int(getattr(settings, "EMAIL_VERIFICATION_MAX_ATTEMPTS", 5)))


def get_email_verification_session_ttl_minutes():
    return max(10, int(getattr(settings, "EMAIL_VERIFICATION_SESSION_TTL_MINUTES", 30)))


def normalize_signup_email(value):
    return str(value or "").strip().lower()


def get_pending_signup_payload(request):
    payload = request.session.get(PENDING_SIGNUP_SESSION_KEY)
    if not isinstance(payload, dict):
        return None

    purpose = str(payload.get("purpose") or "").strip()
    if purpose not in EMAIL_VERIFICATION_PURPOSE_META:
        request.session.pop(PENDING_SIGNUP_SESSION_KEY, None)
        request.session.modified = True
        return None

    started_at_raw = str(payload.get("started_at") or "").strip()
    if started_at_raw:
        try:
            started_at = datetime.fromisoformat(started_at_raw)
        except ValueError:
            request.session.pop(PENDING_SIGNUP_SESSION_KEY, None)
            request.session.modified = True
            return None
        if started_at.tzinfo is None:
            started_at = timezone.make_aware(started_at, timezone.get_current_timezone())
        if timezone.now() - started_at > timedelta(minutes=get_email_verification_session_ttl_minutes()):
            request.session.pop(PENDING_SIGNUP_SESSION_KEY, None)
            request.session.modified = True
            return None

    return payload


def set_pending_signup_payload(request, payload):
    request.session[PENDING_SIGNUP_SESSION_KEY] = {
        **payload,
        "email": normalize_signup_email(payload.get("email")),
        "started_at": timezone.now().isoformat(),
    }
    request.session.modified = True


def clear_pending_signup_payload(request):
    request.session.pop(PENDING_SIGNUP_SESSION_KEY, None)
    request.session.modified = True


def get_signup_verification_meta(purpose):
    return EMAIL_VERIFICATION_PURPOSE_META.get(str(purpose or "").strip(), EMAIL_VERIFICATION_PURPOSE_META["customer-signup"])


def generate_email_verification_code():
    upper_bound = 10 ** EMAIL_VERIFICATION_CODE_LENGTH
    return f"{randbelow(upper_bound):0{EMAIL_VERIFICATION_CODE_LENGTH}d}"


def hash_email_verification_code(email, purpose, code):
    normalized_email = normalize_signup_email(email)
    raw_value = f"{settings.SECRET_KEY}:{purpose}:{normalized_email}:{str(code or '').strip()}"
    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def get_latest_email_verification(email, purpose):
    return (
        EmailVerificationCode.objects.filter(email__iexact=normalize_signup_email(email), purpose=purpose)
        .order_by("-created_at", "-id")
        .first()
    )


def get_active_email_verification(email, purpose):
    now = timezone.now()
    return (
        EmailVerificationCode.objects.filter(
            email__iexact=normalize_signup_email(email),
            purpose=purpose,
            consumed_at__isnull=True,
            expires_at__gt=now,
        )
        .order_by("-created_at", "-id")
        .first()
    )


def get_signup_resend_available_in(email, purpose):
    latest_verification = get_latest_email_verification(email, purpose)
    if not latest_verification or not latest_verification.created_at:
        return 0
    elapsed_seconds = int((timezone.now() - latest_verification.created_at).total_seconds())
    return max(0, get_email_verification_resend_cooldown_seconds() - elapsed_seconds)


def extract_client_ip(request):
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()[:64]
    return request.META.get("REMOTE_ADDR", "")[:64]


def send_brevo_transactional_email(*, subject, body, recipient_email):
    api_key = str(getattr(settings, "BREVO_API_KEY", "") or "").strip()
    if not api_key:
        raise RuntimeError("BREVO_API_KEY ayari eksik.")

    sender_name, sender_email = parseaddr(settings.DEFAULT_FROM_EMAIL or "")
    if not sender_email:
        raise RuntimeError("DEFAULT_FROM_EMAIL ayari gecersiz.")

    api_base_url = str(getattr(settings, "BREVO_API_BASE_URL", "https://api.brevo.com/v3") or "").rstrip("/")
    timeout_seconds = max(5, int(getattr(settings, "BREVO_API_TIMEOUT", getattr(settings, "EMAIL_TIMEOUT", 15))))
    payload = {
        "sender": {
            "email": sender_email,
            "name": sender_name or "Ustabul",
        },
        "to": [{"email": normalize_signup_email(recipient_email)}],
        "subject": subject,
        "textContent": body,
    }
    response = requests.post(
        f"{api_base_url}/smtp/email",
        headers={
            "accept": "application/json",
            "api-key": api_key,
            "content-type": "application/json",
        },
        json=payload,
        timeout=timeout_seconds,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        response_body = (response.text or "").strip()
        if response_body:
            raise RuntimeError(f"Brevo API hatasi ({response.status_code}): {response_body[:300]}") from exc
        raise


def send_signup_verification_email(email, code, *, purpose):
    meta = get_signup_verification_meta(purpose)
    ttl_minutes = get_email_verification_code_ttl_minutes()
    subject = f"Ustabul {meta['mail_subject']}"
    body = (
        f"Merhaba,\n\n"
        f"Kaydınızı tamamlamak için doğrulama kodunuz: {code}\n\n"
        f"Bu kod {ttl_minutes} dakika boyunca geçerlidir.\n"
        f" Eğer bu işlemi siz yapmadıysanız bu e-postayı dikkate almayınız.\n\n"
        f"Ustabul"
    )
    send_text_transactional_email(subject=subject, body=body, recipient_email=email)


def send_text_transactional_email(*, subject, body, recipient_email):
    sender_email = parseaddr(settings.DEFAULT_FROM_EMAIL or "")[1]
    brevo_api_key = str(getattr(settings, "BREVO_API_KEY", "") or "").strip()
    smtp_backend = str(getattr(settings, "EMAIL_BACKEND", "") or "").endswith("smtp.EmailBackend")
    if brevo_api_key:
        send_brevo_transactional_email(subject=subject, body=body, recipient_email=recipient_email)
        return
    if smtp_backend:
        missing_fields = [
            field_name
            for field_name in ("EMAIL_HOST", "EMAIL_HOST_USER", "EMAIL_HOST_PASSWORD")
            if not str(getattr(settings, field_name, "") or "").strip()
        ]
        if missing_fields:
            raise RuntimeError(f"SMTP ayarlari eksik: {', '.join(missing_fields)}")
    if not sender_email:
        raise RuntimeError("DEFAULT_FROM_EMAIL ayari gecersiz.")
    send_mail(
        subject,
        body,
        settings.DEFAULT_FROM_EMAIL,
        [normalize_signup_email(recipient_email)],
        fail_silently=False,
    )


def build_absolute_url(request, path):
    scheme = "https" if request.is_secure() or request.META.get("HTTP_X_FORWARDED_PROTO") == "https" else "http"
    return f"{scheme}://{request.get_host()}{path}"


def build_password_reset_url(request, user):
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    path = reverse("password_reset_confirm", args=[uidb64, token])
    return build_absolute_url(request, path)


def send_password_reset_email(user, *, reset_url):
    recipient_email = normalize_signup_email(user.email)
    subject = "Ustabul sifre sifirlama baglantiniz"
    display_name = user.get_full_name().strip() or user.username
    body = (
        f"Merhaba {display_name},\n\n"
        f"Sifrenizi yenilemek icin asagidaki baglantiyi acin:\n{reset_url}\n\n"
        f"Bu baglanti tek kullanimliktir. Eger bu islemi siz yapmadiysaniz e-postayi dikkate almayiniz.\n\n"
        f"Ustabul"
    )
    send_text_transactional_email(subject=subject, body=body, recipient_email=recipient_email)


def get_signup_email_delivery_error_message(exc):
    reason = f"{type(exc).__name__}: {exc}".strip().lower()
    normalized_reason = (
        unicodedata.normalize("NFKD", reason).encode("ascii", "ignore").decode("ascii")
    )
    if "brevo_api_key ayari eksik" in normalized_reason:
        return "Doğrulama e-postası gönderilemedi. Brevo API anahtarı eksik."
    if "brevo api hatasi" in normalized_reason and "401" in normalized_reason:
        return "Doğrulama e-postası gönderilemedi. Brevo API anahtarı geçersiz görünüyor."
    if "brevo api hatasi" in normalized_reason and "sender" in normalized_reason:
        return "Doğrulama e-postası gönderilemedi. Gönderen e-posta adresi Brevo içinde doğrulanmamış görünüyor."
    if (
        ("smtp ayar" in normalized_reason and "eksik" in normalized_reason)
        or "default_from_email ayari gecersiz" in normalized_reason
    ):
        return "Doğrulama e-postası gönderilemedi. Sunucudaki e-posta ayarları eksik veya hatalı."
    if isinstance(exc, smtplib.SMTPAuthenticationError) or "authentication" in normalized_reason or "535" in normalized_reason:
        return "Doğrulama e-postası gönderilemedi. SMTP giriş bilgileri hatalı görünüyor."
    if isinstance(exc, smtplib.SMTPSenderRefused) or "sender" in normalized_reason or "from address" in normalized_reason:
        return "Doğrulama e-postası gönderilemedi. Gönderen e-posta adresi henüz doğrulanmamış görünüyor."
    if (
        isinstance(exc, (socket.timeout, TimeoutError, smtplib.SMTPConnectError, requests.Timeout))
        or "timed out" in normalized_reason
    ):
        if getattr(settings, "RENDER_EXTERNAL_HOSTNAME", "") and not str(getattr(settings, "BREVO_API_KEY", "") or "").strip():
            return "Doğrulama e-postası gönderilemedi. Render üzerinde SMTP bağlantısı zaman aşımına uğradı. Brevo API anahtarı ekleyip HTTPS üzerinden gönderim yapın."
        return "Doğrulama e-postası gönderilemedi. E-posta sunucusuna bağlanılamadı."
    if settings.DEBUG:
        return f"Doğrulama e-postası gönderilemedi. Teknik neden: {type(exc).__name__}: {exc}"
    return "Doğrulama e-postası gönderilemedi. Lütfen daha sonra tekrar deneyin."


def get_password_reset_email_delivery_error_message(exc):
    reason = f"{type(exc).__name__}: {exc}".strip().lower()
    normalized_reason = unicodedata.normalize("NFKD", reason).encode("ascii", "ignore").decode("ascii")
    if "brevo_api_key ayari eksik" in normalized_reason:
        return "Sifre sifirlama e-postasi gonderilemedi. Brevo API anahtari eksik."
    if "brevo api hatasi" in normalized_reason and "401" in normalized_reason:
        return "Sifre sifirlama e-postasi gonderilemedi. Brevo API anahtari gecersiz gorunuyor."
    if "brevo api hatasi" in normalized_reason and "sender" in normalized_reason:
        return "Sifre sifirlama e-postasi gonderilemedi. Gonderen e-posta adresi Brevo icinde dogrulanmamis gorunuyor."
    if (
        ("smtp ayar" in normalized_reason and "eksik" in normalized_reason)
        or "default_from_email ayari gecersiz" in normalized_reason
    ):
        return "Sifre sifirlama e-postasi gonderilemedi. Sunucudaki e-posta ayarlari eksik veya hatali."
    if isinstance(exc, smtplib.SMTPAuthenticationError) or "authentication" in normalized_reason or "535" in normalized_reason:
        return "Sifre sifirlama e-postasi gonderilemedi. SMTP giris bilgileri hatali gorunuyor."
    if isinstance(exc, smtplib.SMTPSenderRefused) or "sender" in normalized_reason or "from address" in normalized_reason:
        return "Sifre sifirlama e-postasi gonderilemedi. Gonderen e-posta adresi henuz dogrulanmamis gorunuyor."
    if (
        isinstance(exc, (socket.timeout, TimeoutError, smtplib.SMTPConnectError, requests.Timeout))
        or "timed out" in normalized_reason
    ):
        if getattr(settings, "RENDER_EXTERNAL_HOSTNAME", "") and not str(getattr(settings, "BREVO_API_KEY", "") or "").strip():
            return "Sifre sifirlama e-postasi gonderilemedi. Render uzerinde SMTP baglantisi zaman asimina ugradi. Brevo API anahtari ekleyip HTTPS uzerinden gonderim yapin."
        return "Sifre sifirlama e-postasi gonderilemedi. E-posta sunucusuna baglanilamadi."
    if settings.DEBUG:
        return f"Sifre sifirlama e-postasi gonderilemedi. Teknik neden: {type(exc).__name__}: {exc}"
    return "Sifre sifirlama e-postasi gonderilemedi. Lutfen daha sonra tekrar deneyin."


def log_signup_email_delivery_failure(request, *, email, purpose, exc):
    logger.exception(
        "Signup verification email could not be sent",
        extra={
            "signup_email": normalize_signup_email(email),
            "signup_purpose": purpose,
            "request_path": getattr(request, "path", ""),
        },
    )
    if not getattr(settings, "ERROR_LOGGING_ENABLED", True):
        return

    try:
        traceback_max_chars = max(500, int(getattr(settings, "ERROR_LOG_TRACEBACK_MAX_CHARS", 12000)))
        message_max_chars = max(80, int(getattr(settings, "ERROR_LOG_MESSAGE_MAX_CHARS", 500)))
        raw_traceback = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
        request_id = request.headers.get("X-Request-ID", "")[:120]
        detail = (
            f"Kayıt doğrulama e-postası gönderilemedi "
            f"({purpose}, {normalize_signup_email(email)}): {type(exc).__name__}: {exc}"
        )
        ErrorLog.objects.create(
            path=(request.path or "")[:300],
            method=(request.method or "")[:10],
            status_code=500,
            message=detail[:message_max_chars],
            traceback=raw_traceback[:traceback_max_chars],
            request_id=request_id,
            ip_address=extract_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:255],
            user=user,
        )
    except Exception:
        logger.exception("Signup email failure could not be persisted to ErrorLog")


def log_password_reset_email_delivery_failure(request, *, email, exc):
    logger.exception(
        "Password reset email could not be sent",
        extra={
            "password_reset_email": normalize_signup_email(email),
            "request_path": getattr(request, "path", ""),
        },
    )
    if not getattr(settings, "ERROR_LOGGING_ENABLED", True):
        return

    try:
        traceback_max_chars = max(500, int(getattr(settings, "ERROR_LOG_TRACEBACK_MAX_CHARS", 12000)))
        message_max_chars = max(80, int(getattr(settings, "ERROR_LOG_MESSAGE_MAX_CHARS", 500)))
        raw_traceback = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
        request_id = request.headers.get("X-Request-ID", "")[:120]
        detail = (
            f"Sifre sifirlama e-postasi gonderilemedi "
            f"({normalize_signup_email(email)}): {type(exc).__name__}: {exc}"
        )
        ErrorLog.objects.create(
            path=(request.path or "")[:300],
            method=(request.method or "")[:10],
            status_code=500,
            message=detail[:message_max_chars],
            traceback=raw_traceback[:traceback_max_chars],
            request_id=request_id,
            ip_address=extract_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:255],
            user=user,
        )
    except Exception:
        logger.exception("Password reset email failure could not be persisted to ErrorLog")


def issue_signup_verification_code(email, purpose):
    normalized_email = normalize_signup_email(email)
    now = timezone.now()
    code = generate_email_verification_code()
    verification = EmailVerificationCode.objects.create(
        email=normalized_email,
        purpose=purpose,
        code_hash=hash_email_verification_code(normalized_email, purpose, code),
        expires_at=now + timedelta(minutes=get_email_verification_code_ttl_minutes()),
    )
    try:
        send_signup_verification_email(normalized_email, code, purpose=purpose)
    except Exception:
        verification.delete()
        raise

    EmailVerificationCode.objects.filter(
        email__iexact=normalized_email,
        purpose=purpose,
        consumed_at__isnull=True,
    ).exclude(id=verification.id).update(consumed_at=now)
    return verification


def create_account_from_pending_signup(payload):
    purpose = str(payload.get("purpose") or "").strip()
    meta = get_signup_verification_meta(purpose)
    account_type = meta["account_type"]
    username = str(payload.get("username") or "").strip()
    email = normalize_signup_email(payload.get("email"))
    password_hash = str(payload.get("password_hash") or "").strip()

    if not username or not email or not password_hash:
        raise ValidationError("Kayıt verisi eksik. ütfen yeniden kayıt olun.")
    if User.objects.filter(username__iexact=username).exists():
        raise ValidationError("Bu kullanici adi artik kullanilamiyor. Lutfen bilgileri yeniden girin.")
    if User.objects.filter(email__iexact=email).exists():
        raise ValidationError("Bu e-posta adresi artik kullanilamiyor. Lutfen bilgileri yeniden girin.")

    with transaction.atomic():
        user = User(
            username=username,
            email=email,
            first_name=str(payload.get("first_name") or "").strip(),
            last_name=str(payload.get("last_name") or "").strip(),
        )
        user.password = password_hash
        user.save()

        if account_type == "customer":
            CustomerProfile.objects.update_or_create(
                user=user,
                defaults={
                    "phone": str(payload.get("phone") or "").strip(),
                    "city": str(payload.get("city") or "").strip(),
                    "district": str(payload.get("district") or "").strip(),
                },
            )
            return user

        service_type_ids = [int(value) for value in payload.get("service_type_ids") or [] if str(value).isdigit()]
        service_types = list(ServiceType.objects.filter(id__in=service_type_ids))
        if len(service_types) != len(service_type_ids):
            raise ValidationError("Seçilen hizmetler doğrulanamadı. Lutfen yeniden kayıt olun.")

        provider = Provider.objects.create(
            user=user,
            full_name=str(payload.get("full_name") or "").strip(),
            city=str(payload.get("city") or "").strip(),
            district=str(payload.get("district") or "").strip(),
            phone=str(payload.get("phone") or "").strip(),
            description=str(payload.get("description") or "").strip(),
            is_verified=False,
            is_available=True,
        )
        provider.service_types.set(service_types)
        return user


def begin_signup_verification(request, pending_payload):
    set_pending_signup_payload(request, pending_payload)
    try:
        verification = issue_signup_verification_code(
            pending_payload.get("email"),
            pending_payload.get("purpose"),
        )
    except Exception:
        clear_pending_signup_payload(request)
        raise
    return verification


def get_offer_expiry_minutes():
    return max(1, int(getattr(settings, "OFFER_EXPIRY_MINUTES", 180)))


def get_offer_reminder_minutes():
    return max(1, int(getattr(settings, "OFFER_REMINDER_MINUTES", 60)))


def get_appointment_provider_confirm_minutes():
    return max(1, int(getattr(settings, "APPOINTMENT_PROVIDER_CONFIRM_MINUTES", 720)))


def get_appointment_customer_confirm_minutes():
    return max(1, int(getattr(settings, "APPOINTMENT_CUSTOMER_CONFIRM_MINUTES", 720)))


def get_appointment_min_lead_minutes():
    return max(1, int(getattr(settings, "APPOINTMENT_MIN_LEAD_MINUTES", 5)))


def get_last_minute_cancel_hours():
    return max(1, int(getattr(settings, "APPOINTMENT_LAST_MINUTE_CANCEL_HOURS", 6)))


def get_no_show_grace_minutes():
    return max(0, int(getattr(settings, "APPOINTMENT_NO_SHOW_GRACE_MINUTES", 30)))


def get_short_note_max_chars():
    configured = int(getattr(settings, "SHORT_NOTE_MAX_CHARS", 100))
    return max(20, min(240, configured))


def evaluate_appointment_cancel_policy(appointment, *, now=None):
    reference_time = now or timezone.now()
    if not appointment or not appointment.scheduled_for:
        return {
            "category": "standard",
            "minutes_to_start": None,
            "ui_note": "",
            "result_message": "Randevu iptal edildi.",
            "workflow_suffix": "",
        }

    minutes_to_start = int((appointment.scheduled_for - reference_time).total_seconds() // 60)
    last_minute_window_minutes = get_last_minute_cancel_hours() * 60
    no_show_grace_minutes = get_no_show_grace_minutes()

    if minutes_to_start <= -no_show_grace_minutes:
        return {
            "category": "no_show",
            "minutes_to_start": minutes_to_start,
            "ui_note": (
                "No-show politikasi: Randevu saatinden sonra uzun gecikmeli iptaller no-show olarak kaydedilir."
            ),
            "result_message": (
                "Randevu iptal edildi. Bu işlem no-show politikası kapsamında kayıt altına alındı."
            ),
            "workflow_suffix": f"No-show kaydi (randevu saatinden {abs(minutes_to_start)} dk sonra iptal).",
        }

    if minutes_to_start <= last_minute_window_minutes:
        if minutes_to_start >= 0:
            timing_note = f"Randevuya {minutes_to_start} dk kala"
        else:
            timing_note = f"Randevu saatinden {abs(minutes_to_start)} dk sonra"
        return {
            "category": "last_minute",
            "minutes_to_start": minutes_to_start,
            "ui_note": (
                f"Son dakika iptal politikasi: Randevuya {get_last_minute_cancel_hours()} saatten az kala iptaller "
                "son dakika iptali olarak kaydedilir."
            ),
            "result_message": "Randevu iptal edildi. Son dakika iptal kaydi oluşturuldu.",
            "workflow_suffix": f"Son dakika iptali ({timing_note}).",
        }

    return {
        "category": "standard",
        "minutes_to_start": minutes_to_start,
        "ui_note": "",
        "result_message": "Randevu iptal edildi.",
        "workflow_suffix": "",
    }




def get_login_rate_limit_max_attempts():
    return max(1, int(getattr(settings, "LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 15)))


def get_login_rate_limit_window_seconds():
    return max(10, int(getattr(settings, "LOGIN_RATE_LIMIT_WINDOW_SECONDS", 60)))


def get_action_rate_limit_max_attempts():
    return max(1, int(getattr(settings, "ACTION_RATE_LIMIT_MAX_ATTEMPTS", 40)))


def get_action_rate_limit_window_seconds():
    return max(10, int(getattr(settings, "ACTION_RATE_LIMIT_WINDOW_SECONDS", 60)))


def get_create_request_rate_limit_max_attempts():
    configured = max(
        1,
        int(getattr(settings, "CREATE_REQUEST_RATE_LIMIT_MAX_ATTEMPTS", get_action_rate_limit_max_attempts())),
    )
    return min(configured, get_action_rate_limit_max_attempts())


def get_create_request_rate_limit_window_seconds():
    configured = max(
        10,
        int(getattr(settings, "CREATE_REQUEST_RATE_LIMIT_WINDOW_SECONDS", get_action_rate_limit_window_seconds())),
    )
    return max(configured, get_action_rate_limit_window_seconds())


def get_create_request_daily_limit():
    return max(1, int(getattr(settings, "CREATE_REQUEST_DAILY_LIMIT", 20)))


def get_create_request_open_limit():
    return max(1, int(getattr(settings, "CREATE_REQUEST_OPEN_LIMIT", 8)))


def get_create_request_ip_daily_limit():
    return max(1, int(getattr(settings, "CREATE_REQUEST_IP_DAILY_LIMIT", 80)))


def get_create_request_ip_burst_limit():
    return max(1, int(getattr(settings, "CREATE_REQUEST_IP_BURST_LIMIT", 15)))


def get_create_request_ip_burst_window_seconds():
    return max(60, int(getattr(settings, "CREATE_REQUEST_IP_BURST_WINDOW_SECONDS", 600)))


def get_create_request_duplicate_cooldown_seconds():
    return max(10, int(getattr(settings, "CREATE_REQUEST_DUPLICATE_COOLDOWN_SECONDS", 300)))


def get_create_request_min_interval_seconds():
    return max(5, int(getattr(settings, "CREATE_REQUEST_MIN_INTERVAL_SECONDS", 30)))


def get_post_idempotency_ttl_seconds():
    return max(3, int(getattr(settings, "POST_IDEMPOTENCY_TTL_SECONDS", 10)))


def get_lifecycle_heartbeat_stale_seconds():
    return max(10, int(getattr(settings, "LIFECYCLE_HEARTBEAT_STALE_SECONDS", 180)))


def get_nav_stream_reopen_min_seconds():
    return max(1, int(getattr(settings, "NAV_STREAM_REOPEN_MIN_SECONDS", 2)))


def get_request_messages_fallback_poll_interval_seconds():
    return max(3, int(getattr(settings, "REQUEST_MESSAGES_FALLBACK_POLL_INTERVAL_SECONDS", 5)))


def get_lifecycle_web_refresh_interval_seconds():
    return max(5, int(getattr(settings, "MARKETPLACE_LIFECYCLE_WEB_REFRESH_INTERVAL_SECONDS", 20)))


def get_housekeeping_interval_seconds():
    return max(60, int(getattr(settings, "HOUSEKEEPING_INTERVAL_SECONDS", 3600)))


def get_idempotency_retention_days():
    return max(1, int(getattr(settings, "IDEMPOTENCY_RETENTION_DAYS", 2)))


def get_workflow_event_retention_days():
    return max(7, int(getattr(settings, "WORKFLOW_EVENT_RETENTION_DAYS", 30)))


def get_activity_log_retention_days():
    return max(7, int(getattr(settings, "ACTIVITY_LOG_RETENTION_DAYS", 90)))


def get_error_log_retention_days():
    return max(7, int(getattr(settings, "ERROR_LOG_RETENTION_DAYS", 30)))


def get_message_retention_days():
    configured = int(getattr(settings, "MESSAGE_RETENTION_DAYS", 45))
    minimum = max(get_notification_retention_days(), 30)
    return max(minimum, configured)


def get_lifecycle_health_token():
    return str(getattr(settings, "LIFECYCLE_HEALTH_TOKEN", "") or "").strip()


def infer_actor_role(user):
    if not user or not getattr(user, "is_authenticated", False):
        return "system"
    return "provider" if get_provider_for_user(user) else "customer"


def get_client_ip(request):
    forwarded_for = (request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or "unknown"
    return (request.META.get("REMOTE_ADDR") or "").strip() or "unknown"


def normalize_request_text(value):
    return " ".join(str(value or "").strip().lower().split())


def normalize_request_phone(value):
    return "".join(char for char in str(value or "") if char.isdigit())[:14]


def build_create_request_fingerprint(*, identity, customer_name, customer_phone, service_type, city, district, details):
    normalized_identity = str(identity or "").strip().lower()
    payload = {
        "customer_name": normalize_request_text(customer_name),
        "customer_phone": normalize_request_phone(customer_phone),
        "service_type": str(service_type or "").strip(),
        "city": normalize_request_text(city),
        "district": normalize_request_text(district),
        "details": normalize_request_text(details)[:260],
    }
    if not normalized_identity or not any(payload.values()):
        return ""
    raw_key = json.dumps({"identity": normalized_identity, "payload": payload}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def reject_create_request_abuse(request, redirect_name, *, cleaned_data):
    if request.method != "POST":
        return None

    now = timezone.now()
    ip_address = get_client_ip(request)[:64]
    user = request.user if request.user.is_authenticated else None
    min_interval_seconds = get_create_request_min_interval_seconds()
    if user and user.id:
        open_request_count = ServiceRequest.objects.filter(
            customer=user,
            status__in=["new", "pending_provider", "pending_customer", "matched"],
        ).count()
        if open_request_count >= get_create_request_open_limit():
            messages.warning(
                request,
                "Çok fazla açık talebiniz var. Önce mevcut talepleri tamamlayın veya iptal edin.",
            )
            return redirect(redirect_name)

        recent_count = ServiceRequest.objects.filter(customer=user, created_at__gte=now - timedelta(days=1)).count()
        if recent_count >= get_create_request_daily_limit():
            messages.warning(
                request,
                "Günlük talep sınırına ulaştınız. Lütfen bir süre sonra tekrar deneyin.",
            )
            return redirect(redirect_name)
        latest_request_at = (
            ServiceRequest.objects.filter(customer=user)
            .order_by("-created_at")
            .values_list("created_at", flat=True)
            .first()
        )
        if latest_request_at:
            elapsed_seconds = int((now - latest_request_at).total_seconds())
            if elapsed_seconds < min_interval_seconds:
                wait_seconds = max(1, min_interval_seconds - elapsed_seconds)
                messages.warning(
                    request,
                    f"Yeni talep açmadan önce {wait_seconds} saniye bekleyin.",
                )
                return redirect(redirect_name)

    ip_daily_count = ServiceRequest.objects.filter(created_ip=ip_address, created_at__gte=now - timedelta(days=1)).count()
    if ip_daily_count >= get_create_request_ip_daily_limit():
        messages.warning(
            request,
            "Bu ağdan günlük talep sınırına ulaşıldı. Lütfen daha sonra tekrar deneyin.",
        )
        return redirect(redirect_name)

    ip_burst_count = ServiceRequest.objects.filter(
        created_ip=ip_address,
        created_at__gte=now - timedelta(seconds=get_create_request_ip_burst_window_seconds()),
    ).count()
    if ip_burst_count >= get_create_request_ip_burst_limit():
        messages.warning(
            request,
            "Bu agdan cok kisa surede cok fazla talep gonderildi. Lutfen daha sonra tekrar deneyin.",
        )
        return redirect(redirect_name)

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
    cooldown_seconds = get_create_request_duplicate_cooldown_seconds()
    if fingerprint:
        duplicate_exists = ServiceRequest.objects.filter(
            request_fingerprint=fingerprint,
            created_at__gte=now - timedelta(seconds=cooldown_seconds),
        ).exists()
        if duplicate_exists:
            messages.warning(
                request,
                "Aynı içerikte talep çok sık gönderilemez. Lütfen kısa bir süre sonra tekrar deneyin.",
            )
            return redirect(redirect_name)
        request._create_request_fingerprint = fingerprint
    return None


def reject_rate_limited_request(request, scope, redirect_name, *, max_attempts, window_seconds, identity=""):
    if request.method != "POST":
        return None

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
        messages.warning(
            request,
            f"Çok kısa sürede çok fazla istek gönderdiniz. Lütfen {window_seconds} saniye sonra tekrar deneyin.",
        )
        return redirect(redirect_name)
    return None


def create_workflow_event(
    instance,
    *,
    from_status,
    to_status,
    actor_user=None,
    actor_role="system",
    source="system",
    note="",
):
    note_text = (note or "")[:240]
    if isinstance(instance, ServiceRequest):
        WorkflowEvent.objects.create(
            target_type="request",
            service_request=instance,
            appointment=None,
            from_status=from_status,
            to_status=to_status,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note_text,
        )
        create_activity_log(
            action_type="request_status",
            service_request=instance,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            summary=f"Talep durumu: {from_status} -> {to_status}",
            note=note_text,
        )
        invalidate_notification_cache_for_instance(instance, actor_user=actor_user)
        return

    if isinstance(instance, ServiceAppointment):
        WorkflowEvent.objects.create(
            target_type="appointment",
            service_request=instance.service_request if instance.service_request_id else None,
            appointment=instance,
            from_status=from_status,
            to_status=to_status,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note_text,
        )
        create_activity_log(
            action_type="appointment_status",
            service_request=instance.service_request if instance.service_request_id else None,
            appointment=instance,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            summary=f"Randevu durumu: {from_status} -> {to_status}",
            note=note_text,
        )
        invalidate_notification_cache_for_instance(instance, actor_user=actor_user)


def create_activity_log(
    *,
    action_type,
    service_request=None,
    appointment=None,
    message_item=None,
    actor_user=None,
    actor_role="system",
    source="system",
    summary="",
    note="",
):
    activity_log = ActivityLog.objects.create(
        action_type=action_type,
        service_request=service_request,
        appointment=appointment,
        message=message_item,
        actor_user=actor_user,
        actor_role=actor_role,
        source=source,
        summary=(summary or "")[:240],
        note=(note or "")[:240],
    )
    queue_mobile_push_for_activity(activity_log.id)
    return activity_log


def maybe_run_housekeeping(*, now=None, force=False):
    reference = now or timezone.now()
    run_interval_seconds = get_housekeeping_interval_seconds()
    cache_key = "housekeeping:last-run"
    lock_key = "housekeeping:lock"

    if not force:
        last_run_ts = cache.get(cache_key)
        now_ts = int(reference.timestamp())
        if isinstance(last_run_ts, int) and now_ts - last_run_ts < run_interval_seconds:
            return False

    if not cache.add(lock_key, str(uuid4()), timeout=120):
        return False

    try:
        now_ts = int(reference.timestamp())
        if not force:
            last_run_ts = cache.get(cache_key)
            if isinstance(last_run_ts, int) and now_ts - last_run_ts < run_interval_seconds:
                return False

        IdempotencyRecord.objects.filter(
            created_at__lt=reference - timedelta(days=get_idempotency_retention_days())
        ).delete()
        WorkflowEvent.objects.filter(
            created_at__lt=reference - timedelta(days=get_workflow_event_retention_days())
        ).delete()
        ActivityLog.objects.filter(
            created_at__lt=reference - timedelta(days=get_activity_log_retention_days())
        ).delete()
        ErrorLog.objects.filter(
            created_at__lt=reference - timedelta(days=get_error_log_retention_days())
        ).delete()
        ServiceMessage.objects.filter(
            read_at__isnull=False,
            created_at__lt=reference - timedelta(days=get_message_retention_days()),
        ).delete()
        cache.set(cache_key, now_ts, timeout=run_interval_seconds)
        return True
    finally:
        cache.delete(lock_key)


def reject_duplicate_submission(request, scope, redirect_name):
    if request.method != "POST":
        return None

    if not request.session.session_key:
        request.session.save()
    session_key = request.session.session_key or "no-session"
    user_id = request.user.id if request.user.is_authenticated else None
    identity = f"user:{user_id}" if user_id else f"session:{session_key}"

    payload = {}
    for key in sorted(request.POST.keys()):
        if key in {"csrfmiddlewaretoken", "idempotency_key"}:
            continue
        payload[key] = request.POST.getlist(key)
    explicit_key = (request.POST.get("idempotency_key") or request.headers.get("X-Idempotency-Key") or "").strip()
    ttl_seconds = get_post_idempotency_ttl_seconds()
    window = int(timezone.now().timestamp() // ttl_seconds)
    raw_key = json.dumps(
        {
            "scope": scope,
            "endpoint": request.path,
            "identity": identity,
            "window": window,
            "payload": payload,
            "explicit": explicit_key,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    dedupe_key = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    now = timezone.now()
    try:
        with transaction.atomic():
            IdempotencyRecord.objects.create(
                key=dedupe_key,
                scope=scope[:80],
                endpoint=request.path[:200],
                user=request.user if request.user.is_authenticated else None,
            )
    except IntegrityError:
        messages.info(request, "Aynı işlem kısa aralıkta tekrar gönderildiği için tek sefer işlendi.")
        return redirect(redirect_name)

    maybe_run_housekeeping(now=now)
    return None


SERVICE_REQUEST_ALLOWED_TRANSITIONS = {
    "new": {"pending_provider", "cancelled"},
    "pending_provider": {"pending_customer", "matched", "new", "cancelled"},
    "pending_customer": {"pending_provider", "matched", "new", "cancelled"},
    "matched": {"completed", "cancelled", "pending_provider", "pending_customer", "new"},
    "completed": set(),
    "cancelled": set(),
}

SERVICE_APPOINTMENT_ALLOWED_TRANSITIONS = {
    "pending": {"pending_customer", "confirmed", "rejected", "cancelled", "completed"},
    "pending_customer": {"confirmed", "cancelled", "pending", "completed"},
    "confirmed": {"completed", "cancelled", "pending"},
    "rejected": {"pending"},
    "cancelled": {"pending"},
    "completed": set(),
}


def transition_model_status(
    instance,
    next_status,
    allowed_transitions,
    extra_update_fields=None,
    *,
    actor_user=None,
    actor_role="system",
    source="system",
    note="",
):
    current_status = instance.status
    changed = current_status != next_status
    if current_status != next_status:
        allowed_targets = allowed_transitions.get(current_status, set())
        if next_status not in allowed_targets:
            return False
        instance.status = next_status

    if extra_update_fields is None:
        if changed:
            instance.save(update_fields=["status"])
        if changed:
            create_workflow_event(
                instance,
                from_status=current_status,
                to_status=next_status,
                actor_user=actor_user,
                actor_role=actor_role,
                source=source,
                note=note,
            )
        return True

    update_fields = list(extra_update_fields)
    if changed:
        update_fields = ["status", *update_fields]
    update_fields = list(dict.fromkeys(update_fields))
    if update_fields:
        instance.save(update_fields=update_fields)
    if changed:
        create_workflow_event(
            instance,
            from_status=current_status,
            to_status=next_status,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note,
        )
    return True


def transition_service_request_status(
    service_request,
    next_status,
    extra_update_fields=None,
    *,
    actor_user=None,
    actor_role="system",
    source="system",
    note="",
):
    return transition_model_status(
        service_request,
        next_status,
        SERVICE_REQUEST_ALLOWED_TRANSITIONS,
        extra_update_fields=extra_update_fields,
        actor_user=actor_user,
        actor_role=actor_role,
        source=source,
        note=note,
    )


def transition_appointment_status(
    appointment,
    next_status,
    extra_update_fields=None,
    *,
    actor_user=None,
    actor_role="system",
    source="system",
    note="",
):
    return transition_model_status(
        appointment,
        next_status,
        SERVICE_APPOINTMENT_ALLOWED_TRANSITIONS,
        extra_update_fields=extra_update_fields,
        actor_user=actor_user,
        actor_role=actor_role,
        source=source,
        note=note,
    )




def refresh_offer_lifecycle():
    now = timezone.now()
    expired_request_ids = set()
    expiry_minutes = get_offer_expiry_minutes()

    pending_without_expiry = list(
        ProviderOffer.objects.filter(status="pending", expires_at__isnull=True).only("id", "sent_at")
    )
    for offer in pending_without_expiry:
        base_time = offer.sent_at or now
        offer.expires_at = base_time + timedelta(minutes=expiry_minutes)
        offer.save(update_fields=["expires_at"])

    expired_qs = ProviderOffer.objects.filter(status="pending", expires_at__isnull=False, expires_at__lte=now)
    expired_request_ids.update(expired_qs.values_list("service_request_id", flat=True))
    expired_qs.update(status="expired", responded_at=now)

    # Providers who are no longer eligible for new work must never stay in offer flow.
    eligible_provider_ids = Provider.objects.accepting_new_requests(now=now).values_list("id", flat=True)
    ineligible_offer_qs = ProviderOffer.objects.filter(status__in=["pending", "accepted"]).exclude(
        provider_id__in=eligible_provider_ids
    )
    expired_request_ids.update(ineligible_offer_qs.values_list("service_request_id", flat=True))
    ineligible_offer_qs.update(status="expired", responded_at=now)

    reminder_deadline = now + timedelta(minutes=get_offer_reminder_minutes())
    reminder_qs = list(
        ProviderOffer.objects.filter(
            status="pending",
            expires_at__isnull=False,
            expires_at__gt=now,
            expires_at__lte=reminder_deadline,
            reminder_sent_at__isnull=True,
        ).select_related("provider", "service_request", "service_request__service_type")
    )
    for offer in reminder_qs:
        offer.reminder_sent_at = now
        offer.save(update_fields=["reminder_sent_at"])

    matched_unverified_requests = list(
        ServiceRequest.objects.filter(status="matched", matched_provider__is_verified=False).select_related("service_type")
    )
    for service_request in matched_unverified_requests:
        open_appointments = ServiceAppointment.objects.filter(
            service_request=service_request,
            status__in=["pending", "pending_customer", "confirmed"],
        )
        for appointment in open_appointments:
            transition_appointment_status(
                appointment,
                "cancelled",
                extra_update_fields=["updated_at"],
                actor_role="system",
                source="scheduler",
                note="Usta admin onaylı olmadığı için randevu kapatıldı",
            )

        service_request.matched_provider = None
        service_request.matched_offer = None
        service_request.matched_at = None

        has_accepted = service_request.provider_offers.filter(status="accepted", provider__is_verified=True).exists()
        has_pending = service_request.provider_offers.filter(status="pending", provider__is_verified=True).exists()
        next_status = "new"
        if has_accepted:
            next_status = "pending_customer"
        elif has_pending:
            next_status = "pending_provider"

        if transition_service_request_status(
            service_request,
            next_status,
            extra_update_fields=["matched_provider", "matched_offer", "matched_at"],
            actor_role="system",
            source="scheduler",
            note="Usta admin onaylı olmadığı için eşleşme kaldırıldı",
        ) and next_status == "new":
            dispatch_next_provider_offer(
                service_request,
                actor_role="system",
                source="scheduler",
                note="Onaysız usta eşleşmesi kaldırıldı, yeni aday arandı",
            )

    if not expired_request_ids:
        return

    impacted_requests = list(ServiceRequest.objects.filter(id__in=expired_request_ids).select_related("service_type"))
    for service_request in impacted_requests:
        if service_request.status in {"matched", "completed", "cancelled"} or service_request.matched_provider_id:
            continue

        has_pending = service_request.provider_offers.filter(status="pending", provider__is_verified=True).exists()
        has_accepted = service_request.provider_offers.filter(status="accepted", provider__is_verified=True).exists()
        if has_accepted:
            if service_request.status != "pending_customer":
                transition_service_request_status(
                    service_request,
                    "pending_customer",
                    actor_role="system",
                    source="scheduler",
                    note="Teklif süre sonu kontrolü",
                )
            continue
        if has_pending:
            if service_request.status != "pending_provider":
                transition_service_request_status(
                    service_request,
                    "pending_provider",
                    actor_role="system",
                    source="scheduler",
                    note="Teklif süre sonu kontrolü",
                )
            continue
        dispatch_next_provider_offer(
            service_request,
            actor_role="system",
            source="scheduler",
            note="Tüm bekleyen teklifler süre doldu",
        )


def refresh_appointment_lifecycle():
    now = timezone.now()
    provider_deadline = now - timedelta(minutes=get_appointment_provider_confirm_minutes())
    customer_deadline = now - timedelta(minutes=get_appointment_customer_confirm_minutes())

    stale_provider_appointments = list(
        ServiceAppointment.objects.filter(status="pending", created_at__lte=provider_deadline).select_related(
            "service_request",
            "provider",
        )
    )
    for appointment in stale_provider_appointments:
        if not transition_appointment_status(
            appointment,
            "cancelled",
            extra_update_fields=["updated_at"],
            actor_role="system",
            source="scheduler",
            note="Usta onay süresi doldu",
        ):
            continue

    stale_customer_appointments = list(
        ServiceAppointment.objects.filter(status="pending_customer", updated_at__lte=customer_deadline).select_related(
            "service_request",
            "provider",
        )
    )
    for appointment in stale_customer_appointments:
        if not transition_appointment_status(
            appointment,
            "cancelled",
            extra_update_fields=["updated_at"],
            actor_role="system",
            source="scheduler",
            note="Müşteri onay süresi doldu",
        ):
            continue


def refresh_marketplace_lifecycle(*, force=False):
    reference = timezone.now()
    maybe_run_housekeeping(now=reference)

    if force:
        refresh_offer_lifecycle()
        refresh_appointment_lifecycle()
        return True

    min_interval_seconds = get_lifecycle_web_refresh_interval_seconds()
    cache_key = "lifecycle:web:last-run"
    lock_key = "lifecycle:web:lock"
    now_ts = int(reference.timestamp())
    last_run_ts = cache.get(cache_key)
    if isinstance(last_run_ts, int) and now_ts - last_run_ts < min_interval_seconds:
        return False

    if not cache.add(lock_key, str(uuid4()), timeout=max(5, min_interval_seconds)):
        return False

    try:
        last_run_ts = cache.get(cache_key)
        if isinstance(last_run_ts, int) and now_ts - last_run_ts < min_interval_seconds:
            return False

        refresh_offer_lifecycle()
        refresh_appointment_lifecycle()
        cache.set(cache_key, now_ts, timeout=min_interval_seconds)
        return True
    finally:
        cache.delete(lock_key)


def maybe_refresh_marketplace_lifecycle_from_request():
    if not request_lifecycle_refresh_enabled():
        return False
    return refresh_marketplace_lifecycle()


def build_unread_message_map(service_request_ids, viewer_role):
    if not service_request_ids:
        return {}
    unread_rows = (
        ServiceMessage.objects.filter(service_request_id__in=service_request_ids, read_at__isnull=True)
        .exclude(sender_role=viewer_role)
        .values("service_request_id")
        .annotate(total=Count("id"))
    )
    return {row["service_request_id"]: row["total"] for row in unread_rows}


def build_latest_incoming_message_map(service_request_ids, viewer_role):
    if not service_request_ids:
        return {}
    latest_map = {}
    message_rows = (
        ServiceMessage.objects.filter(service_request_id__in=service_request_ids)
        .exclude(sender_role=viewer_role)
        .order_by("-created_at", "-id")
    )
    for row in message_rows:
        if row.service_request_id not in latest_map:
            latest_map[row.service_request_id] = row
    return latest_map


def build_latest_workflow_event_map(service_request_ids, actor_user):
    if not service_request_ids:
        return {}
    latest_map = {}
    event_rows = (
        WorkflowEvent.objects.filter(
            Q(service_request_id__in=service_request_ids)
            | Q(appointment__service_request_id__in=service_request_ids)
        )
        .exclude(actor_user=actor_user)
        .select_related("appointment")
        .order_by("-created_at", "-id")
    )
    for row in event_rows:
        service_request_id = row.service_request_id or getattr(row.appointment, "service_request_id", None)
        if service_request_id and service_request_id not in latest_map:
            latest_map[service_request_id] = row
    return latest_map


def get_customer_snapshot_cache_seconds():
    return max(1, int(getattr(settings, "CUSTOMER_SNAPSHOT_CACHE_SECONDS", 3)))


def get_provider_snapshot_cache_seconds():
    return max(1, int(getattr(settings, "PROVIDER_SNAPSHOT_CACHE_SECONDS", 3)))


def build_customer_requests_signature(user):
    if not user or not getattr(user, "is_authenticated", False):
        return "empty"

    request_rows = list(
        ServiceRequest.objects.filter(customer=user)
        .values_list("id", "status", "matched_provider_id", "matched_offer_id", "matched_at")
        .order_by("id")
    )
    if not request_rows:
        return "empty"

    offer_rows = list(
        ProviderOffer.objects.filter(
            service_request__customer=user,
            provider_id__in=Provider.objects.accepting_new_requests().values("id"),
        )
        .values_list("service_request_id", "provider_id", "status", "responded_at")
        .order_by("service_request_id", "provider_id")
    )
    appointment_rows = []
    if is_calendar_enabled():
        appointment_rows = list(
            ServiceAppointment.objects.filter(service_request__customer=user)
            .values_list("service_request_id", "status", "scheduled_for", "updated_at")
            .order_by("service_request_id")
        )
    rating_rows = list(
        ProviderRating.objects.filter(service_request__customer=user)
        .values_list("service_request_id", "score", "updated_at")
        .order_by("service_request_id")
    )
    unread_rows = list(
        ServiceMessage.objects.filter(service_request__customer=user, read_at__isnull=True)
        .exclude(sender_role="customer")
        .values("service_request_id")
        .annotate(total=Count("id"))
        .order_by("service_request_id")
    )
    payload = {
        "requests": request_rows,
        "offers": offer_rows,
        "appointments": appointment_rows,
        "ratings": rating_rows,
        "unread": unread_rows,
    }
    encoded = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_provider_panel_signature(provider):
    if not provider:
        return "empty"

    offer_rows = list(
        ProviderOffer.objects.filter(provider=provider)
        .values_list("id", "service_request_id", "status", "responded_at", "sent_at")
        .order_by("id")
    )
    request_rows = list(
        ServiceRequest.objects.filter(provider_offers__provider=provider)
        .values_list("id", "status", "matched_provider_id", "matched_offer_id", "matched_at")
        .distinct()
        .order_by("id")
    )
    appointment_rows = []
    if is_calendar_enabled():
        appointment_rows = list(
            ServiceAppointment.objects.filter(provider=provider)
            .values_list("id", "service_request_id", "status", "scheduled_for", "updated_at")
            .order_by("id")
        )
    unread_rows = list(
        ServiceMessage.objects.filter(
            service_request__matched_provider=provider,
            service_request__status="matched",
            read_at__isnull=True,
        )
        .exclude(sender_role="provider")
        .values_list("service_request_id", "id")
        .order_by("service_request_id", "id")
    )
    payload = {
        "offers": offer_rows,
        "requests": request_rows,
        "appointments": appointment_rows,
        "unread": unread_rows,
        "membership": [
            provider.membership_status,
            provider.get_membership_state(),
            provider.membership_expires_at,
            provider.last_cash_payment_at,
            provider.is_available,
            provider.is_verified,
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_customer_snapshot_payload(user):
    snapshot = {
        "signature": "empty",
        "pending_customer_requests_count": 0,
        "matched_requests_count": 0,
        "pending_customer_appointments_count": 0,
        "confirmed_appointments_count": 0,
        "accepted_offers_count": 0,
        "unread_messages_count": 0,
        "unread_notifications_count": 0,
    }
    if not user or not getattr(user, "is_authenticated", False):
        return snapshot

    calendar_suffix = "calendar-on" if is_calendar_enabled() else "calendar-off"
    cache_key = f"snapshot:customer:{user.id}:{calendar_suffix}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        payload = dict(cached)
        payload["unread_notifications_count"] = get_total_unread_notifications_count(user)
        return payload

    request_counts = ServiceRequest.objects.filter(customer=user).aggregate(
        pending_customer_requests_count=Count("id", filter=Q(status="pending_customer")),
        matched_requests_count=Count("id", filter=Q(status="matched")),
    )
    snapshot["pending_customer_requests_count"] = int(request_counts.get("pending_customer_requests_count") or 0)
    snapshot["matched_requests_count"] = int(request_counts.get("matched_requests_count") or 0)
    if is_calendar_enabled():
        snapshot["pending_customer_appointments_count"] = ServiceAppointment.objects.filter(
            service_request__customer=user,
            status="pending_customer",
        ).count()
        snapshot["confirmed_appointments_count"] = ServiceAppointment.objects.filter(
            service_request__customer=user,
            status="confirmed",
        ).count()
    snapshot["accepted_offers_count"] = ProviderOffer.objects.filter(
        service_request__customer=user,
        status="accepted",
        provider_id__in=Provider.objects.accepting_new_requests().values("id"),
    ).count()
    snapshot["unread_messages_count"] = ServiceMessage.objects.filter(
        service_request__customer=user,
        read_at__isnull=True,
    ).exclude(sender_role="customer").count()
    snapshot["unread_notifications_count"] = get_total_unread_notifications_count(user)
    snapshot["signature"] = build_customer_requests_signature(user)
    cache.set(cache_key, snapshot, timeout=get_customer_snapshot_cache_seconds())
    return snapshot


def build_provider_snapshot_payload(provider, *, user=None):
    snapshot = {
        "signature": "empty",
        "pending_offers_count": 0,
        "latest_pending_offer_id": 0,
        "waiting_customer_selection_count": 0,
        "pending_appointments_count": 0,
        "unread_messages_count": 0,
        "unread_notifications_count": 0,
    }
    if not provider:
        return snapshot

    provider_user = user
    if provider_user is None:
        provider_user = getattr(provider, "user", None)
    if provider_user is None and getattr(provider, "user_id", None):
        provider_user = provider.user

    calendar_suffix = "calendar-on" if is_calendar_enabled() else "calendar-off"
    cache_key = f"snapshot:provider:{provider.id}:{calendar_suffix}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        payload = dict(cached)
        if provider_user and getattr(provider_user, "is_authenticated", True):
            payload["unread_notifications_count"] = get_total_unread_notifications_count(provider_user)
        return payload

    offer_counts = provider.offers.aggregate(
        pending_offers_count=Count("id", filter=Q(status="pending")),
        latest_pending_offer_id=Max("id", filter=Q(status="pending")),
        waiting_customer_selection_count=Count(
            "id",
            filter=Q(
                status="accepted",
                service_request__status="pending_customer",
                service_request__matched_provider__isnull=True,
            ),
        ),
    )
    snapshot["pending_offers_count"] = int(offer_counts.get("pending_offers_count") or 0)
    snapshot["latest_pending_offer_id"] = int(offer_counts.get("latest_pending_offer_id") or 0)
    snapshot["waiting_customer_selection_count"] = int(offer_counts.get("waiting_customer_selection_count") or 0)
    if is_calendar_enabled():
        snapshot["pending_appointments_count"] = provider.appointments.filter(status="pending").count()
    snapshot["unread_messages_count"] = ServiceMessage.objects.filter(
        service_request__matched_provider=provider,
        service_request__status="matched",
        read_at__isnull=True,
    ).exclude(sender_role="provider").count()
    snapshot["signature"] = build_provider_panel_signature(provider)
    if provider_user and getattr(provider_user, "is_authenticated", True):
        snapshot["unread_notifications_count"] = get_total_unread_notifications_count(provider_user)
    cache.set(cache_key, snapshot, timeout=get_provider_snapshot_cache_seconds())
    return snapshot


def is_panel_partial_request(request):
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        and (request.GET.get("partial") or "").strip() == "panel"
    )


def build_panel_partial_url(request):
    params = request.GET.copy()
    params["partial"] = "panel"
    return f"{request.path}?{params.urlencode()}"


def render_panel_partial_response(request, *, template_name, context, snapshot):
    html = render_to_string(template_name, context=context, request=request)
    response = JsonResponse(
        {
            "html": html,
            "snapshot": snapshot,
        }
    )
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


def purge_request_messages(service_request_id):
    ServiceMessage.objects.filter(service_request_id=service_request_id).delete()


def generate_offer_token():
    token = uuid4().hex[:10].upper()
    while ProviderOffer.objects.filter(token=token).exists():
        token = uuid4().hex[:10].upper()
    return token


def build_provider_candidate_groups(service_request):
    city_variants = _build_city_variants(service_request.city)
    base_qs = (
        Provider.objects.accepting_new_requests()
        .filter(service_types=service_request.service_type)
        .filter(_build_iexact_query("city", city_variants))
        .prefetch_related("service_types")
    )

    if service_request.district == ANY_DISTRICT_VALUE:
        return [list(base_qs.order_by("-rating", "full_name"))]

    district_variants = _build_district_variants(service_request.city, service_request.district)
    district_first = list(
        base_qs.filter(_build_iexact_query("district", district_variants)).order_by("-rating", "full_name")
    )
    remaining_city = list(
        base_qs.exclude(id__in=[provider.id for provider in district_first]).order_by("-rating", "full_name")
    )

    groups = []
    if district_first:
        groups.append(district_first)
    if remaining_city:
        groups.append(remaining_city)
    return groups


def set_other_pending_offers_expired(service_request, exclude_offer_id):
    pending_qs = service_request.provider_offers.filter(status__in=["pending", "accepted"]).exclude(id=exclude_offer_id)
    pending_qs.update(status="expired", responded_at=timezone.now())


def dispatch_preferred_provider_offer(
    service_request,
    preferred_provider,
    actor_user=None,
    actor_role="system",
    source="system",
    note="",
):
    if not preferred_provider:
        return {"result": "no-candidates"}

    city_variants = _build_city_variants(service_request.city)
    candidate_qs = (
        Provider.objects.accepting_new_requests()
        .filter(
            id=preferred_provider.id,
            service_types=service_request.service_type,
        )
        .filter(_build_iexact_query("city", city_variants))
        .prefetch_related("service_types")
    )
    if service_request.district != ANY_DISTRICT_VALUE:
        district_variants = _build_district_variants(service_request.city, service_request.district)
        candidate_qs = candidate_qs.filter(_build_iexact_query("district", district_variants))

    provider = candidate_qs.first()
    if not provider:
        return {"result": "no-candidates"}

    offered_provider_ids = set(service_request.provider_offers.values_list("provider_id", flat=True))
    if provider.id in offered_provider_ids:
        return {"result": "all-contacted"}

    now = timezone.now()
    created_offer = ProviderOffer.objects.create(
        service_request=service_request,
        provider=provider,
        token=generate_offer_token(),
        sequence=service_request.provider_offers.count() + 1,
        status="pending",
        last_delivery_detail="in-app-queue",
        sent_at=now,
        expires_at=now + timedelta(minutes=get_offer_expiry_minutes()),
        reminder_sent_at=None,
    )

    service_request.preferred_provider = provider
    service_request.matched_provider = None
    service_request.matched_offer = None
    service_request.matched_at = None
    previous_status = service_request.status
    if not transition_service_request_status(
        service_request,
        "pending_provider",
        extra_update_fields=["preferred_provider", "matched_provider", "matched_offer", "matched_at"],
        actor_user=actor_user,
        actor_role=actor_role,
        source=source,
        note=note,
    ):
        return {"result": "invalid-state"}
    if previous_status == "pending_provider":
        create_workflow_event(
            service_request,
            from_status="pending_provider",
            to_status="pending_provider",
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note or "Talep yeni bir ustaya iletildi",
        )
    return {"result": "offers-created", "offers": [created_offer]}


def dispatch_next_provider_offer(service_request, actor_user=None, actor_role="system", source="system", note=""):
    clear_preferred_provider = False
    if service_request.preferred_provider_id:
        has_pending_for_preferred = service_request.provider_offers.filter(
            provider_id=service_request.preferred_provider_id,
            status="pending",
        ).exists()
        if not has_pending_for_preferred:
            service_request.preferred_provider = None
            clear_preferred_provider = True

    reset_fields = ["matched_provider", "matched_offer", "matched_at"]
    if clear_preferred_provider:
        reset_fields.append("preferred_provider")

    groups = build_provider_candidate_groups(service_request)
    if not groups:
        service_request.matched_provider = None
        service_request.matched_offer = None
        service_request.matched_at = None
        if not transition_service_request_status(
            service_request,
            "new",
            extra_update_fields=reset_fields,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note,
        ):
            return {"result": "invalid-state"}
        return {"result": "no-candidates"}

    offered_provider_ids = set(service_request.provider_offers.values_list("provider_id", flat=True))
    now = timezone.now()

    for group in groups:
        next_providers = [provider for provider in group if provider.id not in offered_provider_ids]
        if not next_providers:
            continue

        next_sequence = service_request.provider_offers.count() + 1
        created_offers = []
        expiry_minutes = get_offer_expiry_minutes()
        expires_at = now + timedelta(minutes=expiry_minutes)
        for provider in next_providers:
            created_offers.append(
                ProviderOffer.objects.create(
                    service_request=service_request,
                    provider=provider,
                    token=generate_offer_token(),
                    sequence=next_sequence,
                    status="pending",
                    last_delivery_detail="in-app-queue",
                    sent_at=now,
                    expires_at=expires_at,
                    reminder_sent_at=None,
                )
            )
            next_sequence += 1

        service_request.matched_provider = None
        service_request.matched_offer = None
        service_request.matched_at = None
        previous_status = service_request.status
        if not transition_service_request_status(
            service_request,
            "pending_provider",
            extra_update_fields=reset_fields,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note,
        ):
            return {"result": "invalid-state"}
        if previous_status == "pending_provider":
            create_workflow_event(
                service_request,
                from_status="pending_provider",
                to_status="pending_provider",
                actor_user=actor_user,
                actor_role=actor_role,
                source=source,
                note=note or "Talep yeni bir ustaya iletildi",
            )
        return {"result": "offers-created", "offers": created_offers}

    service_request.matched_provider = None
    service_request.matched_offer = None
    service_request.matched_at = None
    if not transition_service_request_status(
        service_request,
        "new",
        extra_update_fields=reset_fields,
        actor_user=actor_user,
        actor_role=actor_role,
        source=source,
        note=note,
    ):
        return {"result": "invalid-state"}
    return {"result": "all-contacted"}


def reroute_service_request_after_provider_exit(
    service_request,
    *,
    actor_user=None,
    actor_role="system",
    source="system",
    note="",
):
    has_accepted_offer = service_request.provider_offers.filter(status="accepted", provider__is_verified=True).exists()
    has_pending_offer = service_request.provider_offers.filter(status="pending", provider__is_verified=True).exists()

    extra_update_fields = []
    if service_request.matched_provider_id is not None:
        service_request.matched_provider = None
        extra_update_fields.append("matched_provider")
    if service_request.matched_offer_id is not None:
        service_request.matched_offer = None
        extra_update_fields.append("matched_offer")
    if service_request.matched_at is not None:
        service_request.matched_at = None
        extra_update_fields.append("matched_at")

    if has_accepted_offer:
        if service_request.status == "pending_customer":
            if extra_update_fields:
                service_request.save(update_fields=extra_update_fields)
            create_workflow_event(
                service_request,
                from_status="pending_customer",
                to_status="pending_customer",
                actor_user=actor_user,
                actor_role=actor_role,
                source=source,
                note=note,
            )
            return {"result": "pending_customer", "offers": []}
        if not transition_service_request_status(
            service_request,
            "pending_customer",
            extra_update_fields=extra_update_fields,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note,
        ):
            return {"result": "invalid-state", "offers": []}
        return {"result": "pending_customer", "offers": []}

    if has_pending_offer:
        if not transition_service_request_status(
            service_request,
            "pending_provider",
            extra_update_fields=extra_update_fields,
            actor_user=actor_user,
            actor_role=actor_role,
            source=source,
            note=note,
        ):
            return {"result": "invalid-state", "offers": []}
        return {"result": "pending_provider", "offers": []}

    return dispatch_next_provider_offer(
        service_request,
        actor_user=actor_user,
        actor_role=actor_role,
        source=source,
        note=note,
    )


@never_cache
@ensure_csrf_cookie
def index(request):
    maybe_refresh_marketplace_lifecycle_from_request()
    is_provider_user = bool(get_provider_for_user(request.user)) if request.user.is_authenticated else False
    normalized_search_params = request.GET.copy()
    if normalized_search_params.get("sort_by") == "distance":
        normalized_search_params["sort_by"] = "relevance"
    requested_latitude = parse_float(request.GET.get("latitude"))
    requested_longitude = parse_float(request.GET.get("longitude"))
    has_location_context = requested_latitude is not None and requested_longitude is not None
    search_form = ServiceSearchForm(normalized_search_params or None)
    provider_page_size_options = [12, 24, 48, 96]
    provider_page_size_raw = (request.GET.get("provider_page_size") or "").strip()
    if provider_page_size_raw.isdigit():
        provider_page_size = int(provider_page_size_raw)
        if provider_page_size not in provider_page_size_options:
            provider_page_size = 24
    else:
        provider_page_size = 24
    providers_qs = Provider.objects.accepting_new_requests().prefetch_related("service_types").annotate(
        ratings_count=Count("ratings", distinct=True)
    )
    selected_sort_label = "Önerilen"

    if search_form.is_valid():
        query_text = (search_form.cleaned_data.get("query") or "").strip()
        service_type = search_form.cleaned_data.get("service_type")
        city = (search_form.cleaned_data.get("city") or "").strip()
        district = (search_form.cleaned_data.get("district") or "").strip()
        sort_by = (search_form.cleaned_data.get("sort_by") or "relevance").strip() or "relevance"
        min_rating = search_form.cleaned_data.get("min_rating")
        min_reviews = search_form.cleaned_data.get("min_reviews")
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
            providers_qs = providers_qs.filter(_build_iexact_query("city", _build_city_variants(city)))
        if district and district != ANY_DISTRICT_VALUE:
            providers_qs = providers_qs.filter(
                _build_iexact_query("district", _build_district_variants(city, district))
            )
        if min_rating is not None:
            providers_qs = providers_qs.filter(rating__gte=min_rating)
        if min_reviews is not None:
            providers_qs = providers_qs.filter(ratings_count__gte=min_reviews)
        if requires_distinct:
            providers_qs = providers_qs.distinct()

        if sort_by not in {"relevance", "rating_desc", "reviews_desc", "newest", "name_asc"}:
            sort_by = "relevance"

        selected_sort_label = dict(search_form.fields["sort_by"].choices).get(sort_by, "Önerilen")

        if sort_by == "reviews_desc":
            providers_qs = providers_qs.order_by("-ratings_count", "-rating", "full_name", "id")
        elif sort_by == "newest":
            providers_qs = providers_qs.order_by("-created_at", "-rating", "full_name", "id")
        elif sort_by == "name_asc":
            providers_qs = providers_qs.order_by("full_name", "-rating", "id")
        else:
            providers_qs = providers_qs.order_by("-rating", "-ratings_count", "full_name", "id")

        if has_location_context:
            sorted_providers = sort_providers_by_distance(
                list(providers_qs),
                requested_latitude,
                requested_longitude,
            )
            provider_page_obj = paginate_items(
                request,
                sorted_providers,
                per_page=provider_page_size,
                page_param="provider_page",
            )
        else:
            provider_page_obj = paginate_items(
                request,
                providers_qs,
                per_page=provider_page_size,
                page_param="provider_page",
            )
        providers = list(provider_page_obj.object_list)
    else:
        selected_sort_label = "Önerilen"
        providers_qs = providers_qs.order_by("-rating", "-ratings_count", "full_name", "id")
        if has_location_context:
            sorted_providers = sort_providers_by_distance(
                list(providers_qs),
                requested_latitude,
                requested_longitude,
            )
            provider_page_obj = paginate_items(
                request,
                sorted_providers,
                per_page=provider_page_size,
                page_param="provider_page",
            )
        else:
            provider_page_obj = paginate_items(
                request,
                providers_qs,
                per_page=provider_page_size,
                page_param="provider_page",
            )
        providers = list(provider_page_obj.object_list)

    query_without_provider_page = normalized_search_params.copy()
    query_without_provider_page.pop("provider_page", None)
    provider_page_query = query_without_provider_page.urlencode()

    preferred_provider = get_preferred_provider(request.GET.get("preferred_provider_id"))
    request_form = build_service_request_form(
        request,
        preferred_provider=preferred_provider,
        is_provider_user=is_provider_user,
    )
    context = {
        "search_form": search_form,
        "request_form": request_form,
        "preferred_provider": preferred_provider,
        "providers": providers,
        "provider_page_obj": provider_page_obj,
        "provider_total_count": provider_page_obj.paginator.count,
        "provider_page_query": provider_page_query,
        "provider_page_size": provider_page_size,
        "provider_page_size_options": provider_page_size_options,
        "selected_sort_label": selected_sort_label,
        "city_district_map_json": get_city_district_map_json(),
        "is_provider_user": is_provider_user,
        "popular_service_types": get_popular_service_types(),
        "form_only_mode": False,
    }
    return render(request, "Myapp/index.html", context)


@never_cache
@ensure_csrf_cookie
def request_form_page(request):
    maybe_refresh_marketplace_lifecycle_from_request()
    is_provider_user = bool(get_provider_for_user(request.user)) if request.user.is_authenticated else False
    preferred_provider = get_preferred_provider(request.GET.get("preferred_provider_id"))
    request_form = build_service_request_form(
        request,
        preferred_provider=preferred_provider,
        is_provider_user=is_provider_user,
    )
    context = {
        "request_form": request_form,
        "preferred_provider": preferred_provider,
        "city_district_map_json": get_city_district_map_json(),
        "is_provider_user": is_provider_user,
        "popular_service_types": get_popular_service_types(),
        "form_only_mode": True,
    }
    return render(request, "Myapp/index.html", context)


def create_request(request):
    if request.method != "POST":
        return redirect("index")

    if not request.user.is_authenticated:
        messages.error(request, "Talep oluşturmak için giriş yapmalısınız.")
        return redirect("customer_login")

    provider_user = get_provider_for_user(request.user)
    if provider_user:
        messages.error(request, "Usta hesabı ile talep oluşturamazsınız.")
        return redirect("provider_requests")

    if (request.POST.get("website_url") or "").strip():
        return redirect("index")

    rate_limit_identity = "|".join(
        [
            str(request.POST.get("service_type") or "").strip(),
            normalize_request_text(request.POST.get("city")),
            normalize_request_text(request.POST.get("district")),
        ]
    )
    rate_limit_response = reject_rate_limited_request(
        request,
        "create-request",
        "index",
        max_attempts=get_create_request_rate_limit_max_attempts(),
        window_seconds=get_create_request_rate_limit_window_seconds(),
        identity=rate_limit_identity,
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "create-request", "index")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    preferred_provider = get_preferred_provider(request.POST.get("preferred_provider_id"))
    request_form = ServiceRequestForm(request.POST, preferred_provider=preferred_provider)
    if not request_form.is_valid():
        search_form = ServiceSearchForm()
        provider_page_size_options = [12, 24, 48, 96]
        provider_page_size = 24
        providers_qs = (
            Provider.objects.accepting_new_requests()
            .prefetch_related("service_types")
            .annotate(ratings_count=Count("ratings", distinct=True))
            .order_by("-rating", "full_name", "id")
        )
        provider_page_obj = paginate_items(
            request,
            providers_qs,
            per_page=provider_page_size,
            page_param="provider_page",
        )
        providers = list(provider_page_obj.object_list)
        return render(
            request,
            "Myapp/index.html",
            {
                "search_form": search_form,
                "request_form": request_form,
                "preferred_provider": preferred_provider,
                "providers": providers,
                "provider_page_obj": provider_page_obj,
                "provider_total_count": provider_page_obj.paginator.count,
                "provider_page_query": "",
                "provider_page_size": provider_page_size,
                "provider_page_size_options": provider_page_size_options,
                "selected_sort_label": "Önerilen",
                "city_district_map_json": get_city_district_map_json(),
                "is_provider_user": False,
                "popular_service_types": get_popular_service_types(),
            },
        )

    abuse_response = reject_create_request_abuse(request, "index", cleaned_data=request_form.cleaned_data)
    if abuse_response:
        return abuse_response

    preferred_provider = request_form.cleaned_data.get("preferred_provider")
    service_request = request_form.save(commit=False)
    service_request.preferred_provider = preferred_provider
    if request.user.is_authenticated:
        service_request.customer = request.user
    service_request.created_ip = get_client_ip(request)[:64]
    service_request.request_fingerprint = getattr(request, "_create_request_fingerprint", "")

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

    if request.user.is_authenticated:
        customer_profile, _ = CustomerProfile.objects.get_or_create(user=request.user)
        customer_profile.phone = service_request.customer_phone
        customer_profile.city = service_request.city
        customer_profile.district = service_request.district
        customer_profile.save(update_fields=["phone", "city", "district"])

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

    if dispatch_result["result"] == "offers-created":
        offer_count = len(dispatch_result["offers"])
        if preferred_provider:
            messages.success(
                request,
                f"Talebiniz alındı. Öncelikli olarak {preferred_provider.full_name} ustasına iletildi.",
            )
        else:
            messages.success(
                request,
                f"Talebiniz alındı. {offer_count} ustaya teklif vermesi için iletildi.",
            )
    elif dispatch_result["result"] == "no-candidates":
        if preferred_provider:
            messages.info(
                request,
                "Talebiniz alındı ancak seçilen usta şu an bu kriterlerde müsait değil.",
            )
        else:
            messages.info(
                request,
                "Talebiniz alındı ancak şu an şehir/ilçe kriterlerinde müsait usta bulunamadı.",
            )
    else:
        messages.warning(
            request,
            "Talebiniz kaydedildi fakat şu an sıradaki uygun usta bulunamadı.",
        )

    return redirect("index")


def contact(request):
    return render(request, "Myapp/Contact.html")


def offline(request):
    return render(request, "Myapp/offline.html")


@never_cache
def service_worker(request):
    response = render(request, "service-worker.js", content_type="application/javascript")
    response["Service-Worker-Allowed"] = "/"
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@login_required
def rate_request(request, request_id):
    back_url = "agreement_history"
    if request.method != "POST":
        return redirect(back_url)
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")

    service_request = get_object_or_404(ServiceRequest, id=request_id, customer=request.user)
    if service_request.status != "completed" or service_request.matched_provider is None:
        messages.error(request, "Puanlama sadece tamamlanmış ve eşleşmiş talepler için yapılabilir.")
        return redirect(back_url)
    appointment = ServiceAppointment.objects.filter(service_request=service_request).only("id", "status").first()
    has_confirmed_appointment = WorkflowEvent.objects.filter(
        target_type="appointment",
        service_request=service_request,
        to_status="confirmed",
    ).exists()
    if not appointment or appointment.status != "completed" or not has_confirmed_appointment:
        messages.error(request, "Randevu oluşturulup onaylanmadan tamamlanan işlerde puanlama yapılamaz.")
        return redirect(back_url)

    current_rating = getattr(service_request, "provider_rating", None)
    form = ProviderRatingForm(request.POST, instance=current_rating)
    if form.is_valid():
        rating = form.save(commit=False)
        rating.service_request = service_request
        rating.provider = service_request.matched_provider
        rating.customer = request.user
        rating.save()
        if current_rating is None:
            messages.success(request, f"{service_request.matched_provider.full_name} için puanınız kaydedildi.")
        else:
            messages.success(request, f"{service_request.matched_provider.full_name} için yorumunuz güncellendi.")
    else:
        messages.error(request, "Puan kaydedilemedi. Lütfen geçerli bir puan seçin.")

    return redirect(back_url)


@never_cache
@ensure_csrf_cookie
def signup_view(request):
    if request.user.is_authenticated:
        return redirect("provider_requests") if get_provider_for_user(request.user) else redirect("index")

    if request.method == "POST":
        form = CustomerSignupForm(request.POST)
        if form.is_valid():
            pending_payload = form.build_pending_verification_payload()
            try:
                verification = begin_signup_verification(request, pending_payload)
            except Exception as exc:
                log_signup_email_delivery_failure(
                    request,
                    email=pending_payload.get("email"),
                    purpose=pending_payload.get("purpose"),
                    exc=exc,
                )
                form.add_error(None, get_signup_email_delivery_error_message(exc))
            else:
                messages.success(
                    request,
                    f"{pending_payload['email']} adresine doğrulama kodu gönderildi. Kod {timezone.localtime(verification.expires_at).strftime('%H:%M')} saatine kadar geçerli.",
                )
                return redirect("signup_email_verify")
    else:
        form = CustomerSignupForm()

    return render(
        request,
        "Myapp/signup.html",
        {
            "form": form,
            "city_district_map_json": get_city_district_map_json(),
        },
    )


@never_cache
@ensure_csrf_cookie
def provider_signup_view(request):
    if request.user.is_authenticated:
        return redirect("provider_requests") if get_provider_for_user(request.user) else redirect("index")

    if request.method == "POST":
        form = ProviderSignupForm(request.POST)
        if form.is_valid():
            clear_pending_signup_payload(request)
            form.save()
            messages.success(
                request,
                "Usta hesabınız oluşturuldu. Admin onayı sonrası giriş yapabilirsiniz.",
            )
            return redirect("provider_login")
    else:
        form = ProviderSignupForm()

    return render(
        request,
        "Myapp/provider_signup.html",
        {
            "form": form,
            "city_district_map_json": get_city_district_map_json(),
        },
    )


@never_cache
@ensure_csrf_cookie
def signup_email_verify_view(request):
    if request.user.is_authenticated:
        return redirect("provider_requests") if get_provider_for_user(request.user) else redirect("index")

    pending_payload = get_pending_signup_payload(request)
    if not pending_payload:
        messages.info(request, "Doğrulama oturumu bulunamadı. Lütfen yeniden kayıt olun.")
        return redirect("customer_signup")

    purpose = pending_payload["purpose"]
    if purpose == "provider-signup":
        clear_pending_signup_payload(request)
        messages.info(
            request,
            "Usta kaydında e-posta doğrulaması kaldırıldı. Lütfen kaydı yeniden tamamlayın.",
        )
        return redirect("provider_signup")
    meta = get_signup_verification_meta(purpose)
    email = pending_payload["email"]
    form = EmailVerificationCodeForm()

    if request.method == "POST":
        action = (request.POST.get("action") or "verify").strip()
        if action == "resend":
            resend_available_in = get_signup_resend_available_in(email, purpose)
            if resend_available_in:
                messages.info(request, f"Yeni kodu {resend_available_in} saniye sonra isteyebilirsiniz.")
            else:
                try:
                    verification = issue_signup_verification_code(email, purpose)
                except Exception as exc:
                    log_signup_email_delivery_failure(request, email=email, purpose=purpose, exc=exc)
                    messages.error(request, get_signup_email_delivery_error_message(exc))
                else:
                    set_pending_signup_payload(request, pending_payload)
                    messages.success(
                        request,
                        f"Yeni kod gönderildi. Kod {timezone.localtime(verification.expires_at).strftime('%H:%M')} saatine kadar geçerli.",
                    )
        else:
            form = EmailVerificationCodeForm(request.POST)
            if form.is_valid():
                verification = get_latest_email_verification(email, purpose)
                now = timezone.now()
                max_attempts = get_email_verification_max_attempts()
                if not verification or verification.consumed_at:
                    form.add_error(None, "Aktif doğrulama kodu bulunamadı. Yeni kod isteyin.")
                elif verification.expires_at <= now:
                    form.add_error(None, "Kodun süresi doldu. Yeni kod isteyin.")
                elif verification.attempt_count >= max_attempts:
                    form.add_error(None, "Çok fazla hatalı deneme oldu. Yeni kod isteyin.")
                else:
                    submitted_hash = hash_email_verification_code(email, purpose, form.cleaned_data["code"])
                    if verification.code_hash != submitted_hash:
                        verification.attempt_count += 1
                        verification.save(update_fields=["attempt_count"])
                        remaining_attempts = max(0, max_attempts - verification.attempt_count)
                        if remaining_attempts:
                            form.add_error("code", f"Kod hatalı. Kalan deneme: {remaining_attempts}.")
                        else:
                            form.add_error(None, "Çok fazla hatalı deneme oldu. Yeni kod isteyin.")
                    else:
                        verification.consumed_at = now
                        verification.save(update_fields=["consumed_at"])
                        try:
                            user = create_account_from_pending_signup(pending_payload)
                        except ValidationError as exc:
                            form.add_error(None, exc.messages[0] if exc.messages else str(exc))
                        else:
                            clear_pending_signup_payload(request)
                            if meta["login_after_verify"]:
                                login(request, user)
                                request.session["role"] = meta["account_type"]
                            messages.success(request, meta["success_message"])
                            return redirect(meta["redirect_url"])

    active_verification = get_active_email_verification(email, purpose)
    latest_verification = active_verification or get_latest_email_verification(email, purpose)
    resend_available_in = get_signup_resend_available_in(email, purpose)
    return render(
        request,
        "Myapp/customer_signup_verify.html",
        {
            "form": form,
            "email": email,
            "expires_at": latest_verification.expires_at if latest_verification and latest_verification.consumed_at is None else None,
            "resend_available_in": resend_available_in,
            "badge_label": meta["badge_label"],
            "title": meta["title"],
            "description": meta["description"],
            "back_url": meta["back_url"],
        },
    )


@never_cache
@ensure_csrf_cookie
def login_view(request):
    if request.user.is_authenticated:
        return redirect("provider_requests") if get_provider_for_user(request.user) else redirect("index")

    if request.method == "POST":
        rate_limit_response = reject_rate_limited_request(
            request,
            "customer-login",
            "customer_login",
            max_attempts=get_login_rate_limit_max_attempts(),
            window_seconds=get_login_rate_limit_window_seconds(),
            identity=(request.POST.get("username") or "").strip(),
        )
        if rate_limit_response:
            return rate_limit_response

        form = CustomerLoginForm(request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            request.session["role"] = "customer"
            messages.success(request, "Giriş başarılı.")
            return redirect("index")
    else:
        form = CustomerLoginForm(request)

    return render(request, "Myapp/login.html", {"form": form})


@never_cache
@ensure_csrf_cookie
def provider_login_view(request):
    if request.user.is_authenticated:
        provider = get_provider_for_user(request.user)
        if provider:
            if provider.is_verified:
                return redirect("provider_requests")
            if not request.session.pop(PROVIDER_PENDING_APPROVAL_FLASH_FLAG, False):
                messages.warning(request, PROVIDER_PENDING_APPROVAL_MESSAGE)
            return redirect("index")
        return redirect("index")

    if request.method == "POST":
        rate_limit_response = reject_rate_limited_request(
            request,
            "provider-login",
            "provider_login",
            max_attempts=get_login_rate_limit_max_attempts(),
            window_seconds=get_login_rate_limit_window_seconds(),
            identity=(request.POST.get("username") or "").strip(),
        )
        if rate_limit_response:
            return rate_limit_response

        form = ProviderLoginForm(request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            request.session["role"] = "provider"
            messages.success(request, "Usta girişi başarılı.")
            return redirect("provider_requests")
    else:
        form = ProviderLoginForm(request)

    return render(request, "Myapp/provider_login.html", {"form": form})


@never_cache
@ensure_csrf_cookie
def password_reset_request_view(request):
    if request.method == "POST":
        rate_limit_response = reject_rate_limited_request(
            request,
            "password-reset",
            "password_reset",
            max_attempts=get_login_rate_limit_max_attempts(),
            window_seconds=get_login_rate_limit_window_seconds(),
            identity=(request.POST.get("email") or "").strip(),
        )
        if rate_limit_response:
            return rate_limit_response

        form = AccountPasswordResetRequestForm(request.POST)
        if form.is_valid():
            normalized_email = normalize_signup_email(form.cleaned_data["email"])
            target_users = list(
                User.objects.filter(email__iexact=normalized_email, is_active=True)
                .exclude(password="")
                .order_by("id")
            )
            try:
                for user in target_users:
                    if not user.has_usable_password():
                        continue
                    send_password_reset_email(
                        user,
                        reset_url=build_password_reset_url(request, user),
                    )
            except Exception as exc:
                log_password_reset_email_delivery_failure(request, email=normalized_email, exc=exc)
                form.add_error(None, get_password_reset_email_delivery_error_message(exc))
            else:
                messages.success(
                    request,
                    "Eger bu e-posta adresiyle bir hesap varsa sifre sifirlama baglantisi gonderildi.",
                )
                return redirect("password_reset_sent")
    else:
        form = AccountPasswordResetRequestForm()

    return render(request, "Myapp/password_reset_request.html", {"form": form})


@never_cache
def password_reset_sent_view(request):
    return render(request, "Myapp/password_reset_sent.html")


@never_cache
@ensure_csrf_cookie
def password_reset_confirm_view(request, uidb64, token):
    user = None
    validlink = False
    try:
        user_id = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=user_id, is_active=True)
        validlink = default_token_generator.check_token(user, token)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        validlink = False

    if not validlink:
        return render(
            request,
            "Myapp/password_reset_confirm.html",
            {
                "form": None,
                "validlink": False,
            },
        )

    if request.method == "POST":
        form = AccountPasswordResetConfirmForm(user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Sifreniz yenilendi. Yeni sifrenizle giris yapabilirsiniz.")
            return redirect("password_reset_complete")
    else:
        form = AccountPasswordResetConfirmForm(user)

    return render(
        request,
        "Myapp/password_reset_confirm.html",
        {
            "form": form,
            "validlink": True,
        },
    )


@never_cache
def password_reset_complete_view(request):
    return render(request, "Myapp/password_reset_complete.html")


def logout_view(request):
    if request.method == "POST":
        logout(request)
        request.session.pop("role", None)
        messages.info(request, "Çıkış yapıldı.")
    return redirect("index")


@login_required
@never_cache
@ensure_csrf_cookie
def provider_profile_view(request):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response

    calendar_enabled = is_provider_availability_enabled()
    availability_form = ProviderAvailabilitySlotForm(provider=provider) if calendar_enabled else None
    if request.method == "POST":
        slot_action = (request.POST.get("slot_action") or "").strip()
        if slot_action == "add":
            if not calendar_enabled:
                return calendar_disabled_redirect(request, "provider_profile")
            form = ProviderProfileForm(instance=provider)
            availability_form = ProviderAvailabilitySlotForm(request.POST, provider=provider)
            if availability_form.is_valid():
                slot = availability_form.save(commit=False)
                slot.provider = provider
                slot.save()
                messages.success(request, "Musaitlik araligi eklendi.")
                return redirect("provider_profile")
        elif slot_action == "delete":
            if not calendar_enabled:
                return calendar_disabled_redirect(request, "provider_profile")
            form = ProviderProfileForm(instance=provider)
            try:
                slot_id = int(request.POST.get("slot_id") or 0)
            except (TypeError, ValueError):
                slot_id = 0
            slot = get_object_or_404(ProviderAvailabilitySlot, id=slot_id, provider=provider)
            slot.delete()
            messages.success(request, "Musaitlik araligi silindi.")
            return redirect("provider_profile")
        else:
            form = ProviderProfileForm(request.POST, instance=provider)
            if form.is_valid():
                form.save()
                messages.success(request, "Usta profiliniz güncellendi.")
                return redirect("provider_profile")
    else:
        form = ProviderProfileForm(instance=provider)

    availability_slots = []
    if calendar_enabled:
        availability_slots = list(provider.availability_slots.order_by("weekday", "start_time", "end_time"))

    return render(
        request,
        "Myapp/provider_profile.html",
        {
            "provider": provider,
            "provider_membership": build_provider_membership_context(provider),
            "form": form,
            "availability_form": availability_form,
            "availability_slots": availability_slots,
            "calendar_enabled": calendar_enabled,
            "city_district_map_json": get_city_district_map_json(),
        },
    )


def serialize_service_message(message_item, viewer_role):
    return {
        "id": message_item.id,
        "body": message_item.body,
        "sender_role": message_item.sender_role,
        "sender_label": message_item.get_sender_role_display(),
        "mine": message_item.sender_role == viewer_role,
        "created_at": timezone.localtime(message_item.created_at).strftime("%d.%m.%Y %H:%M"),
    }


def get_request_messages_group_name(request_id):
    return f"request_messages_{int(request_id)}"


def publish_service_message_event(message_item):
    if not realtime_channels_enabled():
        return
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = serialize_service_message(message_item, message_item.sender_role)
    payload.pop("mine", None)
    try:
        async_to_sync(channel_layer.group_send)(
            get_request_messages_group_name(message_item.service_request_id),
            {"type": "service_message_created", "message": payload},
        )
    except Exception:
        return


def resolve_request_message_access(request, request_id, *, api=False):
    service_request = get_object_or_404(
        ServiceRequest.objects.select_related(
            "service_type",
            "customer",
            "matched_provider",
            "matched_offer",
            "matched_offer__provider",
        ),
        id=request_id,
    )
    provider = get_provider_for_user(request.user)
    if provider:
        if not provider.is_verified:
            if api:
                return None, None, None, JsonResponse({"detail": "pending-approval"}, status=403)
            queue_provider_pending_approval_warning(request)
            return None, None, None, redirect("provider_login")
        if service_request.matched_provider_id != provider.id:
            if api:
                return None, None, None, JsonResponse({"detail": "forbidden"}, status=403)
            messages.error(request, "Bu mesajlaşmaya erişiminiz yok.")
            return None, None, None, redirect("provider_requests")
        viewer_role = "provider"
        back_url = "provider_requests"
    else:
        if service_request.customer_id != request.user.id:
            if api:
                return None, None, None, JsonResponse({"detail": "forbidden"}, status=403)
            messages.error(request, "Bu mesajlaşmaya erişiminiz yok.")
            return None, None, None, redirect("index")
        viewer_role = "customer"
        back_url = "my_requests"

    if provider:
        if service_request.status == "pending_customer" and (
            service_request.matched_offer_id is None or service_request.matched_offer.provider_id != provider.id
        ):
            if api:
                return None, None, None, JsonResponse({"detail": "not-selected-by-customer"}, status=403)
            messages.warning(request, "Müşteri sizi henüz seçmediği için mesajlaşma açılmadı.")
            return None, None, None, redirect("provider_requests")
    if service_request.status != "matched":
        if api:
            return (
                None,
                None,
                None,
                JsonResponse({"detail": "thread-closed", "request_status": service_request.status}, status=409),
            )
        messages.warning(request, "Tamamlanan veya kapalı taleplerde mesajlaşma açık değildir.")
        return None, None, None, redirect(back_url)

    if provider:
        if service_request.matched_offer_id is None or service_request.matched_offer.provider_id != provider.id:
            if api:
                return None, None, None, JsonResponse({"detail": "not-selected-by-customer"}, status=403)
            messages.warning(request, "Müşteri sizi henüz seçmediği için mesajlaşma açılmadı.")
            return None, None, None, redirect("provider_requests")
    else:
        if service_request.matched_provider and not service_request.matched_provider.is_verified:
            if api:
                return None, None, None, JsonResponse({"detail": "provider-not-verified"}, status=403)
            messages.warning(request, "Bu usta henüz admin onaylı olmadığı için mesajlaşma kapalı.")
            return None, None, None, redirect("my_requests")
        if service_request.matched_offer_id is None:
            if api:
                return None, None, None, JsonResponse({"detail": "provider-not-selected"}, status=403)
            messages.warning(request, "Usta seçimi tamamlanmadan mesajlaşma açılmaz.")
            return None, None, None, redirect("my_requests")
    return service_request, viewer_role, back_url, None


@login_required
@never_cache
@ensure_csrf_cookie
def request_messages(request, request_id):
    service_request, viewer_role, back_url, blocked_response = resolve_request_message_access(request, request_id)
    if blocked_response:
        return blocked_response

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if request.method == "POST":
        form = ServiceMessageForm(request.POST)
        if form.is_valid():
            message_item = form.save(commit=False)
            message_item.service_request = service_request
            message_item.sender_user = request.user
            message_item.sender_role = viewer_role
            message_item.save()
            create_activity_log(
                action_type="message_sent",
                service_request=service_request,
                message_item=message_item,
                actor_user=request.user,
                actor_role=viewer_role,
                source="user",
                summary=f"Talep {get_request_display_code(service_request)} için yeni mesaj",
                note=message_item.body,
            )
            publish_service_message_event(message_item)
            invalidate_notification_cache_for_instance(service_request, actor_user=request.user)
            if is_ajax:
                return JsonResponse(
                    {
                        "ok": True,
                        "message": serialize_service_message(message_item, viewer_role),
                    }
                )
            return redirect("request_messages", request_id=service_request.id)
        if is_ajax:
            return JsonResponse({"ok": False, "error": get_first_form_error(form)}, status=400)
    else:
        form = ServiceMessageForm()

    marked_count = ServiceMessage.objects.filter(service_request=service_request, read_at__isnull=True).exclude(
        sender_role=viewer_role
    ).update(read_at=timezone.now())
    if marked_count:
        invalidate_notification_cache_for_instance(service_request, actor_user=request.user)
    thread_messages = list(service_request.messages.select_related("sender_user").order_by("id"))
    latest_message_id = thread_messages[-1].id if thread_messages else 0

    return render(
        request,
        "Myapp/request_messages.html",
        {
            "service_request": service_request,
            "viewer_role": viewer_role,
            "messages_list": thread_messages,
            "latest_message_id": latest_message_id,
            "form": form,
            "back_url": back_url,
            "fallback_poll_interval_ms": get_request_messages_fallback_poll_interval_seconds() * 1000,
            "realtime_channels_enabled": realtime_channels_enabled(),
        },
    )


@login_required
@never_cache
def request_messages_snapshot(request, request_id):
    service_request, viewer_role, _back_url, blocked_response = resolve_request_message_access(
        request, request_id, api=True
    )
    if blocked_response:
        return blocked_response

    after_id_raw = (request.GET.get("after_id") or "").strip()
    if after_id_raw.isdigit():
        after_id = int(after_id_raw)
    else:
        after_id = 0

    marked_count = ServiceMessage.objects.filter(service_request=service_request, read_at__isnull=True).exclude(
        sender_role=viewer_role
    ).update(read_at=timezone.now())
    if marked_count:
        invalidate_notification_cache_for_instance(service_request, actor_user=request.user)

    thread_qs = service_request.messages.select_related("sender_user").order_by("id")
    if after_id > 0:
        thread_qs = thread_qs.filter(id__gt=after_id)
    thread_messages = list(thread_qs[:100])

    if thread_messages:
        latest_id = thread_messages[-1].id
    else:
        latest_id = service_request.messages.order_by("-id").values_list("id", flat=True).first() or 0

    return JsonResponse(
        {
            "messages": [serialize_service_message(item, viewer_role) for item in thread_messages],
            "latest_id": latest_id,
            "thread_closed": False,
        }
    )


@login_required
@never_cache
def notifications_view(request):
    selected_category = normalize_notification_category(request.GET.get("category"))
    entries = build_notification_entries(
        request.user,
        limit=NOTIFICATION_CENTER_LIMIT,
        include_all=True,
        unread_only=True,
    )
    category_filtered_entries = entries
    if selected_category != "all":
        category_filtered_entries = [item for item in category_filtered_entries if item.get("category_key") == selected_category]

    category_count_source = entries
    category_counts = {
        "all": len(category_count_source),
        "message": sum(1 for item in category_count_source if item.get("category_key") == "message"),
        "request": sum(1 for item in category_count_source if item.get("category_key") == "request"),
        "appointment": sum(1 for item in category_count_source if item.get("category_key") == "appointment"),
    }

    notification_category_filters = []
    for category_key, label in (
        ("all", "Tümü"),
        ("message", "Mesaj"),
        ("request", "Talep"),
        ("appointment", "Randevu"),
    ):
        notification_category_filters.append(
            {
                "value": category_key,
                "label": label,
                "count": category_counts.get(category_key, 0),
                "is_active": selected_category == category_key,
                "url": build_query_url(request, updates={"category": category_key}, remove=["page", "unread"]),
            }
        )

    unread_count = get_total_unread_notifications_count(request.user)
    notification_cursor = get_notification_cursor(request.user, create=True)
    notification_preferences = get_notification_preferences(cursor=notification_cursor)
    disabled_categories = [
        filter_item["label"]
        for filter_item in notification_category_filters
        if filter_item["value"] != "all" and not notification_preferences.get(filter_item["value"], True)
    ]

    return render(
        request,
        "Myapp/notifications.html",
        {
            "notification_entries": category_filtered_entries,
            "notification_sections": build_notification_sections(category_filtered_entries),
            "notifications_unread_count": unread_count,
            "notification_category_filters": notification_category_filters,
            "selected_notification_category": selected_category,
            "disabled_notification_categories": disabled_categories,
        },
    )


@login_required
@require_POST
def notifications_mark_all_read(request):
    result = mark_all_notifications_read(request.user)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(
            {
                "ok": True,
                "marked_count": result["message_count"] + result["workflow_count"],
                "unread_notifications_count": result["unread_notifications_count"],
            }
        )
    return redirect("notifications")


@login_required
@require_POST
def notifications_mark_entry_read(request, entry_id):
    result = mark_notification_entry_read(request.user, entry_id)
    if not result:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({"ok": False}, status=404)
        messages.error(request, "Bildirim bulunamadı veya size ait değil.")
        return redirect("notifications")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(
            {
                "ok": True,
                "entry_id": result["entry_id"],
                "marked": result["marked"],
                "unread_notifications_count": result["unread_notifications_count"],
            }
        )

    return redirect(request.POST.get("next") or "notifications")


@login_required
@never_cache
def notifications_open_entry(request, entry_id):
    entry = resolve_notification_entry(request.user, entry_id)
    if not entry:
        messages.error(request, "Bildirim bulunamadı veya size ait değil.")
        return redirect("notifications")

    mark_notification_entry_read(request.user, entry_id)
    return redirect(entry["link"])


@login_required
@never_cache
def notifications_unread_count(request):
    response = JsonResponse(
        {
            "unread_notifications_count": get_total_unread_notifications_count(request.user),
        }
    )
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@never_cache
@ensure_csrf_cookie
def mobile_shell_context(request):
    if not request.user.is_authenticated:
        response = JsonResponse({"authenticated": False, "user_id": None, "role": None})
        response["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    provider = get_provider_for_user(request.user)
    role = "provider" if provider else "customer"
    response = JsonResponse(
        {
            "authenticated": True,
            "user_id": request.user.id,
            "role": role,
        }
    )
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@csrf_exempt
@require_POST
def mobile_shell_register_device(request):
    if not request.user.is_authenticated:
        return JsonResponse({"ok": False, "detail": "auth-required"}, status=401)

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"ok": False, "detail": "invalid-json"}, status=400)

    serializer = MobileDeviceRegistrationSerializer(data=payload)
    if not serializer.is_valid():
        return JsonResponse({"ok": False, "errors": serializer.errors}, status=400)

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

    return JsonResponse(
        {
            "ok": True,
            "created": created,
            "device_id": device.id,
        },
        status=201 if created else 200,
    )


@csrf_exempt
@require_POST
def mobile_shell_unregister_device(request):
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"ok": False, "detail": "invalid-json"}, status=400)

    serializer = MobileDeviceRegistrationSerializer(data=payload)
    if not serializer.is_valid():
        return JsonResponse({"ok": False, "errors": serializer.errors}, status=400)

    validated = serializer.validated_data
    filters = {
        "platform": validated["platform"],
        "device_id": validated["device_id"],
    }
    push_token = validated.get("push_token")
    if push_token:
        filters["push_token"] = push_token

    deleted_count, _details = MobileDevice.objects.filter(**filters).delete()
    return JsonResponse({"ok": True, "deleted_count": deleted_count})


@login_required
@never_cache
def operations_dashboard(request):
    from .services.operations_dashboard import operations_dashboard as operations_dashboard_service

    return operations_dashboard_service(request)


def build_customer_panel_context(request):
    from .services.customer_panel import build_customer_panel_context as build_customer_panel_context_service

    return build_customer_panel_context_service(request)
@login_required
def my_requests(request):
    maybe_refresh_marketplace_lifecycle_from_request()
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")
    is_partial = is_panel_partial_request(request)
    context = build_customer_panel_context(request)
    if is_partial:
        return render_panel_partial_response(
            request,
            template_name="Myapp/partials/customer_panel_content.html",
            context=context,
            snapshot=context["customer_snapshot"],
        )
    return render(request, "Myapp/my_requests.html", context)


@login_required
def agreement_history(request):
    provider = get_provider_for_user(request.user)
    calendar_enabled = is_calendar_enabled()
    if provider:
        agreements_qs = (
            ServiceRequest.objects.filter(
                matched_provider=provider,
                matched_offer__isnull=False,
            )
            .select_related(
                "service_type",
                "customer",
                "matched_provider",
                "matched_offer",
                "matched_offer__provider",
            )
            .order_by("-matched_at", "-created_at")
        )
    else:
        agreements_qs = (
            request.user.service_requests.filter(matched_offer__isnull=False)
            .select_related(
                "service_type",
                "customer",
                "matched_provider",
                "matched_offer",
                "matched_offer__provider",
            )
            .order_by("-matched_at", "-created_at")
        )

    agreements_page_obj = paginate_items(request, agreements_qs, per_page=12, page_param="page")
    agreements = list(agreements_page_obj.object_list)
    agreement_ids = [item.id for item in agreements]
    appointment_map = {
        appointment.service_request_id: appointment
        for appointment in ServiceAppointment.objects.filter(service_request_id__in=agreement_ids)
    }
    rating_map = {
        rating.service_request_id: rating
        for rating in ProviderRating.objects.filter(service_request_id__in=agreement_ids)
    }
    confirmed_appointment_request_ids = set()
    if calendar_enabled and agreement_ids:
        confirmed_appointment_request_ids = set(
            WorkflowEvent.objects.filter(
                target_type="appointment",
                service_request_id__in=agreement_ids,
                to_status="confirmed",
            ).values_list("service_request_id", flat=True)
        )
    for item in agreements:
        item.appointment_entry = appointment_map.get(item.id)
        item.rating_entry = rating_map.get(item.id)
        status_ui = get_service_request_status_ui(
            item,
            item.appointment_entry,
            calendar_enabled=calendar_enabled,
        )
        item.status_ui_label = status_ui["label"]
        item.status_ui_class = status_ui["css_status"]
        item.can_rate = False
        item.rate_block_reason = ""
        if not provider and item.status == "completed" and item.matched_provider_id:
            if calendar_enabled:
                item.can_rate = (
                    bool(item.appointment_entry)
                    and item.appointment_entry.status == "completed"
                    and item.id in confirmed_appointment_request_ids
                )
                if not item.can_rate:
                    if item.appointment_entry is None:
                        item.rate_block_reason = "Randevu oluşturulmadan kapanan işlerde puanlama kapalıdır."
                    elif item.id not in confirmed_appointment_request_ids:
                        item.rate_block_reason = "Randevu müşteri onayı olmadan kapatıldığı için puanlama kapalıdır."
                    elif item.appointment_entry.status != "completed":
                        item.rate_block_reason = "Puanlama için randevunun tamamlanması gerekir."
            else:
                item.can_rate = True

    summary = agreements_qs.aggregate(
        total_count=Count("id"),
        completed_count=Count("id", filter=Q(status="completed")),
        matched_count=Count("id", filter=Q(status="matched")),
    )
    return render(
        request,
        "Myapp/agreement_history.html",
        {
            "agreements": agreements,
            "agreements_page_obj": agreements_page_obj,
            "is_provider_user": bool(provider),
            "calendar_enabled": calendar_enabled,
            "summary_total_count": summary.get("total_count", 0) or 0,
            "summary_completed_count": summary.get("completed_count", 0) or 0,
            "summary_matched_count": summary.get("matched_count", 0) or 0,
        },
    )


@login_required
@never_cache
@ensure_csrf_cookie
def account_settings(request):
    provider = get_provider_for_user(request.user)
    customer_profile = None
    if not provider:
        customer_profile, _ = CustomerProfile.objects.get_or_create(user=request.user)
    notification_cursor = get_notification_cursor(request.user, create=True)

    allow_contact_tab = not bool(provider)
    active_tab = request.GET.get("tab") or "identity"
    allowed_tabs = {"identity", "notifications", "security", "danger"}
    if allow_contact_tab:
        allowed_tabs.add("contact")
    if active_tab not in allowed_tabs:
        active_tab = "identity"

    identity_form = AccountIdentityForm(instance=request.user, prefix="identity")
    contact_form = CustomerContactSettingsForm(instance=customer_profile, prefix="contact") if allow_contact_tab else None
    notification_form = NotificationPreferenceForm(instance=notification_cursor, prefix="notifications")
    password_form = AccountPasswordChangeForm(user=request.user, prefix="password")

    if request.method == "POST":
        action = (request.POST.get("form_action") or "").strip()
        if action == "identity":
            active_tab = "identity"
            identity_form = AccountIdentityForm(request.POST, instance=request.user, prefix="identity")
            if identity_form.is_valid():
                identity_form.save()
                messages.success(request, "Hesap bilgileriniz güncellendi.")
                return redirect("account_settings")
        elif action == "contact":
            if provider:
                messages.info(request, "Usta profil ve iletişim bilgileri Usta Profili sekmesinden güncellenir.")
                return redirect("provider_profile")
            active_tab = "contact"
            contact_form = CustomerContactSettingsForm(request.POST, instance=customer_profile, prefix="contact")
            if contact_form.is_valid():
                contact_form.save()
                messages.success(request, "İletişim bilgileriniz güncellendi.")
                return redirect("account_settings")
        elif action == "notifications":
            active_tab = "notifications"
            notification_form = NotificationPreferenceForm(
                request.POST,
                instance=notification_cursor,
                prefix="notifications",
            )
            if notification_form.is_valid():
                notification_form.save()
                invalidate_unread_notifications_cache(request.user)
                messages.success(request, "Bildirim tercihleriniz güncellendi.")
                return redirect(f"{reverse('account_settings')}?tab=notifications")
        elif action == "security":
            active_tab = "security"
            password_form = AccountPasswordChangeForm(user=request.user, data=request.POST, prefix="password")
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, "Şifreniz güncellendi.")
                return redirect("account_settings")
        elif action == "danger":
            active_tab = "danger"

    return render(
        request,
        "Myapp/account_settings.html",
        {
            "is_provider_user": bool(provider),
            "identity_form": identity_form,
            "contact_form": contact_form,
            "notification_form": notification_form,
            "password_form": password_form,
            "active_tab": active_tab,
            "allow_contact_tab": allow_contact_tab,
            "city_district_map_json": get_city_district_map_json(),
        },
    )



@login_required
@require_POST
def delete_account(request):
    expected_phrase = "HESABIMI SIL"
    confirm_phrase = " ".join(((request.POST.get("confirmation_text") or "").strip().upper()).split())
    confirm_phrase = unicodedata.normalize("NFKD", confirm_phrase).encode("ascii", "ignore").decode("ascii")
    password = request.POST.get("password") or ""

    if confirm_phrase != expected_phrase:
        messages.error(request, 'Hesap silme onayı için "HESABIMI SİL" yazmalısınız.')
        return redirect(f"{reverse('account_settings')}?tab=danger")

    if not request.user.check_password(password):
        messages.error(request, "Şifre doğrulaması başarısız.")
        return redirect(f"{reverse('account_settings')}?tab=danger")

    user = request.user
    provider = get_provider_for_user(user)
    with transaction.atomic():
        if provider:
            provider.delete()
        else:
            user.service_requests.all().delete()

        user.delete()

    logout(request)
    request.session.pop("role", None)
    messages.success(request, "Hesabınız kalıcı olarak silindi.")
    return redirect("index")


@login_required
@never_cache
def customer_requests_snapshot(request):
    if get_provider_for_user(request.user):
        return JsonResponse({"detail": "forbidden"}, status=403)
    maybe_refresh_marketplace_lifecycle_from_request()
    response = JsonResponse(build_customer_snapshot_payload(request.user))
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@login_required
@never_cache
def nav_live_stream(request):
    provider = get_provider_for_user(request.user)
    is_provider = bool(provider)
    if is_provider:
        provider, blocked_response = get_verified_provider_or_redirect(request, api=True)
        if blocked_response:
            return blocked_response

    interval_seconds = max(3, int(getattr(settings, "NAV_STREAM_INTERVAL_SECONDS", 8)))
    max_duration_seconds = max(15, int(getattr(settings, "NAV_STREAM_MAX_DURATION_SECONDS", 55)))
    min_reopen_seconds = get_nav_stream_reopen_min_seconds()
    stream_identity = f"provider:{provider.id}" if is_provider and provider else f"customer:{request.user.id}"
    active_key = f"nav-stream:active:{stream_identity}"
    reopen_key = f"nav-stream:last:{stream_identity}"
    lock_token = uuid4().hex
    now_ts = int(time.time())
    last_open_ts = cache.get(reopen_key)
    if isinstance(last_open_ts, int) and now_ts - last_open_ts < min_reopen_seconds:
        return JsonResponse({"detail": "stream-reopen-rate-limited"}, status=429)
    if not cache.add(active_key, lock_token, timeout=max_duration_seconds + 10):
        return JsonResponse({"detail": "stream-already-open"}, status=429)
    cache.set(reopen_key, now_ts, timeout=max(max_duration_seconds + 10, min_reopen_seconds))

    def build_payload():
        if is_provider:
            return build_provider_snapshot_payload(provider, user=request.user)
        return build_customer_snapshot_payload(request.user)

    def stream_events():
        started_at = timezone.now()
        yield "retry: 5000\n\n"
        try:
            try:
                maybe_refresh_marketplace_lifecycle_from_request()
            except Exception:
                # Snapshot delivery should keep working even if lifecycle refresh fails.
                pass

            while True:
                payload = build_payload()
                payload["stream_role"] = "provider" if is_provider else "customer"
                payload["stream_ts"] = timezone.now().isoformat()
                yield f"event: snapshot\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

                elapsed_seconds = (timezone.now() - started_at).total_seconds()
                if elapsed_seconds >= max_duration_seconds:
                    break
                time.sleep(interval_seconds)

            yield "event: end\ndata: {}\n\n"
        finally:
            if cache.get(active_key) == lock_token:
                cache.delete(active_key)

    response = StreamingHttpResponse(stream_events(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response["X-Accel-Buffering"] = "no"
    return response


@never_cache
def lifecycle_health(request):
    expected_token = get_lifecycle_health_token()
    if expected_token:
        provided_token = (request.headers.get("X-Health-Token") or request.GET.get("token") or "").strip()
        if provided_token != expected_token:
            return JsonResponse({"ok": False, "detail": "forbidden"}, status=403)

    worker_name = (request.GET.get("worker") or "marketplace_lifecycle").strip()[:80] or "marketplace_lifecycle"
    stale_after_seconds = get_lifecycle_heartbeat_stale_seconds()
    now = timezone.now()
    heartbeat = SchedulerHeartbeat.objects.filter(worker_name=worker_name).first()

    if heartbeat is None:
        payload = {
            "ok": False,
            "worker_name": worker_name,
            "status": "missing",
            "stale_after_seconds": stale_after_seconds,
            "message": "Scheduler heartbeat kaydı bulunamadı.",
        }
        response = JsonResponse(payload, status=503)
        response["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    reference_at = heartbeat.last_success_at or heartbeat.last_started_at or heartbeat.updated_at
    age_seconds = None
    is_stale = True
    if reference_at is not None:
        age_seconds = max(0, int((now - reference_at).total_seconds()))
        is_stale = age_seconds > stale_after_seconds

    payload = {
        "ok": not is_stale,
        "worker_name": worker_name,
        "status": "stale" if is_stale else "healthy",
        "stale_after_seconds": stale_after_seconds,
        "age_seconds": age_seconds,
        "run_count": heartbeat.run_count,
        "last_started_at": heartbeat.last_started_at.isoformat() if heartbeat.last_started_at else None,
        "last_success_at": heartbeat.last_success_at.isoformat() if heartbeat.last_success_at else None,
        "last_error_at": heartbeat.last_error_at.isoformat() if heartbeat.last_error_at else None,
        "last_error": heartbeat.last_error,
    }
    response = JsonResponse(payload, status=503 if is_stale else 200)
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@login_required
def complete_request(request, request_id):
    if request.method != "POST":
        return redirect("my_requests")
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "complete-request",
        "my_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "complete-request", "my_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    service_request = get_object_or_404(ServiceRequest, id=request_id, customer=request.user)
    if service_request.status != "matched":
        messages.warning(request, "Sadece eşleşen talepler tamamlandı olarak işaretlenebilir.")
        return redirect("my_requests")

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
                "Müşteri randevu seçmeden eşleşmeyi iptal etti"
                if appointment is None
                else "Müşteri aktif olmayan randevu sonrası talebi iptal etti"
            ),
        ):
            messages.warning(request, "Talep durumu güncellenemedi.")
            return redirect("my_requests")

        purge_request_messages(service_request.id)
        messages.success(request, "Talep iptal edildi.")
        return redirect("my_requests")

    if calendar_enabled and appointment and appointment.status == "pending":
        messages.warning(request, "Bekleyen randevu talebi varken talep tamamlanamaz.")
        return redirect("my_requests")
    if (
        calendar_enabled
        and appointment
        and appointment.status in {"confirmed", "pending_customer"}
        and appointment.scheduled_for > timezone.now()
    ):
        messages.warning(request, "Onayli randevu zamani gelmeden talep tamamlanamaz.")
        return redirect("my_requests")

    if not transition_service_request_status(
        service_request,
        "completed",
        actor_user=request.user,
        actor_role=actor_role,
        source="user",
        note="Müşteri talebi tamamladı",
    ):
        messages.warning(request, "Talep durumu güncellenemedi.")
        return redirect("my_requests")

    if calendar_enabled and appointment and appointment.status in {"confirmed", "pending_customer"}:
        if appointment.status == "pending_customer":
            transition_appointment_status(
                appointment,
                "confirmed",
                extra_update_fields=["updated_at"],
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Bekleyen eski randevu kaydı tamamlanmadan önce onaylandı",
            )
        transition_appointment_status(
            appointment,
            "completed",
            extra_update_fields=["updated_at"],
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Talep tamamlandı, randevu da tamamlandı",
        )

    purge_request_messages(service_request.id)
    messages.success(request, "Talep tamamlandı olarak güncellendi.")
    return redirect("my_requests")

@login_required
@require_POST
def create_appointment(request, request_id):
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")
    if not is_calendar_enabled():
        return calendar_disabled_redirect(request, "my_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "create-appointment",
        "my_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "create-appointment", "my_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    refresh_appointment_lifecycle()
    service_request = get_object_or_404(ServiceRequest, id=request_id, customer=request.user)
    if service_request.status != "matched" or service_request.matched_provider is None:
        messages.warning(request, "Randevu sadece eşleşen talepler için oluşturulabilir.")
        return redirect("my_requests")
    if not service_request.matched_provider.is_verified:
        messages.warning(request, "Bu usta henüz admin onaylı olmadığı için randevu oluşturulamaz.")
        return redirect("my_requests")

    existing = ServiceAppointment.objects.filter(service_request=service_request).first()
    if existing and existing.status == "completed":
        messages.warning(request, "Tamamlanan bir talep için yeni randevu oluşturulamaz.")
        return redirect("my_requests")

    form = AppointmentCreateForm(
        request.POST,
        provider=service_request.matched_provider,
        current_appointment_id=existing.id if existing else None,
    )
    if not form.is_valid():
        messages.error(request, get_first_form_error(form))
        return redirect("my_requests")

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
            note="Müşteri randevuyu yeniden planladı",
        ):
            messages.warning(request, "Bu randevu durumu yeniden planlama için uygun değil.")
            return redirect("my_requests")
        messages.success(request, "Randevu talebiniz güncellendi ve ustaya iletildi.")
        return redirect("my_requests")

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
        note="Müşteri yeni randevu talebi oluşturdu",
    )
    messages.success(request, "Randevu talebiniz ustaya iletildi.")
    return redirect("my_requests")


@login_required
@require_POST
def cancel_appointment(request, request_id):
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")
    if not is_calendar_enabled():
        return calendar_disabled_redirect(request, "my_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "cancel-appointment",
        "my_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "cancel-appointment", "my_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    refresh_appointment_lifecycle()
    service_request = get_object_or_404(ServiceRequest, id=request_id, customer=request.user)
    appointment = get_object_or_404(ServiceAppointment, service_request=service_request)
    if appointment.status not in {"pending", "pending_customer", "confirmed"}:
        messages.warning(request, "Bu randevu artik iptal edilemez.")
        return redirect("my_requests")

    cancel_policy = evaluate_appointment_cancel_policy(appointment)
    if appointment.status == "pending":
        cancel_policy = {
            "category": "standard",
            "minutes_to_start": cancel_policy.get("minutes_to_start"),
            "ui_note": "",
            "result_message": "Randevu iptal edildi.",
            "workflow_suffix": "",
        }
    workflow_note = "Müşteri randevuyu iptal etti"
    if cancel_policy["workflow_suffix"]:
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
    if cancel_policy["category"] in {"last_minute", "no_show"}:
        messages.warning(request, cancel_policy["result_message"])
    else:
        messages.success(request, cancel_policy["result_message"])
    return redirect("my_requests")


@login_required
@require_POST
def cancel_request(request, request_id):
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "cancel-request",
        "my_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "cancel-request", "my_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    service_request = get_object_or_404(ServiceRequest, id=request_id, customer=request.user)
    if service_request.status not in {"new", "pending_provider", "pending_customer"} or service_request.matched_provider is not None:
        messages.warning(request, "Bu talep artik iptal edilemez.")
        return redirect("my_requests")

    now = timezone.now()
    service_request.provider_offers.filter(status__in=["pending", "accepted"]).update(status="expired", responded_at=now)
    service_request.matched_provider = None
    service_request.matched_offer = None
    service_request.matched_at = None
    transition_service_request_status(
        service_request,
        "cancelled",
        extra_update_fields=["matched_provider", "matched_offer", "matched_at"],
        actor_user=request.user,
        actor_role=actor_role,
        source="user",
        note="Müşteri talebi iptal etti",
    )
    messages.success(request, "Talep aramasi iptal edildi.")
    return redirect("my_requests")


@login_required
@require_POST
def delete_cancelled_request(request, request_id):
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")

    service_request = get_object_or_404(ServiceRequest, id=request_id, customer=request.user)
    if service_request.status != "cancelled":
        messages.warning(request, "Sadece iptal edilen talepler silinebilir.")
        return redirect("my_requests")

    service_request.delete()
    messages.success(request, "İptal edilen talep silindi.")
    return redirect("my_requests")


@login_required
@require_POST
def delete_all_cancelled_requests(request):
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")

    deleted_count, _ = request.user.service_requests.filter(status="cancelled").delete()
    if deleted_count:
        messages.success(request, "İptal edilen talepler silindi.")
    else:
        messages.info(request, "Silinecek iptal edilen talep bulunamadı.")
    return redirect("my_requests")


@login_required
@require_POST
def select_provider_offer(request, request_id, offer_id):
    if get_provider_for_user(request.user):
        messages.error(request, "Bu alan sadece müşteri hesapları içindir.")
        return redirect("provider_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "select-provider-offer",
        "my_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "select-provider-offer", "my_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    service_request = get_object_or_404(ServiceRequest, id=request_id, customer=request.user)
    if (
        service_request.status not in {"pending_provider", "pending_customer"}
        or service_request.matched_provider is not None
        or service_request.matched_offer is not None
    ):
        messages.warning(request, "Bu talep için usta seçimi artık yapılamaz.")
        return redirect("my_requests")

    with transaction.atomic():
        service_request = ServiceRequest.objects.select_for_update().filter(id=service_request.id).first()
        if not service_request:
            messages.warning(request, "Talep bulunamadı.")
            return redirect("my_requests")
        if (
            service_request.status not in {"pending_provider", "pending_customer"}
            or service_request.matched_provider_id is not None
            or service_request.matched_offer_id is not None
        ):
            messages.warning(request, "Bu talep zaten eşleştirilmiş.")
            return redirect("my_requests")

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
            messages.warning(request, "Bu teklif artık seçilemez veya usta henüz admin onaylı değil.")
            return redirect("my_requests")

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
            note="Müşteri teklif seçti ve usta eşleşti",
        ):
            messages.warning(request, "Talep durumu eşleştirme için uygun değil.")
            return redirect("my_requests")

    messages.success(
        request,
        f"Talep {get_request_display_code(service_request)} için {selected_offer.provider.full_name} seçildi.",
    )
    return redirect("my_requests")

def build_provider_panel_context(request, provider):
    from .services.provider_panel import build_provider_panel_context as build_provider_panel_context_service

    return build_provider_panel_context_service(request, provider)


@login_required
def provider_requests(request):
    maybe_refresh_marketplace_lifecycle_from_request()
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response
    is_partial = is_panel_partial_request(request)
    context = build_provider_panel_context(request, provider)
    if is_partial:
        return render_panel_partial_response(
            request,
            template_name="Myapp/partials/provider_panel_content.html",
            context=context,
            snapshot=context["provider_live_snapshot"],
        )
    return render(request, "Myapp/provider_requests.html", context)


@login_required
@never_cache
def provider_panel_snapshot(request):
    provider, blocked_response = get_verified_provider_or_redirect(request, api=True)
    if blocked_response:
        return blocked_response

    maybe_refresh_marketplace_lifecycle_from_request()
    payload = build_provider_snapshot_payload(provider, user=request.user)
    response = JsonResponse(payload)
    response["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response



def provider_detail(request, provider_id):
    provider = get_object_or_404(
        Provider.objects.accepting_new_requests()
        .prefetch_related("service_types")
        .annotate(ratings_count=Count("ratings", distinct=True)),
        id=provider_id,
    )
    recent_ratings = list(provider.ratings.select_related("customer").order_by("-updated_at")[:10])
    completed_jobs = provider.service_requests.filter(status="completed").count()
    successful_quotes = provider.offers.filter(status="accepted").count()
    return render(
        request,
        "Myapp/provider_detail.html",
        {
            "provider": provider,
            "recent_ratings": recent_ratings,
            "completed_jobs": completed_jobs,
            "successful_quotes": successful_quotes,
        },
    )


@login_required
@require_POST
def provider_confirm_appointment(request, appointment_id):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response
    if not is_calendar_enabled():
        return calendar_disabled_redirect(request, "provider_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "provider-confirm-appointment",
        "provider_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "provider-confirm-appointment", "provider_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    refresh_appointment_lifecycle()
    appointment = get_object_or_404(
        ServiceAppointment.objects.select_related("service_request"),
        id=appointment_id,
        provider=provider,
    )
    if appointment.status != "pending":
        messages.warning(request, "Bu randevu talebi artık açık değil.")
        return redirect("provider_requests")

    max_short_note_chars = get_short_note_max_chars()
    provider_note = (request.POST.get("provider_note") or "").strip()
    if len(provider_note) > max_short_note_chars:
        messages.warning(request, f"Usta notu en fazla {max_short_note_chars} karakter olabilir.")
        return redirect("provider_requests")
    appointment.provider_note = provider_note
    if not transition_appointment_status(
        appointment,
        "confirmed",
        extra_update_fields=["provider_note", "updated_at"],
        actor_user=request.user,
        actor_role=actor_role,
        source="user",
        note="Usta randevuyu onayladı",
    ):
        messages.warning(request, "Randevu durumu usta onayı için uygun değil.")
        return redirect("provider_requests")
    messages.success(
        request,
        f"Talep {get_request_display_code(appointment.service_request)} için randevu onaylandı.",
    )
    return redirect("provider_requests")


@login_required
@require_POST
def provider_complete_appointment(request, appointment_id):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response
    if not is_calendar_enabled():
        return calendar_disabled_redirect(request, "provider_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "provider-complete-appointment",
        "provider_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "provider-complete-appointment", "provider_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    appointment = get_object_or_404(
        ServiceAppointment.objects.select_related("service_request"),
        id=appointment_id,
        provider=provider,
    )
    if appointment.status not in {"confirmed", "pending_customer"}:
        messages.warning(request, "Sadece onaylı randevular tamamlanabilir.")
        return redirect("provider_requests")

    if appointment.status == "pending_customer":
        transition_appointment_status(
            appointment,
            "confirmed",
            extra_update_fields=["updated_at"],
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Bekleyen eski randevu kaydı tamamlanmadan önce onaylandı",
        )

    if not transition_appointment_status(
        appointment,
        "completed",
        extra_update_fields=["updated_at"],
        actor_user=request.user,
        actor_role=actor_role,
        source="user",
        note="Usta randevuyu tamamladı",
    ):
        messages.warning(request, "Randevu durumu tamamlamaya uygun değil.")
        return redirect("provider_requests")

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
                note="Randevu tamamlandı, talep kapatıldı",
            )
        else:
            transition_service_request_status(
                service_request,
                "completed",
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Randevu tamamlandı, talep kapatıldı",
            )

    purge_request_messages(service_request.id)
    messages.success(
        request,
        f"Talep {get_request_display_code(service_request)} randevusu tamamlandı olarak işaretlendi.",
    )
    return redirect("provider_requests")


@login_required
@require_POST
def provider_reject_appointment(request, appointment_id):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response
    if not is_calendar_enabled():
        return calendar_disabled_redirect(request, "provider_requests")

    rate_limit_response = reject_rate_limited_request(
        request,
        "provider-reject-appointment",
        "provider_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "provider-reject-appointment", "provider_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    refresh_appointment_lifecycle()
    appointment = get_object_or_404(
        ServiceAppointment.objects.select_related("service_request"),
        id=appointment_id,
        provider=provider,
    )
    if appointment.status != "pending":
        messages.warning(request, "Bu randevu talebi artık açık değil.")
        return redirect("provider_requests")

    max_short_note_chars = get_short_note_max_chars()
    provider_note = (request.POST.get("provider_note") or "").strip()
    if len(provider_note) > max_short_note_chars:
        messages.warning(request, f"Usta notu en fazla {max_short_note_chars} karakter olabilir.")
        return redirect("provider_requests")
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
        messages.warning(request, "Randevu durumu red için uygun değil.")
        return redirect("provider_requests")
    messages.info(
        request,
        f"Talep {get_request_display_code(appointment.service_request)} randevusu reddedildi.",
    )
    return redirect("provider_requests")


@login_required
@require_POST
def provider_accept_offer(request, offer_id):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response
    membership_block = require_provider_membership_for_new_requests(request, provider)
    if membership_block:
        return membership_block

    rate_limit_response = reject_rate_limited_request(
        request,
        "provider-accept-offer",
        "provider_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "provider-accept-offer", "provider_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    with transaction.atomic():
        offer = (
            ProviderOffer.objects.select_for_update()
            .select_related("service_request")
            .filter(id=offer_id, provider=provider)
            .first()
        )
        if not offer:
            messages.warning(request, "Teklif bulunamadı.")
            return redirect("provider_requests")

        service_request = ServiceRequest.objects.select_for_update().filter(id=offer.service_request_id).first()
        if not service_request:
            messages.warning(request, "Talep artık mevcut değil.")
            return redirect("provider_requests")

        if offer.status != "pending":
            messages.warning(request, "Bu teklif artık açık değil.")
            return redirect("provider_requests")

        if service_request.status in {"matched", "completed", "cancelled"}:
            offer.status = "expired"
            offer.responded_at = timezone.now()
            offer.save(update_fields=["status", "responded_at"])
            messages.warning(request, "Bu talep artık açık değil.")
            return redirect("provider_requests")

        max_short_note_chars = get_short_note_max_chars()
        quote_note = (request.POST.get("quote_note") or "").strip()
        if len(quote_note) > max_short_note_chars:
            messages.warning(request, f"Teklif notu en fazla {max_short_note_chars} karakter olabilir.")
            return redirect("provider_requests")

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
                note="Özel usta talebi kabul edildi ve doğrudan eşleşti",
            ):
                messages.warning(request, "Talep durumu eşleşme için güncellenemedi.")
                return redirect("provider_requests")
        else:
            if not transition_service_request_status(
                service_request,
                "pending_customer",
                actor_user=request.user,
                actor_role=actor_role,
                source="user",
                note="Usta teklif verdi, müşteri seçimi bekleniyor",
            ):
                messages.warning(request, "Talep durumu teklif sonrası güncellenemedi.")
                return redirect("provider_requests")

    if service_request.preferred_provider_id == provider.id and service_request.status == "matched":
        messages.success(
            request,
            f"Talep {get_request_display_code(service_request)} için müşteriyle doğrudan eşleştiniz.",
        )
    else:
        messages.success(
            request,
            f"Talep {get_request_display_code(service_request)} iş teklifiniz müşteriye gönderildi.",
        )
    return redirect("provider_requests")


@login_required
@require_POST
def provider_reject_offer(request, offer_id):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response

    rate_limit_response = reject_rate_limited_request(
        request,
        "provider-reject-offer",
        "provider_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "provider-reject-offer", "provider_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    offer = get_object_or_404(
        ProviderOffer.objects.select_related("service_request"),
        id=offer_id,
        provider=provider,
        status="pending",
    )
    now = timezone.now()
    service_request = offer.service_request

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
                note="Reddedilen teklif sonrası müşteri seçimi bekleniyor",
            )
        messages.info(
            request,
            f"Talep {get_request_display_code(service_request)} reddedildi. Diğer ustalardan gelecek onay bekleniyor.",
        )
        return redirect("provider_requests")

    if has_accepted_offer:
        transition_service_request_status(
            service_request,
            "pending_customer",
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Reddedilen teklif sonrası müşteri seçimi bekleniyor",
        )
        messages.info(
            request,
            f"Talep {get_request_display_code(service_request)} reddedildi. Müşterinin teklif seçimi bekleniyor.",
        )
        return redirect("provider_requests")

    dispatch_result = dispatch_next_provider_offer(
        service_request,
        actor_user=request.user,
        actor_role=actor_role,
        source="user",
        note="Usta teklifi reddetti, sıradaki adaylara geçildi",
    )
    if dispatch_result["result"] == "offers-created":
        offer_count = len(dispatch_result["offers"])
        messages.info(
            request,
            f"Talep {get_request_display_code(service_request)} reddedildi. {offer_count} yeni ustaya teklif açıldı.",
        )
    else:
        messages.warning(
            request,
            f"Talep {get_request_display_code(service_request)} için yeni aday bulunamadı. Kayıt korunuyor.",
        )
    return redirect("provider_requests")


@login_required
@require_POST
def provider_withdraw_offer(request, offer_id):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response

    rate_limit_response = reject_rate_limited_request(
        request,
        "provider-withdraw-offer",
        "provider_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "provider-withdraw-offer", "provider_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    with transaction.atomic():
        offer = (
            ProviderOffer.objects.select_for_update()
            .select_related("service_request")
            .filter(id=offer_id, provider=provider)
            .first()
        )
        if not offer:
            messages.warning(request, "Teklif bulunamadı.")
            return redirect("provider_requests")

        service_request = ServiceRequest.objects.select_for_update().filter(id=offer.service_request_id).first()
        if not service_request:
            messages.warning(request, "Talep artık mevcut değil.")
            return redirect("provider_requests")

        if (
            offer.status != "accepted"
            or service_request.status != "pending_customer"
            or service_request.matched_provider_id is not None
        ):
            messages.warning(request, "Bu teklif artık geri çekilemez.")
            return redirect("provider_requests")

        now = timezone.now()
        offer.status = "expired"
        offer.responded_at = now
        offer.save(update_fields=["status", "responded_at"])

        reroute_result = reroute_service_request_after_provider_exit(
            service_request,
            actor_user=request.user,
            actor_role=actor_role,
            source="user",
            note="Usta müşteri seçimi bekleyen teklifini geri çekti",
        )
        if reroute_result["result"] == "invalid-state":
            messages.warning(request, "Talep durumu güncellenemedi.")
            return redirect("provider_requests")

    messages.info(
        request,
        f"Talep {get_request_display_code(service_request)} için teklifinizi geri çektiniz.",
    )
    return redirect("provider_requests")


@login_required
@require_POST
def provider_release_request(request, request_id):
    provider, blocked_response = get_verified_provider_or_redirect(request)
    if blocked_response:
        return blocked_response

    rate_limit_response = reject_rate_limited_request(
        request,
        "provider-release-request",
        "provider_requests",
        max_attempts=get_action_rate_limit_max_attempts(),
        window_seconds=get_action_rate_limit_window_seconds(),
    )
    if rate_limit_response:
        return rate_limit_response

    duplicate_response = reject_duplicate_submission(request, "provider-release-request", "provider_requests")
    if duplicate_response:
        return duplicate_response

    actor_role = infer_actor_role(request.user)
    with transaction.atomic():
        service_request = (
            ServiceRequest.objects.select_for_update()
            .filter(id=request_id, matched_provider=provider)
            .first()
        )
        if not service_request:
            messages.warning(request, "Aktif iş bulunamadı.")
            return redirect("provider_requests")

        appointment = None
        if is_calendar_enabled():
            appointment = (
                ServiceAppointment.objects.select_for_update()
                .filter(service_request=service_request)
                .first()
            )

        if not provider_can_release_request_match(
            service_request,
            appointment,
                calendar_enabled=is_calendar_enabled(),
        ):
            messages.warning(request, "Bu iş için sonlandırma aksiyonu şu anda uygun değil.")
            return redirect("provider_requests")

        now = timezone.now()
        matched_offer = None
        if service_request.matched_offer_id:
            matched_offer = (
                ProviderOffer.objects.select_for_update()
                .filter(id=service_request.matched_offer_id)
                .first()
            )

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
            note="Usta müşteriden yanıt beklediği eşleşmeyi sonlandırdı",
        )
        if reroute_result["result"] == "invalid-state":
            messages.warning(request, "Talep durumu güncellenemedi.")
            return redirect("provider_requests")

    messages.info(
        request,
        f"Talep {get_request_display_code(service_request)} için eşleşmeyi sonlandırdınız.",
    )
    return redirect("provider_requests")
