import base64
import json
import logging
from functools import lru_cache
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.conf import settings
from django.db import transaction

from .models import ActivityLog, MobileDevice, NotificationCursor, ProviderOffer, ServiceAppointment
from .services.flow import get_service_request_status_label


logger = logging.getLogger(__name__)
FCM_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
MAX_PUSH_BODY_LENGTH = 140

REQUEST_STATUS_LABELS = {
    "new": "Yeni",
    "pending_provider": "Usta onayı bekleniyor",
    "pending_customer": "Müşteri seçimi bekleniyor",
    "matched": "Eşleşti",
    "completed": "Tamamlandı",
    "cancelled": "İptal edildi",
}
APPOINTMENT_STATUS_LABELS = {
    "pending": "Usta onayı bekleniyor",
    "pending_customer": "Müşteri onayı bekleniyor",
    "confirmed": "Onaylandı",
    "rejected": "Reddedildi",
    "cancelled": "İptal edildi",
    "completed": "Tamamlandı",
}


def _truncate(text, max_len=MAX_PUSH_BODY_LENGTH):
    value = str(text or "").strip()
    if len(value) <= max_len:
        return value
    return value[: max_len - 1].rstrip() + "…"


def _get_request_code(service_request):
    if not service_request:
        return "-"
    return getattr(service_request, "display_code", "") or getattr(service_request, "request_code", "") or f"TLP-{service_request.id}"


def _is_mobile_push_configured():
    if not getattr(settings, "MOBILE_PUSH_ENABLED", True):
        return False
    if getattr(settings, "FCM_PROJECT_ID", "").strip():
        return True
    if getattr(settings, "FCM_SERVICE_ACCOUNT_FILE", "").strip():
        return True
    if getattr(settings, "FCM_SERVICE_ACCOUNT_JSON", "").strip():
        return True
    return False


def _load_service_account_info():
    raw_json = getattr(settings, "FCM_SERVICE_ACCOUNT_JSON", "").strip()
    if raw_json:
        try:
            if raw_json.startswith("{"):
                return json.loads(raw_json)
            decoded = base64.b64decode(raw_json).decode("utf-8")
            return json.loads(decoded)
        except Exception:
            logger.warning("FCM_SERVICE_ACCOUNT_JSON could not be parsed.")
            return None

    service_account_file = getattr(settings, "FCM_SERVICE_ACCOUNT_FILE", "").strip()
    if service_account_file:
        try:
            with open(service_account_file, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except OSError:
            logger.warning("FCM service account file could not be read: %s", service_account_file)
            return None
        except json.JSONDecodeError:
            logger.warning("FCM service account file is not valid JSON: %s", service_account_file)
            return None
    return None


@lru_cache(maxsize=1)
def _build_google_credentials():
    service_account_info = _load_service_account_info()
    if not service_account_info:
        return None

    try:
        from google.oauth2 import service_account
    except ImportError:
        logger.warning("google-auth package is missing; mobile push is disabled.")
        return None

    try:
        return service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=FCM_SCOPES,
        )
    except Exception:
        logger.exception("FCM credentials could not be created.")
        return None


def _get_fcm_project_id():
    configured = getattr(settings, "FCM_PROJECT_ID", "").strip()
    if configured:
        return configured
    service_account_info = _load_service_account_info() or {}
    return str(service_account_info.get("project_id") or "").strip()


def _get_fcm_access_token():
    credentials = _build_google_credentials()
    if credentials is None:
        return None

    try:
        from google.auth.transport.requests import Request as GoogleAuthRequest
    except ImportError:
        logger.warning("google-auth transport dependencies are missing; mobile push is disabled.")
        return None

    try:
        if not credentials.valid:
            credentials.refresh(GoogleAuthRequest())
        return credentials.token
    except Exception:
        logger.exception("FCM access token could not be refreshed.")
        return None


def _clear_stale_push_token(push_token):
    if push_token:
        MobileDevice.objects.filter(push_token=push_token).update(push_token=None)


def _notification_pref_enabled(user_id, category):
    cursor = NotificationCursor.objects.filter(user_id=user_id).only(
        "allow_message_notifications",
        "allow_request_notifications",
        "allow_appointment_notifications",
    ).first()
    if cursor is None:
        return True
    if category == "message":
        return bool(cursor.allow_message_notifications)
    if category == "request":
        return bool(cursor.allow_request_notifications)
    if category == "appointment":
        return bool(cursor.allow_appointment_notifications)
    return True


def _collect_request_provider_user_ids(service_request):
    if not service_request:
        return set()
    if service_request.matched_provider_id:
        matched_provider = getattr(service_request, "matched_provider", None)
        matched_user_id = getattr(matched_provider, "user_id", None)
        if matched_user_id:
            return {matched_user_id}

    if service_request.status == "pending_customer":
        return set(
            ProviderOffer.objects.filter(
                service_request=service_request,
                status="accepted",
                provider__is_verified=True,
            ).values_list("provider__user_id", flat=True)
        )

    if service_request.status == "pending_provider":
        return set(
            ProviderOffer.objects.filter(
                service_request=service_request,
                status="pending",
                provider__is_verified=True,
            ).values_list("provider__user_id", flat=True)
        )

    return set()


def _build_push_recipients(activity_log):
    recipients = set()
    action_type = activity_log.action_type
    actor_user_id = activity_log.actor_user_id
    service_request = activity_log.service_request
    appointment = activity_log.appointment

    if action_type == "message_sent":
        if not service_request:
            return recipients
        sender_role = getattr(activity_log.message, "sender_role", "")
        if sender_role == "customer":
            matched_provider = getattr(service_request, "matched_provider", None)
            provider_user_id = getattr(matched_provider, "user_id", None)
            if provider_user_id:
                recipients.add((provider_user_id, "message"))
        elif service_request.customer_id:
            recipients.add((service_request.customer_id, "message"))
    elif action_type == "request_status":
        if service_request and service_request.customer_id:
            recipients.add((service_request.customer_id, "request"))
        for provider_user_id in _collect_request_provider_user_ids(service_request):
            recipients.add((provider_user_id, "request"))
    elif action_type == "appointment_status":
        if service_request and service_request.customer_id:
            recipients.add((service_request.customer_id, "appointment"))
        if appointment:
            provider = getattr(appointment, "provider", None)
            provider_user_id = getattr(provider, "user_id", None)
            if provider_user_id:
                recipients.add((provider_user_id, "appointment"))

    return {
        (user_id, category)
        for (user_id, category) in recipients
        if user_id and user_id != actor_user_id and _notification_pref_enabled(user_id, category)
    }


def _build_push_content(activity_log):
    service_request = activity_log.service_request
    appointment = activity_log.appointment
    request_code = _get_request_code(service_request)

    if activity_log.action_type == "message_sent":
        message_body = ""
        if activity_log.message_id:
            message_body = getattr(activity_log.message, "body", "") or ""
        body = _truncate(message_body) or f"Talep {request_code} için yeni mesaj var."
        return {
            "category": "message",
            "title": "Yeni mesaj",
            "body": body,
            "data": {
                "type": "message",
                "request_id": str(service_request.id if service_request else ""),
                "request_code": request_code,
            },
        }

    if activity_log.action_type == "appointment_status":
        appointment_status = getattr(appointment, "status", "") or ""
        status_label = APPOINTMENT_STATUS_LABELS.get(appointment_status, appointment_status or "Güncellendi")
        return {
            "category": "appointment",
            "title": "Randevu güncellendi",
            "body": f"Talep {request_code}: {status_label}",
            "data": {
                "type": "appointment",
                "request_id": str(service_request.id if service_request else ""),
                "appointment_id": str(appointment.id if appointment else ""),
                "request_code": request_code,
                "status": appointment_status,
            },
        }

    request_status = getattr(service_request, "status", "") or ""
    status_label = (
        get_service_request_status_label(service_request)
        if service_request is not None
        else REQUEST_STATUS_LABELS.get(request_status, request_status or "Güncellendi")
    )
    return {
        "category": "request",
        "title": "Talep güncellendi",
        "body": f"Talep {request_code}: {status_label}",
        "data": {
            "type": "request",
            "request_id": str(service_request.id if service_request else ""),
            "request_code": request_code,
            "status": request_status,
        },
    }


def _iter_recipient_devices(recipient_refs):
    recipient_user_ids = [user_id for user_id, _category in recipient_refs]
    if not recipient_user_ids:
        return []

    devices = (
        MobileDevice.objects.filter(user_id__in=recipient_user_ids)
        .exclude(push_token__isnull=True)
        .exclude(push_token="")
        .values("id", "user_id", "push_token", "platform")
    )
    category_map = {user_id: category for user_id, category in recipient_refs}
    result = []
    for device in devices:
        category = category_map.get(device["user_id"])
        if category:
            result.append(
                {
                    "device_id": device["id"],
                    "user_id": device["user_id"],
                    "push_token": device["push_token"],
                    "platform": device["platform"],
                    "category": category,
                }
            )
    return result


def _build_fcm_message(token, title, body, data):
    data_payload = {key: str(value) for key, value in (data or {}).items() if value not in (None, "")}
    channel_id = getattr(settings, "MOBILE_PUSH_ANDROID_CHANNEL_ID", "ustabul_general")
    return {
        "message": {
            "token": token,
            "notification": {
                "title": title,
                "body": body,
            },
            "data": data_payload,
            "android": {
                "priority": "high",
                "notification": {
                    "channel_id": channel_id,
                    "sound": "default",
                },
            },
            "apns": {
                "headers": {
                    "apns-priority": "10",
                },
                "payload": {
                    "aps": {
                        "sound": "default",
                    }
                },
            },
        }
    }


def _send_fcm_message(push_token, title, body, data):
    project_id = _get_fcm_project_id()
    access_token = _get_fcm_access_token()
    if not project_id or not access_token:
        return False, False

    payload = json.dumps(_build_fcm_message(push_token, title, body, data)).encode("utf-8")
    request = Request(
        url=f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {access_token}",
        },
    )
    try:
        with urlopen(request, timeout=8) as response:
            response.read()
        return True, False
    except HTTPError as error:
        invalid_token = False
        try:
            body_text = error.read().decode("utf-8")
            payload = json.loads(body_text or "{}")
            error_text = json.dumps(payload)
            invalid_token = "UNREGISTERED" in error_text or "registration-token-not-registered" in error_text
        except Exception:
            invalid_token = error.code in {404, 410}
        if invalid_token:
            _clear_stale_push_token(push_token)
            return False, True
        logger.warning("FCM push request failed with HTTP %s.", error.code)
        return False, False
    except URLError:
        logger.warning("FCM push request could not reach the server.")
        return False, False
    except Exception:
        logger.exception("Unexpected error while sending FCM push.")
        return False, False


def send_mobile_push_for_activity(activity_log_id):
    if not _is_mobile_push_configured():
        return False

    activity_log = (
        ActivityLog.objects.select_related(
            "service_request",
            "appointment",
            "appointment__provider",
            "service_request__matched_provider",
            "message",
        )
        .filter(id=activity_log_id)
        .first()
    )
    if activity_log is None:
        return False

    recipients = _build_push_recipients(activity_log)
    if not recipients:
        return False

    push_content = _build_push_content(activity_log)
    devices = _iter_recipient_devices(recipients)
    if not devices:
        return False

    sent_any = False
    for device in devices:
        sent, _invalid = _send_fcm_message(
            device["push_token"],
            push_content["title"],
            push_content["body"],
            {
                **push_content["data"],
                "platform": device["platform"],
                "user_id": str(device["user_id"]),
            },
        )
        sent_any = sent_any or sent
    return sent_any


def queue_mobile_push_for_activity(activity_log_id):
    if not _is_mobile_push_configured():
        return
    transaction.on_commit(lambda: send_mobile_push_for_activity(activity_log_id))
