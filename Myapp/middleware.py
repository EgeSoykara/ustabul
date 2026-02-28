import traceback

from django.conf import settings
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import Http404

from .models import ErrorLog


class ErrorLoggingMiddleware:
    """Persist unexpected server errors for quick admin-side triage."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if not getattr(settings, "ERROR_LOGGING_ENABLED", True):
            return None
        if isinstance(exception, (Http404, PermissionDenied, SuspiciousOperation)):
            return None

        try:
            traceback_max_chars = max(500, int(getattr(settings, "ERROR_LOG_TRACEBACK_MAX_CHARS", 12000)))
            message_max_chars = max(80, int(getattr(settings, "ERROR_LOG_MESSAGE_MAX_CHARS", 500)))
            raw_traceback = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
            status_code = int(getattr(exception, "status_code", 500) or 500)
            user = request.user if getattr(request, "user", None) and request.user.is_authenticated else None
            request_id = request.headers.get("X-Request-ID", "")[:120]
            ip_address = self._extract_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]

            ErrorLog.objects.create(
                path=(request.path or "")[:300],
                method=(request.method or "")[:10],
                status_code=status_code,
                message=str(exception)[:message_max_chars],
                traceback=raw_traceback[:traceback_max_chars],
                request_id=request_id,
                ip_address=ip_address,
                user_agent=user_agent,
                user=user,
            )
        except Exception:
            # Error logging should never break the request lifecycle.
            pass

        return None

    @staticmethod
    def _extract_client_ip(request):
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()[:64]
        return request.META.get("REMOTE_ADDR", "")[:64]
