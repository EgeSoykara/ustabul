from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.authentication import JWTAuthentication


@database_sync_to_async
def _resolve_user_from_token(raw_token):
    token = str(raw_token or "").strip()
    if not token:
        return AnonymousUser()

    try:
        validated = JWTAuthentication().get_validated_token(token)
        user = JWTAuthentication().get_user(validated)
        return user or AnonymousUser()
    except Exception:
        return AnonymousUser()


class JwtAuthMiddleware:
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        current_user = scope.get("user")
        if getattr(current_user, "is_authenticated", False):
            return await self.inner(scope, receive, send)

        token = ""
        query_string = scope.get("query_string", b"").decode("utf-8", "ignore")
        if query_string:
            token = parse_qs(query_string).get("token", [""])[0]

        if not token:
            for header_key, header_value in scope.get("headers", []):
                if header_key == b"authorization":
                    raw_value = header_value.decode("utf-8", "ignore")
                    if raw_value.lower().startswith("bearer "):
                        token = raw_value[7:].strip()
                    break

        scope["user"] = await _resolve_user_from_token(token)
        return await self.inner(scope, receive, send)

