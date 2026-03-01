from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer

from .models import Provider, ServiceRequest


def request_messages_group_name(request_id):
    return f"request_messages_{int(request_id)}"


def _resolve_thread_access(*, user_id, request_id):
    if not user_id:
        return {"ok": False, "reason": "unauthorized"}

    service_request = (
        ServiceRequest.objects.select_related(
            "customer",
            "matched_provider",
            "matched_offer",
            "matched_offer__provider",
        )
        .filter(id=request_id)
        .first()
    )
    if not service_request:
        return {"ok": False, "reason": "not-found"}

    provider = Provider.objects.filter(user_id=user_id).first()
    if provider:
        if not provider.is_verified:
            return {"ok": False, "reason": "pending-approval"}
        if service_request.matched_provider_id != provider.id:
            return {"ok": False, "reason": "forbidden"}
        if service_request.status != "matched":
            return {"ok": False, "reason": "thread-closed"}
        matched_offer = service_request.matched_offer
        if matched_offer is None or matched_offer.provider_id != provider.id:
            return {"ok": False, "reason": "not-selected-by-customer"}
        return {"ok": True, "viewer_role": "provider"}

    if service_request.customer_id != user_id:
        return {"ok": False, "reason": "forbidden"}
    if service_request.status != "matched":
        return {"ok": False, "reason": "thread-closed"}
    if service_request.matched_provider and not service_request.matched_provider.is_verified:
        return {"ok": False, "reason": "provider-not-verified"}
    if service_request.matched_offer_id is None:
        return {"ok": False, "reason": "provider-not-selected"}
    return {"ok": True, "viewer_role": "customer"}


class RequestMessagesConsumer(AsyncJsonWebsocketConsumer):
    CLOSE_CODES = {
        "unauthorized": 4401,
        "forbidden": 4403,
        "pending-approval": 4403,
        "not-selected-by-customer": 4403,
        "provider-not-verified": 4403,
        "provider-not-selected": 4403,
        "not-found": 4404,
        "thread-closed": 4409,
    }

    async def connect(self):
        user = self.scope.get("user")
        request_id_raw = self.scope.get("url_route", {}).get("kwargs", {}).get("request_id")
        if not request_id_raw or not str(request_id_raw).isdigit():
            await self.close(code=4404)
            return

        self.request_id = int(request_id_raw)
        access = await database_sync_to_async(_resolve_thread_access)(
            user_id=getattr(user, "id", None),
            request_id=self.request_id,
        )
        if not access.get("ok"):
            reason = access.get("reason", "forbidden")
            await self.close(code=self.CLOSE_CODES.get(reason, 4403))
            return

        self.viewer_role = access["viewer_role"]
        self.group_name = request_messages_group_name(self.request_id)
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        group_name = getattr(self, "group_name", "")
        if group_name:
            await self.channel_layer.group_discard(group_name, self.channel_name)
        await super().disconnect(close_code)

    async def receive_json(self, content, **kwargs):
        event_type = (content or {}).get("type")
        if event_type == "ping":
            await self.send_json({"type": "pong"})

    async def service_message_created(self, event):
        raw_message = event.get("message") or {}
        if not raw_message:
            return
        payload = dict(raw_message)
        payload["mine"] = payload.get("sender_role") == getattr(self, "viewer_role", "")
        await self.send_json({"type": "message.created", "message": payload})
