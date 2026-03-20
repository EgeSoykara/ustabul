from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import ProviderOffer, ProviderRating, ServiceAppointment, ServiceMessage, ServiceRequest
from .realtime import publish_mobile_refresh_for_request, publish_mobile_refresh_for_user_ids


@receiver(post_save, sender=ServiceRequest)
def service_request_mobile_live_refresh(sender, instance, **kwargs):
    publish_mobile_refresh_for_request(
        instance,
        reason="request.changed",
        areas=("dashboard", "notifications", "request_detail"),
    )


@receiver(post_save, sender=ProviderOffer)
def provider_offer_mobile_live_refresh(sender, instance, **kwargs):
    service_request = getattr(instance, "service_request", None)
    if service_request is None:
        return
    provider_user_id = getattr(getattr(instance, "provider", None), "user_id", None)
    publish_mobile_refresh_for_user_ids(
        [service_request.customer_id, provider_user_id],
        reason="offer.changed",
        request_id=service_request.id,
        areas=("dashboard", "notifications", "request_detail"),
    )


@receiver(post_save, sender=ServiceAppointment)
def service_appointment_mobile_live_refresh(sender, instance, **kwargs):
    publish_mobile_refresh_for_user_ids(
        [instance.customer_id, getattr(instance.provider, "user_id", None)],
        reason="appointment.changed",
        request_id=instance.service_request_id,
        areas=("dashboard", "notifications", "request_detail"),
    )


@receiver(post_save, sender=ProviderRating)
def provider_rating_mobile_live_refresh(sender, instance, **kwargs):
    publish_mobile_refresh_for_user_ids(
        [instance.customer_id, getattr(instance.provider, "user_id", None)],
        reason="rating.changed",
        request_id=instance.service_request_id,
        areas=("dashboard", "notifications", "request_detail"),
    )


@receiver(post_save, sender=ServiceMessage)
def service_message_mobile_live_refresh(sender, instance, created, **kwargs):
    reason = "message.created" if created else "message.changed"
    service_request = getattr(instance, "service_request", None)
    if service_request is None:
        return
    publish_mobile_refresh_for_user_ids(
        [
            service_request.customer_id,
            getattr(getattr(service_request, "matched_provider", None), "user_id", None),
        ],
        reason=reason,
        request_id=service_request.id,
        areas=("dashboard", "notifications", "request_detail", "messages"),
    )

