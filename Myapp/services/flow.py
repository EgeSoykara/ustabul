from django.utils import timezone


def build_recent_change_from_event(event):
    if not event:
        return None

    if event.target_type == "appointment":
        if event.to_status == "pending":
            return {"label": "Randevu talebi", "tone": "warning"}
        if event.to_status in {"pending_customer", "confirmed"}:
            return {"label": "Randevu güncellendi", "tone": "info"}
        if event.to_status in {"cancelled", "rejected"}:
            return {"label": "Randevu iptal edildi", "tone": "danger"}
        if event.to_status == "completed":
            return {"label": "Randevu tamamlandı", "tone": "success"}
        return {"label": "Randevu güncellendi", "tone": "info"}

    if event.to_status == "pending_provider":
        return {"label": "Yeni talep", "tone": "warning"}
    if event.to_status == "pending_customer":
        return {"label": "Teklif kabul edildi", "tone": "info"}
    if event.to_status == "matched":
        return {"label": "Eşleşme tamamlandı", "tone": "success"}
    if event.to_status == "completed":
        return {"label": "İş tamamlandı", "tone": "success"}
    if event.to_status == "cancelled":
        return {"label": "Müşteri iptal etti", "tone": "danger"}
    return {"label": "Talep güncellendi", "tone": "info"}


def assign_recent_change_state(target, latest_message=None, latest_event=None):
    if latest_message and (not latest_event or latest_message.created_at >= latest_event.created_at):
        target.recent_change_label = "Yeni mesaj"
        target.recent_change_tone = "danger"
        return

    event_change = build_recent_change_from_event(latest_event)
    if event_change:
        target.recent_change_label = event_change["label"]
        target.recent_change_tone = event_change["tone"]
        return

    target.recent_change_label = ""
    target.recent_change_tone = "muted"


def build_customer_flow_state(
    service_request,
    appointment,
    *,
    has_accepted_offers=False,
    now=None,
    calendar_enabled,
    last_minute_cancel_hours=0,
    no_show_grace_minutes=0,
):
    reference_time = now or timezone.now()
    flow = {
        "step": "Adım 1/4",
        "title": "Usta yanıtı bekleniyor",
        "hint": "Talebiniz uygun ustalara iletildi. Usta dönüşlerini bekleyin.",
        "next_action": "Şimdilik bekleyin veya isterseniz talebi iptal edin.",
        "tone": "waiting",
    }
    status = service_request.status

    if status in {"new", "pending_provider"} and service_request.preferred_provider_id:
        flow.update(
            {
                "title": "Seçtiğiniz usta yanıtı bekleniyor",
                "hint": "Talebiniz doğrudan seçtiğiniz ustaya iletildi.",
                "next_action": "Usta onay verirse otomatik eşleşeceksiniz.",
                "tone": "waiting",
            }
        )

    if status == "pending_customer":
        flow.update(
            {
                "step": "Adım 2/4",
                "title": "Usta seçimi sizde",
                "hint": "Teklifler geldiyse bir ustayı seçip ilerleyin.",
                "next_action": "Listeden bir ustayı seçin.",
                "tone": "action",
            }
        )
        if not has_accepted_offers:
            flow.update(
                {
                    "title": "Teklifler hazırlanıyor",
                    "hint": "Henüz seçilebilir teklif oluşmadı.",
                    "next_action": "Ustalardan yeni teklif gelmesini bekleyin.",
                    "tone": "waiting",
                }
            )
        return flow

    if status == "matched":
        if not calendar_enabled:
            return {
                "step": "Adım 3/3",
                "title": "Usta seçildi",
                "hint": "Usta ile mesajlaşıp işi netleştirebilirsiniz.",
                "next_action": "İş tamamlandığında talebi tamamlandı olarak kapatın.",
                "tone": "action",
            }
        flow.update(
            {
                "step": "Adım 3/4",
                "title": "Usta seçildi",
                "hint": "Şimdi randevu zamanını belirleyin.",
                "next_action": "Randevu saati seçip ustaya gönderin.",
                "tone": "action",
            }
        )
        if not appointment:
            return flow

        appointment_status = appointment.status
        if appointment_status == "pending":
            flow.update(
                {
                    "title": "Randevu usta onayında",
                    "hint": "Randevu talebiniz ustaya iletildi.",
                    "next_action": "Ustanın randevu onayını bekleyin.",
                    "tone": "waiting",
                }
            )
        elif appointment_status in {"pending_customer", "confirmed"}:
            is_future = bool(appointment.scheduled_for and appointment.scheduled_for > reference_time)
            if is_future:
                flow.update(
                    {
                        "title": "Randevu onaylandı",
                        "hint": (
                            "Randevu tarihi netleşti. Saatinde hazır olmanız yeterli. "
                            f"Son dakika iptal politikası: {last_minute_cancel_hours} saat kala iptaller "
                            "son dakika olarak kaydedilir."
                        ),
                        "next_action": "Randevu sonrası işi tamamlandı olarak işaretleyin.",
                        "tone": "success",
                    }
                )
            else:
                flow.update(
                    {
                        "title": "Randevu saati geldi",
                        "hint": (
                            "İş tamamlandıysa talebi kapatabilirsiniz. "
                            f"Randevu saatinden sonra {no_show_grace_minutes} dakika gecikmeli iptaller "
                            "no-show olarak kaydedilir."
                        ),
                        "next_action": "İş bittiyse Tamamlandı butonunu kullanın.",
                        "tone": "action",
                    }
                )
        elif appointment_status in {"rejected", "cancelled"}:
            flow.update(
                {
                    "title": "Randevu yeniden planlanmalı",
                    "hint": "Mevcut randevu aktif değil.",
                    "next_action": "Yeni bir randevu saati belirleyin.",
                    "tone": "danger",
                }
            )
        elif appointment_status == "completed":
            flow.update(
                {
                    "title": "Randevu tamamlandı",
                    "hint": "İş kapatma aşamasına geçebilirsiniz.",
                    "next_action": "Talep tamamlandıysa puanlama yapabilirsiniz.",
                    "tone": "success",
                }
            )
        return flow

    if status == "completed":
        if not calendar_enabled:
            return {
                "step": "Adım 3/3",
                "title": "İş tamamlandı",
                "hint": "Talep başarıyla tamamlandı.",
                "next_action": "Ustayı puanlayarak süreci bitirebilirsiniz.",
                "tone": "success",
            }
        has_completed_appointment = bool(appointment and appointment.status == "completed")
        if not has_completed_appointment:
            return {
                "step": "Kapalı",
                "title": "Talep iptal edildi",
                "hint": "Randevu seçilmeden kapanan talepler iptal olarak gösterilir.",
                "next_action": "Gerekirse yeni bir talep oluşturun.",
                "tone": "muted",
            }
        return {
            "step": "Adım 4/4",
            "title": "İş tamamlandı",
            "hint": "Talep başarıyla tamamlandı.",
            "next_action": (
                "Ustayı puanlayarak süreci bitirebilirsiniz."
                if has_completed_appointment
                else "Randevu onayı olmadan kapanan işlerde puanlama kapalıdır."
            ),
            "tone": "success" if has_completed_appointment else "muted",
        }

    if status == "cancelled":
        return {
            "step": "Kapalı",
            "title": "Talep iptal edildi",
            "hint": "Bu talep müşteri tarafından kapatıldı.",
            "next_action": "Gerekirse yeni bir talep oluşturun.",
            "tone": "muted",
        }

    return flow


def get_service_request_status_ui(service_request, appointment=None, *, calendar_enabled):
    if service_request.status == "cancelled":
        return {"label": "Müşteri İptal Etti", "css_status": "cancelled"}
    if calendar_enabled and service_request.status == "completed" and not (
        appointment and appointment.status == "completed"
    ):
        return {"label": "Müşteri İptal Etti", "css_status": "cancelled"}
    return {"label": service_request.get_status_display(), "css_status": service_request.status}


def build_provider_pending_offer_flow_state():
    return {
        "step": "Adım 1/4",
        "title": "Talep kararınız bekleniyor",
        "hint": "Bu talep size iletildi ve müşteri yanıtınızı bekliyor.",
        "next_action": "Talebi onaylayın veya reddedin.",
        "tone": "action",
    }


def build_provider_waiting_selection_flow_state():
    return {
        "step": "Adım 2/4",
        "title": "Müşteri seçimi bekleniyor",
        "hint": "Teklifiniz müşteriye ulaştı.",
        "next_action": "Müşteri karar vermezse teklifi geri çekebilirsiniz.",
        "tone": "waiting",
    }


def provider_can_release_request_match(service_request, appointment, *, calendar_enabled):
    if not calendar_enabled or service_request.status != "matched":
        return False
    if appointment is None:
        return True
    return appointment.status in {"rejected", "cancelled"}


def build_provider_thread_flow_state(appointment, *, calendar_enabled):
    if not calendar_enabled:
        return {
            "step": "Adım 3/3",
            "title": "Mesajlaşma aktif",
            "hint": "Müşteri ile detayları mesajlardan netleştirebilirsiniz.",
            "next_action": "İş bitince tamamlandı olarak işaretleyin.",
            "tone": "action",
        }

    if appointment is None:
        return {
            "step": "Adım 3/4",
            "title": "Randevu saati bekleniyor",
            "hint": "Müşteri henüz bir saat seçmedi.",
            "next_action": "Müşteri dönmezse eşleşmeyi sonlandırabilirsiniz.",
            "tone": "waiting",
        }

    appointment_status = appointment.status
    if appointment_status in {"rejected", "cancelled"}:
        return {
            "step": "Adım 3/4",
            "title": "Yeni randevu saati bekleniyor",
            "hint": "Mevcut randevu aktif değil.",
            "next_action": "Müşteri dönmezse eşleşmeyi sonlandırabilirsiniz.",
            "tone": "danger",
        }
    if appointment_status == "pending":
        return {
            "step": "Adım 4/4",
            "title": "Randevu onayınız bekleniyor",
            "hint": "Müşteri saat seçimini yaptı.",
            "next_action": "Bekleyen randevular bölümünden onaylayın veya reddedin.",
            "tone": "action",
        }
    if appointment_status in {"pending_customer", "confirmed"}:
        return {
            "step": "Adım 4/4",
            "title": "Randevu onaylandı",
            "hint": "Planlanan ziyaret saati netleşti.",
            "next_action": "İş bittiğinde tamamlandı olarak işaretleyin.",
            "tone": "success",
        }
    if appointment_status == "completed":
        return {
            "step": "Tamamlandı",
            "title": "Randevu tamamlandı",
            "hint": "Bu iş için randevu süreci kapandı.",
            "next_action": "Gerekirse mesajlar üzerinden son notları takip edin.",
            "tone": "muted",
        }
    return {
        "step": "Aktif",
        "title": "Mesajlaşma aktif",
        "hint": "Durumu mesajlardan takip edebilirsiniz.",
        "next_action": "Gerekirse müşteriye yazın.",
        "tone": "action",
    }


def build_provider_pending_appointment_flow_state():
    return {
        "step": "Adım 4/4",
        "title": "Randevu onayı bekleniyor",
        "hint": "Müşteri saati belirledi ve yanıtınızı bekliyor.",
        "next_action": "Randevuyu onaylayın veya reddedin.",
        "tone": "action",
    }


def score_accepted_offers(offers):
    if not offers:
        return []

    max_sequence = max((offer.sequence or 1) for offer in offers) or 1

    for offer in offers:
        rating_score = max(0.0, min(70.0, (float(offer.provider.rating) / 5.0) * 70.0))
        if max_sequence <= 1:
            speed_score = 30.0
        else:
            speed_score = max(
                0.0,
                min(30.0, ((max_sequence - (offer.sequence or 1)) / (max_sequence - 1)) * 30.0),
            )

        offer.rating_score = round(rating_score, 1)
        offer.speed_score = round(speed_score, 1)
        offer.comparison_score = round(offer.rating_score + offer.speed_score, 1)

    return sorted(
        offers,
        key=lambda offer: (
            -(offer.comparison_score),
            -float(offer.provider.rating),
            offer.sequence or 1,
        ),
    )
