from .. import core_views as core


Q = core.Q
ServiceAppointment = core.ServiceAppointment
ServiceMessage = core.ServiceMessage
timezone = core.timezone


def build_provider_panel_context(request, provider):
    calendar_enabled = core.is_calendar_enabled()
    provider_membership = core.build_provider_membership_context(provider)
    highlight_request_raw = str(request.GET.get("highlight_request") or "").strip()
    highlight_request_id = int(highlight_request_raw) if highlight_request_raw.isdigit() else None
    highlight_appointment_raw = str(request.GET.get("highlight_appointment") or "").strip()
    highlight_appointment_id = int(highlight_appointment_raw) if highlight_appointment_raw.isdigit() else None
    provider_filter_query = str(request.GET.get("provider_q") or "").strip()

    pending_offers_qs = (
        provider.offers.filter(status="pending")
        .select_related("service_request", "service_request__service_type")
        .order_by("-sent_at")
    )
    if provider_filter_query:
        pending_offers_qs = pending_offers_qs.filter(
            core.build_request_search_query(provider_filter_query, prefix="service_request__")
        )
    pending_offers_count = pending_offers_qs.count()
    latest_pending_offer_id = pending_offers_qs.values_list("id", flat=True).first() or 0
    pending_offers_page_obj = core.paginate_items(request, pending_offers_qs, per_page=10, page_param="pending_offer_page")
    pending_offers = list(pending_offers_page_obj.object_list)
    for offer in pending_offers:
        flow_state = core.build_provider_pending_offer_flow_state()
        offer.flow_step = flow_state["step"]
        offer.flow_title = flow_state["title"]
        offer.flow_hint = flow_state["hint"]
        offer.flow_next_action = flow_state["next_action"]
        offer.flow_tone = flow_state["tone"]

    waiting_customer_selection_qs = (
        provider.offers.filter(
            status="accepted",
            service_request__status="pending_customer",
            service_request__matched_provider__isnull=True,
        )
        .select_related("service_request", "service_request__service_type")
        .order_by("-responded_at", "-sent_at")
    )
    if provider_filter_query:
        waiting_customer_selection_qs = waiting_customer_selection_qs.filter(
            core.build_request_search_query(provider_filter_query, prefix="service_request__")
        )
    waiting_customer_selection_count = waiting_customer_selection_qs.count()
    waiting_customer_selection_page_obj = core.paginate_items(
        request,
        waiting_customer_selection_qs,
        per_page=10,
        page_param="waiting_selection_page",
    )
    waiting_customer_selection_offers = list(waiting_customer_selection_page_obj.object_list)
    for offer in waiting_customer_selection_offers:
        flow_state = core.build_provider_waiting_selection_flow_state()
        offer.flow_step = flow_state["step"]
        offer.flow_title = flow_state["title"]
        offer.flow_hint = flow_state["hint"]
        offer.flow_next_action = flow_state["next_action"]
        offer.flow_tone = flow_state["tone"]
        offer.can_withdraw_offer = True

    recent_offers_qs = (
        provider.offers.exclude(status="pending")
        .select_related("service_request", "service_request__service_type")
        .order_by("-responded_at", "-sent_at")
    )
    if provider_filter_query:
        recent_offers_qs = recent_offers_qs.filter(
            core.build_request_search_query(provider_filter_query, prefix="service_request__")
        )
    recent_offers_page_obj = core.paginate_items(request, recent_offers_qs, per_page=10, page_param="recent_offer_page")
    recent_offers = list(recent_offers_page_obj.object_list)
    if calendar_enabled:
        pending_appointments_qs = (
            provider.appointments.filter(status="pending")
            .select_related("service_request", "service_request__service_type")
            .order_by("scheduled_for")
        )
        if provider_filter_query:
            pending_appointments_qs = pending_appointments_qs.filter(
                core.build_request_search_query(provider_filter_query, prefix="service_request__")
            )
        pending_appointments_count = pending_appointments_qs.count()
        pending_appointments_page_obj = core.paginate_items(
            request,
            pending_appointments_qs,
            per_page=10,
            page_param="pending_appointment_page",
        )
        pending_appointments = list(pending_appointments_page_obj.object_list)
        for appointment in pending_appointments:
            flow_state = core.build_provider_pending_appointment_flow_state()
            appointment.flow_step = flow_state["step"]
            appointment.flow_title = flow_state["title"]
            appointment.flow_hint = flow_state["hint"]
            appointment.flow_next_action = flow_state["next_action"]
            appointment.flow_tone = flow_state["tone"]

        confirmed_appointments_qs = (
            provider.appointments.filter(status__in=["confirmed", "pending_customer"])
            .select_related("service_request", "service_request__service_type")
            .order_by("scheduled_for")
        )
        if provider_filter_query:
            confirmed_appointments_qs = confirmed_appointments_qs.filter(
                core.build_request_search_query(provider_filter_query, prefix="service_request__")
            )
        confirmed_appointments_page_obj = core.paginate_items(
            request,
            confirmed_appointments_qs,
            per_page=10,
            page_param="confirmed_appointment_page",
        )
        confirmed_appointments = list(confirmed_appointments_page_obj.object_list)
        recent_appointments_qs = (
            provider.appointments.exclude(status__in=["pending", "pending_customer", "confirmed"])
            .select_related("service_request", "service_request__service_type")
            .order_by("-updated_at")
        )
        if provider_filter_query:
            recent_appointments_qs = recent_appointments_qs.filter(
                core.build_request_search_query(provider_filter_query, prefix="service_request__")
            )
        recent_appointments_page_obj = core.paginate_items(
            request,
            recent_appointments_qs,
            per_page=10,
            page_param="recent_appointment_page",
        )
        recent_appointments = list(recent_appointments_page_obj.object_list)
    else:
        pending_appointments_count = 0
        pending_appointments_page_obj = core.paginate_items(request, [], per_page=10, page_param="pending_appointment_page")
        pending_appointments = []
        confirmed_appointments_page_obj = core.paginate_items(
            request,
            [],
            per_page=10,
            page_param="confirmed_appointment_page",
        )
        confirmed_appointments = []
        recent_appointments_page_obj = core.paginate_items(request, [], per_page=10, page_param="recent_appointment_page")
        recent_appointments = []
    active_threads_qs = (
        provider.service_requests.filter(
            status="matched",
            matched_offer__isnull=False,
            matched_offer__provider=provider,
        )
        .select_related("service_type", "customer")
        .order_by("-created_at")
    )
    if provider_filter_query:
        active_threads_qs = active_threads_qs.filter(
            core.build_request_search_query(provider_filter_query)
        )
    active_threads_page_obj = core.paginate_items(request, active_threads_qs, per_page=10, page_param="active_thread_page")
    active_threads = list(active_threads_page_obj.object_list)
    active_thread_ids = [item.id for item in active_threads]
    unread_map = core.build_unread_message_map(active_thread_ids, "provider")
    appointment_map = {}
    waiting_schedule_count = 0
    if calendar_enabled:
        appointment_map = {
            appointment.service_request_id: appointment
            for appointment in ServiceAppointment.objects.filter(service_request_id__in=active_thread_ids)
        }
        waiting_schedule_count = active_threads_qs.filter(
            Q(appointment__isnull=True) | Q(appointment__status__in=["rejected", "cancelled"])
        ).count()
    for thread in active_threads:
        thread.unread_messages = unread_map.get(thread.id, 0)
        thread.appointment_entry = appointment_map.get(thread.id)
        thread.appointment_feedback_tone = "info"
        thread.appointment_feedback_label = "Mesajlaşma aktif"
        thread.appointment_feedback_note = "Durumu mesajlardan takip edebilirsiniz."

        if calendar_enabled:
            appointment = thread.appointment_entry
            if appointment is None:
                thread.appointment_feedback_tone = "warning"
                thread.appointment_feedback_label = "Randevu saati bekleniyor"
                thread.appointment_feedback_note = "Müşterinin randevu saati seçmesi bekleniyor."
            else:
                appointment_status = appointment.status
                if appointment_status in {"rejected", "cancelled"}:
                    thread.appointment_feedback_tone = "warning"
                    thread.appointment_feedback_label = "Yeni randevu saati bekleniyor"
                    thread.appointment_feedback_note = "Müşterinin yeni bir randevu oluşturması gerekiyor."
                elif appointment_status == "pending":
                    thread.appointment_feedback_tone = "action"
                    thread.appointment_feedback_label = "Randevu onayınız bekleniyor"
                    thread.appointment_feedback_note = "Müşteri saat seçimini yaptı. Bekleyen Randevu Talepleri bölümünü kontrol edin."
                elif appointment_status in {"pending_customer", "confirmed"}:
                    thread.appointment_feedback_tone = "success"
                    thread.appointment_feedback_label = "Randevu onaylandı"
                    thread.appointment_feedback_note = "Planlanan saat: " + timezone.localtime(appointment.scheduled_for).strftime(
                        "%d.%m.%Y %H:%M"
                    )
                elif appointment_status == "completed":
                    thread.appointment_feedback_tone = "success"
                    thread.appointment_feedback_label = "Randevu tamamlandı"
                    thread.appointment_feedback_note = "Bu randevu kapatıldı."

        flow_state = core.build_provider_thread_flow_state(
            thread.appointment_entry,
            calendar_enabled=calendar_enabled,
        )
        thread.flow_step = flow_state["step"]
        thread.flow_title = flow_state["title"]
        thread.flow_hint = flow_state["hint"]
        thread.flow_next_action = flow_state["next_action"]
        thread.flow_tone = flow_state["tone"]
        thread.can_release_match = core.provider_can_release_request_match(
            thread,
            thread.appointment_entry,
            calendar_enabled=calendar_enabled,
        )
    total_unread_messages = ServiceMessage.objects.filter(
        service_request__matched_provider=provider,
        service_request__status="matched",
        service_request__matched_offer__isnull=False,
        service_request__matched_offer__provider=provider,
        read_at__isnull=True,
    ).exclude(sender_role="provider").count()
    waiting_selection_page_query = core.build_page_query_suffix(request, "waiting_selection_page")
    pending_offer_page_query = core.build_page_query_suffix(request, "pending_offer_page")
    active_thread_page_query = core.build_page_query_suffix(request, "active_thread_page")
    pending_appointment_page_query = ""
    confirmed_appointment_page_query = ""
    recent_offer_page_query = core.build_page_query_suffix(request, "recent_offer_page")
    recent_appointment_page_query = ""
    if calendar_enabled:
        pending_appointment_page_query = core.build_page_query_suffix(request, "pending_appointment_page")
        confirmed_appointment_page_query = core.build_page_query_suffix(request, "confirmed_appointment_page")
        recent_appointment_page_query = core.build_page_query_suffix(request, "recent_appointment_page")

    recent_change_request_ids = set()
    recent_change_request_ids.update(offer.service_request_id for offer in pending_offers)
    recent_change_request_ids.update(offer.service_request_id for offer in waiting_customer_selection_offers)
    recent_change_request_ids.update(thread.id for thread in active_threads)
    recent_change_request_ids.update(appointment.service_request_id for appointment in pending_appointments)
    latest_message_map = core.build_latest_incoming_message_map(list(recent_change_request_ids), "provider")
    latest_workflow_event_map = core.build_latest_workflow_event_map(list(recent_change_request_ids), request.user)

    for offer in pending_offers:
        offer.is_highlighted = highlight_request_id == offer.service_request_id
        core.assign_recent_change_state(
            offer,
            latest_message=latest_message_map.get(offer.service_request_id),
            latest_event=latest_workflow_event_map.get(offer.service_request_id),
        )

    for offer in waiting_customer_selection_offers:
        offer.is_highlighted = highlight_request_id == offer.service_request_id
        core.assign_recent_change_state(
            offer,
            latest_message=latest_message_map.get(offer.service_request_id),
            latest_event=latest_workflow_event_map.get(offer.service_request_id),
        )

    for thread in active_threads:
        thread.is_highlighted = highlight_request_id == thread.id
        core.assign_recent_change_state(
            thread,
            latest_message=latest_message_map.get(thread.id),
            latest_event=latest_workflow_event_map.get(thread.id),
        )

    for appointment in pending_appointments:
        appointment.is_highlighted = (
            highlight_request_id == appointment.service_request_id
            or highlight_appointment_id == appointment.id
        )
        core.assign_recent_change_state(
            appointment,
            latest_message=latest_message_map.get(appointment.service_request_id),
            latest_event=latest_workflow_event_map.get(appointment.service_request_id),
        )

    provider_live_snapshot = {
        "signature": core.build_provider_panel_signature(provider),
        "pending_offers_count": pending_offers_count,
        "latest_pending_offer_id": latest_pending_offer_id,
        "waiting_customer_selection_count": waiting_customer_selection_count,
        "pending_appointments_count": pending_appointments_count,
        "unread_messages_count": total_unread_messages,
    }

    return {
        "provider": provider,
        "provider_membership": provider_membership,
        "provider_filter_query": provider_filter_query,
        "pending_offers": pending_offers,
        "pending_offers_count": pending_offers_count,
        "latest_pending_offer_id": latest_pending_offer_id,
        "pending_offers_page_obj": pending_offers_page_obj,
        "waiting_customer_selection_offers": waiting_customer_selection_offers,
        "waiting_customer_selection_page_obj": waiting_customer_selection_page_obj,
        "waiting_customer_selection_count": waiting_customer_selection_count,
        "recent_offers": recent_offers,
        "recent_offers_page_obj": recent_offers_page_obj,
        "pending_appointments": pending_appointments,
        "pending_appointments_count": pending_appointments_count,
        "pending_appointments_page_obj": pending_appointments_page_obj,
        "confirmed_appointments": confirmed_appointments,
        "confirmed_appointments_page_obj": confirmed_appointments_page_obj,
        "recent_appointments": recent_appointments,
        "recent_appointments_page_obj": recent_appointments_page_obj,
        "active_threads": active_threads,
        "active_threads_page_obj": active_threads_page_obj,
        "total_unread_messages": total_unread_messages,
        "waiting_schedule_count": waiting_schedule_count,
        "waiting_selection_page_query": waiting_selection_page_query,
        "pending_offer_page_query": pending_offer_page_query,
        "active_thread_page_query": active_thread_page_query,
        "pending_appointment_page_query": pending_appointment_page_query,
        "confirmed_appointment_page_query": confirmed_appointment_page_query,
        "recent_offer_page_query": recent_offer_page_query,
        "recent_appointment_page_query": recent_appointment_page_query,
        "provider_live_snapshot": provider_live_snapshot,
        "calendar_enabled": calendar_enabled,
        "provider_panel_partial_url": core.build_panel_partial_url(request),
    }
