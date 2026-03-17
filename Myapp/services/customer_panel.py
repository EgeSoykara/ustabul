from .. import core_views as core


ProviderRating = core.ProviderRating
ServiceAppointment = core.ServiceAppointment
WorkflowEvent = core.WorkflowEvent
timezone = core.timezone


def build_customer_panel_context(request):
    calendar_enabled = core.is_calendar_enabled()
    highlight_request_raw = str(request.GET.get("highlight_request") or "").strip()
    highlight_request_id = int(highlight_request_raw) if highlight_request_raw.isdigit() else None
    customer_filter_query = str(request.GET.get("request_q") or "").strip()
    customer_filter_state = str(request.GET.get("request_state") or "all").strip()
    customer_filter_options = {
        "all": "Tümü",
        "waiting_provider": "Yanıt bekliyor",
        "pending_customer": "Seçmen gereken",
        "matched": "Devam eden",
        "cancelled": "İptal edilen",
    }
    if customer_filter_state not in customer_filter_options:
        customer_filter_state = "all"

    all_requests_qs = request.user.service_requests.select_related(
        "service_type",
        "matched_provider",
        "matched_offer",
        "matched_offer__provider",
    ).prefetch_related(
        "provider_offers",
        "provider_offers__provider",
        "matched_provider__availability_slots",
    )
    completed_history_count = all_requests_qs.filter(status="completed").count()
    requests_qs = all_requests_qs.exclude(status="completed")

    if customer_filter_query:
        requests_qs = requests_qs.filter(
            core.build_request_search_query(
                customer_filter_query,
                include_matched_provider=True,
            )
        )
    if customer_filter_state == "waiting_provider":
        requests_qs = requests_qs.filter(status__in=["new", "pending_provider"])
    elif customer_filter_state != "all":
        requests_qs = requests_qs.filter(status=customer_filter_state)

    pending_selection_qs = requests_qs.filter(status="pending_customer").order_by("-created_at")
    pending_selection_page_obj = core.paginate_items(
        request,
        pending_selection_qs,
        per_page=5,
        page_param="pending_selection_page",
    )
    pending_selection_items = list(pending_selection_page_obj.object_list)
    main_requests_qs = requests_qs.exclude(status="pending_customer")
    requests_page_obj = core.paginate_items(request, main_requests_qs, per_page=10, page_param="page")
    requests = list(requests_page_obj.object_list)
    requests_page_query = core.build_page_query_suffix(request, "page")
    pending_selection_page_query = core.build_page_query_suffix(request, "pending_selection_page")
    request_ids = [item.id for item in requests + pending_selection_items]
    rating_map = {
        rating.service_request_id: rating
        for rating in ProviderRating.objects.filter(service_request_id__in=request_ids)
    }
    appointment_map = {}
    confirmed_appointment_request_ids = set()
    if calendar_enabled:
        appointment_map = {
            appointment.service_request_id: appointment
            for appointment in ServiceAppointment.objects.filter(service_request_id__in=request_ids)
        }
        confirmed_appointment_request_ids = set(
            WorkflowEvent.objects.filter(
                target_type="appointment",
                service_request_id__in=request_ids,
                to_status="confirmed",
            ).values_list("service_request_id", flat=True)
        )
    unread_message_map = core.build_unread_message_map(request_ids, "customer")
    latest_message_map = core.build_latest_incoming_message_map(request_ids, "customer")
    latest_workflow_event_map = core.build_latest_workflow_event_map(request_ids, request.user)
    now = timezone.now()
    for item in requests + pending_selection_items:
        item.rating_entry = rating_map.get(item.id)
        item.appointment_entry = appointment_map.get(item.id)
        status_ui = core.get_service_request_status_ui(
            item,
            item.appointment_entry,
            calendar_enabled=calendar_enabled,
        )
        item.status_ui_label = status_ui["label"]
        item.status_ui_class = status_ui["css_status"]
        item.is_highlighted = highlight_request_id == item.id
        item.cancel_policy_note = ""
        item.cancel_policy_tone = "muted"
        if calendar_enabled and item.appointment_entry and item.appointment_entry.status in {"pending_customer", "confirmed"}:
            cancel_policy = core.evaluate_appointment_cancel_policy(item.appointment_entry, now=now)
            if cancel_policy["category"] in {"last_minute", "no_show"}:
                item.cancel_policy_note = cancel_policy["ui_note"]
                item.cancel_policy_tone = "danger" if cancel_policy["category"] == "no_show" else "warning"
        if calendar_enabled:
            item.can_rate = (
                item.status == "completed"
                and bool(item.matched_provider_id)
                and bool(item.appointment_entry)
                and item.appointment_entry.status == "completed"
                and item.id in confirmed_appointment_request_ids
            )
        else:
            item.can_rate = item.status == "completed" and bool(item.matched_provider_id)
        item.rate_block_reason = ""
        if calendar_enabled and item.status == "completed" and item.matched_provider_id and not item.can_rate:
            if item.appointment_entry is None:
                item.rate_block_reason = "Randevu oluşturulmadan kapanan işlerde puanlama kapalıdır."
            elif item.id not in confirmed_appointment_request_ids:
                item.rate_block_reason = "Randevu müşteri onayı olmadan kapatıldığı için puanlama kapalıdır."
            elif item.appointment_entry.status != "completed":
                item.rate_block_reason = "Puanlama için randevunun tamamlanması gerekir."
        verified_offers = [
            offer for offer in item.provider_offers.all() if offer.provider_id and getattr(offer.provider, "is_verified", False)
        ]
        item.pending_offer = next((offer for offer in verified_offers if offer.status == "pending"), None)
        accepted_offers = [offer for offer in verified_offers if offer.status == "accepted"]
        item.accepted_offers = core.score_accepted_offers(accepted_offers)
        item.recommended_offer_id = item.accepted_offers[0].id if item.accepted_offers else None
        item.unread_messages = unread_message_map.get(item.id, 0)
        item.can_complete_now = False
        item.can_cancel_now = False
        item.complete_block_reason = ""

        if item.status == "matched" and calendar_enabled:
            appointment = item.appointment_entry
            if appointment is None or appointment.status in {"rejected", "cancelled"}:
                item.can_cancel_now = True
            elif appointment.status == "pending":
                item.complete_block_reason = "Bekleyen randevu talebi varken tamamlanamaz."
            elif (
                appointment.status in {"confirmed", "pending_customer"}
                and appointment.scheduled_for
                and appointment.scheduled_for > now
            ):
                item.complete_block_reason = "Onaylı randevu zamanı gelmeden tamamlanamaz."
            else:
                item.can_complete_now = True
        elif item.status == "matched":
            item.can_complete_now = True
        item.provider_availability_slots = []
        if calendar_enabled and item.matched_provider:
            item.provider_availability_slots = list(
                item.matched_provider.availability_slots.filter(is_active=True).order_by("weekday", "start_time")
            )
        flow_state = core.build_customer_flow_state(
            item,
            item.appointment_entry,
            has_accepted_offers=bool(item.accepted_offers),
            now=now,
            calendar_enabled=calendar_enabled,
            last_minute_cancel_hours=core.get_last_minute_cancel_hours(),
            no_show_grace_minutes=core.get_no_show_grace_minutes(),
        )
        if calendar_enabled and item.status == "completed" and not item.can_rate:
            flow_state["hint"] = "Bu iş kaydı randevu onayı tamamlanmadan kapatıldığı için puanlama kapalıdır."
            flow_state["next_action"] = "Gerekirse yeni bir talep oluşturabilirsiniz."
            flow_state["tone"] = "muted"
        item.flow_step = flow_state["step"]
        item.flow_title = flow_state["title"]
        item.flow_hint = flow_state["hint"]
        item.flow_next_action = flow_state["next_action"]
        item.flow_tone = flow_state["tone"]
        core.assign_recent_change_state(
            item,
            latest_message=latest_message_map.get(item.id),
            latest_event=latest_workflow_event_map.get(item.id),
        )
    cancelled_count = requests_qs.filter(status="cancelled").count()
    all_request_ids = list(requests_qs.values_list("id", flat=True))
    waiting_provider_appointment_count = 0
    if calendar_enabled and all_request_ids:
        waiting_provider_appointment_count = ServiceAppointment.objects.filter(
            service_request_id__in=all_request_ids,
            status="pending",
        ).count()
    customer_flow_summary = {
        "waiting_provider_count": requests_qs.filter(status__in=["new", "pending_provider"]).count(),
        "waiting_customer_selection_count": requests_qs.filter(status="pending_customer").count(),
        "active_matched_count": requests_qs.filter(status="matched").count(),
        "waiting_provider_appointment_count": waiting_provider_appointment_count,
    }
    customer_snapshot = core.build_customer_snapshot_payload(request.user)
    return {
        "requests": requests,
        "requests_page_obj": requests_page_obj,
        "cancelled_count": cancelled_count,
        "completed_history_count": completed_history_count,
        "customer_requests_signature": customer_snapshot["signature"],
        "customer_snapshot": customer_snapshot,
        "customer_flow_summary": customer_flow_summary,
        "customer_filter_query": customer_filter_query,
        "customer_filter_state": customer_filter_state,
        "customer_filter_options": customer_filter_options,
        "customer_filtered_count": requests_qs.count(),
        "pending_selection_items": pending_selection_items,
        "pending_selection_page_obj": pending_selection_page_obj,
        "pending_selection_page_query": pending_selection_page_query,
        "requests_page_query": requests_page_query,
        "appointment_min_lead_minutes": core.get_appointment_min_lead_minutes() if calendar_enabled else 0,
        "calendar_enabled": calendar_enabled,
        "customer_panel_partial_url": core.build_panel_partial_url(request),
    }
