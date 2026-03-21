import csv

from django.db.models import Count, Exists, OuterRef

from .. import core_views as core


ActivityLog = core.ActivityLog
Decimal = core.Decimal
ErrorLog = core.ErrorLog
InvalidOperation = core.InvalidOperation
Prefetch = core.Prefetch
Provider = core.Provider
ProviderPayment = core.ProviderPayment
Q = core.Q
SchedulerHeartbeat = core.SchedulerHeartbeat
ServiceAppointment = core.ServiceAppointment
ServiceRequest = core.ServiceRequest
ServiceType = core.ServiceType
datetime = core.datetime
messages = core.messages
timezone = core.timezone
timedelta = core.timedelta

ATTENTION_SELECTION_STALE_HOURS = 2
ATTENTION_MATCHED_STALE_HOURS = 2
ATTENTION_APPOINTMENT_STALE_MINUTES = 60


def _build_membership_queryset(filter_query):
    payment_prefetch = Prefetch(
        "membership_payments",
        queryset=(
            ProviderPayment.objects.select_related("received_by")
            .only(
                "id",
                "provider_id",
                "amount",
                "cash_received_at",
                "received_by_id",
                "received_by__username",
                "note",
            )
            .order_by("-cash_received_at", "-id")
        ),
    )
    service_type_prefetch = Prefetch(
        "service_types",
        queryset=ServiceType.objects.only("id", "name").order_by("name"),
    )
    membership_qs = (
        Provider.objects.select_related("user")
        .only(
            "id",
            "user_id",
            "user__username",
            "full_name",
            "city",
            "district",
            "phone",
            "is_verified",
            "membership_status",
            "membership_expires_at",
            "membership_note",
            "created_at",
        )
        .prefetch_related(service_type_prefetch, payment_prefetch)
    )
    if filter_query:
        membership_qs = membership_qs.filter(
            Q(full_name__icontains=filter_query)
            | Q(user__username__icontains=filter_query)
            | Q(phone__icontains=filter_query)
            | Q(city__icontains=filter_query)
            | Q(district__icontains=filter_query)
        )
    return membership_qs


def _decorate_membership_rows(rows, *, membership_now):
    fallback_sort_at = timezone.make_aware(datetime.max.replace(microsecond=0))
    for provider in rows:
        membership = core.build_provider_membership_context(provider, now=membership_now)
        provider.membership_state = membership["state"]
        provider.membership_state_label = core.get_provider_membership_state_label(membership["state"])
        provider.membership_remaining_label = core.build_provider_membership_remaining_label(
            provider,
            membership,
            now=membership_now,
        )
        provider.membership_ui = membership
        payments = list(provider.membership_payments.all())
        provider.latest_membership_payment = payments[0] if payments else None
        provider.membership_is_expiring_soon = False
        provider.membership_sort_rank = core.get_provider_membership_state_rank(membership["state"])
        provider.membership_sort_at = provider.membership_expires_at or membership.get("grace_until") or fallback_sort_at
        provider.membership_attention_deadline = None
        provider.membership_attention_label = ""
        provider.pending_wait_label = core.build_waiting_duration_label(provider.created_at, now=membership_now)
        provider.membership_filter_token = provider.user.username if provider.user_id and provider.user else provider.full_name
        service_names = [service.name for service in provider.service_types.all()]
        provider.service_type_summary = ", ".join(service_names[:2])
        if len(service_names) > 2:
            provider.service_type_summary = f"{provider.service_type_summary} +{len(service_names) - 2}"

        if provider.membership_expires_at and membership["state"] in {"active", "trial"}:
            remaining_seconds = (provider.membership_expires_at - membership_now).total_seconds()
            if 0 <= remaining_seconds <= 7 * 86400:
                provider.membership_is_expiring_soon = True
                provider.membership_attention_deadline = provider.membership_expires_at
                provider.membership_attention_label = "Esas bitiş"
        elif membership["state"] == "grace" and membership.get("grace_until"):
            remaining_seconds = (membership["grace_until"] - membership_now).total_seconds()
            if 0 <= remaining_seconds <= 7 * 86400:
                provider.membership_is_expiring_soon = True
                provider.membership_attention_deadline = membership["grace_until"]
                provider.membership_attention_label = "Ek süre biter"
    return fallback_sort_at


def _filter_membership_rows(rows, membership_filter_state):
    if membership_filter_state == "expiring_soon":
        return [provider for provider in rows if provider.membership_is_expiring_soon]
    if membership_filter_state == "pending_verification":
        return [provider for provider in rows if not provider.is_verified]
    if membership_filter_state != "all":
        return [provider for provider in rows if provider.membership_state == membership_filter_state]
    return list(rows)


def _approve_provider(provider, *, membership_note, now):
    if provider.is_verified:
        return False

    update_fields = ["is_verified", "verified_at"]
    provider.is_verified = True
    started_trial = False
    if provider.membership_expires_at is None:
        provider.membership_status = "trial"
        provider.membership_expires_at = now + timedelta(days=core.get_provider_membership_trial_days())
        update_fields.extend(["membership_status", "membership_expires_at"])
        started_trial = True
    if membership_note and provider.membership_note != membership_note:
        provider.membership_note = membership_note
        update_fields.append("membership_note")
    provider.save(update_fields=list(dict.fromkeys(update_fields)))
    return started_trial


def _build_readiness_items(*, scheduler_heartbeat, scheduler_healthy, scheduler_age_seconds, stale_after_seconds):
    settings = core.settings
    readiness_items = []
    redis_url = str(getattr(settings, "REDIS_URL", "") or "").strip()
    has_channels_redis = bool(getattr(settings, "HAS_CHANNELS_REDIS", False))
    realtime_enabled = bool(getattr(settings, "REALTIME_CHANNELS_ENABLED", False))
    request_lifecycle_enabled = bool(core.request_lifecycle_refresh_enabled())
    email_ready = bool(
        str(getattr(settings, "BREVO_API_KEY", "") or "").strip()
        or (
            str(getattr(settings, "EMAIL_HOST", "") or "").strip()
            and str(getattr(settings, "EMAIL_HOST_USER", "") or "").strip()
            and str(getattr(settings, "EMAIL_HOST_PASSWORD", "") or "").strip()
        )
    )
    mobile_push_enabled = bool(getattr(settings, "MOBILE_PUSH_ENABLED", True))
    mobile_push_ready = bool(
        str(getattr(settings, "FCM_PROJECT_ID", "") or "").strip()
        or str(getattr(settings, "FCM_SERVICE_ACCOUNT_FILE", "") or "").strip()
        or str(getattr(settings, "FCM_SERVICE_ACCOUNT_JSON", "") or "").strip()
    )

    if not scheduler_heartbeat:
        readiness_items.append(
            {
                "code": "scheduler_missing",
                "tone": "danger",
                "badge_label": "Kritik",
                "title": "Lifecycle worker heartbeat güncellenmiyor",
                "message": "Marketplace lifecycle workeri son durum kaydı bırakmıyor.",
                "action": "Scheduler görevini ve worker loglarını kontrol edin.",
            }
        )
    elif not scheduler_healthy:
        age_label = f"{scheduler_age_seconds} sn" if scheduler_age_seconds is not None else "bilinmiyor"
        readiness_items.append(
            {
                "code": "scheduler_stale",
                "tone": "danger",
                "badge_label": "Kritik",
                "title": "Lifecycle worker gecikmiş görünüyor",
                "message": f"Son heartbeat {age_label} önce alınmış. Limit {stale_after_seconds} sn.",
                "action": "Worker çalışmıyorsa yeniden başlatın; hata varsa logu inceleyin.",
            }
        )

    if realtime_enabled and (not redis_url or not has_channels_redis):
        readiness_items.append(
            {
                "code": "realtime_inmemory",
                "tone": "danger",
                "badge_label": "Kritik",
                "title": "Gerçek zamanlı kanallar Redis olmadan açık",
                "message": "WebSocket ve canlı güncellemeler workerlar arası güvenilir çalışmayabilir.",
                "action": "REDIS_URL ve channels_redis kurulumu tamamlanmalı.",
            }
        )
    elif not realtime_enabled:
        readiness_items.append(
            {
                "code": "realtime_disabled",
                "tone": "warning",
                "badge_label": "Dikkat",
                "title": "Gerçek zamanlı kanallar kapalı",
                "message": "Mesaj ve badge güncellemeleri polling ile çalışacak; canlılık hissi düşebilir.",
                "action": "Redis bağlantısı hazırsa REALTIME_CHANNELS_ENABLED=1 yapın.",
            }
        )

    if not email_ready:
        readiness_items.append(
            {
                "code": "email_not_configured",
                "tone": "danger",
                "badge_label": "Kritik",
                "title": "E-posta gönderimi hazır değil",
                "message": "Kayıt doğrulama ve şifre sıfırlama e-postaları kullanıcıya ulaşmayacak.",
                "action": "BREVO_API_KEY ya da SMTP ayarlarını tamamlayın.",
            }
        )

    if mobile_push_enabled and not mobile_push_ready:
        readiness_items.append(
            {
                "code": "mobile_push_incomplete",
                "tone": "warning",
                "badge_label": "Dikkat",
                "title": "Mobil push ayarları eksik",
                "message": "Cihaz bildirimi açık görünüyor ama FCM projesi veya servis hesabı eksik.",
                "action": "FCM_PROJECT_ID ve servis hesabı ayarlarını tamamlayın.",
            }
        )

    if request_lifecycle_enabled and not getattr(settings, "DEBUG", False):
        readiness_items.append(
            {
                "code": "request_lifecycle_on_web",
                "tone": "warning",
                "badge_label": "Dikkat",
                "title": "Lifecycle yenilemesi web isteklerinde açık",
                "message": "Kullanıcı istekleri arka plan lifecycle yükünü de taşır. Yoğunlukta sayfa cevapları dalgalanabilir.",
                "action": "Prod ortamında REQUEST_LIFECYCLE_REFRESH_ENABLED=0 önerilir.",
            }
        )

    readiness_summary = {
        "critical_count": sum(1 for item in readiness_items if item["tone"] == "danger"),
        "warning_count": sum(1 for item in readiness_items if item["tone"] == "warning"),
        "info_count": sum(1 for item in readiness_items if item["tone"] == "info"),
    }
    return readiness_items, readiness_summary


def _build_membership_csv_response(rows):
    response = core.HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="usta-uyelikleri.csv"'
    response.write("\ufeff")
    writer = csv.writer(response)
    writer.writerow(
        [
            "Ad Soyad",
            "Kullanıcı",
            "Telefon",
            "Şehir",
            "İlçe",
            "Admin Onayı",
            "Durum",
            "Kalan Süre",
            "Esas Bitiş",
            "Ek Süre Biter",
            "Son Tahsilat",
            "Tahsil Eden",
            "Not",
        ]
    )
    for provider in rows:
        latest_payment = getattr(provider, "latest_membership_payment", None)
        writer.writerow(
            [
                provider.full_name,
                provider.user.username if provider.user_id and provider.user else "",
                provider.phone,
                provider.city,
                provider.district,
                "Onaylı" if provider.is_verified else "Bekliyor",
                provider.membership_state_label,
                provider.membership_remaining_label,
                timezone.localtime(provider.membership_expires_at).strftime("%d.%m.%Y %H:%M")
                if provider.membership_expires_at
                else "",
                timezone.localtime(provider.membership_ui["grace_until"]).strftime("%d.%m.%Y %H:%M")
                if provider.membership_ui.get("grace_until")
                else "",
                timezone.localtime(latest_payment.cash_received_at).strftime("%d.%m.%Y %H:%M")
                if latest_payment and latest_payment.cash_received_at
                else "",
                latest_payment.received_by.username if latest_payment and latest_payment.received_by_id else "",
                provider.membership_ui.get("note") or "",
            ]
        )
    return response


def operations_dashboard(request):
    if not request.user.is_staff:
        messages.error(request, "Bu alan sadece yönetim kullanıcıları içindir.")
        return core.redirect("index")

    today = timezone.localdate()
    selected_day = today
    selected_day_raw = (request.POST.get("day") or request.GET.get("day") or "").strip()
    if selected_day_raw:
        try:
            selected_day = datetime.strptime(selected_day_raw, "%Y-%m-%d").date()
        except ValueError:
            messages.warning(request, "Geçersiz tarih nedeniyle bugünün verileri gösterildi.")
            selected_day = today
    membership_filter_query = str(request.POST.get("membership_q") or request.GET.get("membership_q") or "").strip()
    membership_filter_state = str(request.POST.get("membership_state") or request.GET.get("membership_state") or "all").strip()
    attention_view = str(request.POST.get("attention") or request.GET.get("attention") or "").strip()
    membership_filter_options = {
        "all": "Tümü",
        "active": "Aktif",
        "trial": "Deneme",
        "grace": "Ek sürede",
        "suspended": "Askıda",
        "expiring_soon": "7 gün içinde bitecek",
        "pending_verification": "Onay bekleyenler",
    }
    if membership_filter_state not in membership_filter_options:
        membership_filter_state = "all"
    if attention_view != "all":
        attention_view = "summary"
    membership_export = str(request.GET.get("membership_export") or "").strip().lower()

    prepared_membership_now = timezone.now()
    prepared_all_membership_rows = list(_build_membership_queryset(membership_filter_query))
    _decorate_membership_rows(prepared_all_membership_rows, membership_now=prepared_membership_now)
    prepared_filtered_membership_rows = _filter_membership_rows(prepared_all_membership_rows, membership_filter_state)
    prepared_filtered_membership_rows.sort(
        key=lambda item: (
            item.membership_sort_rank,
            item.membership_sort_at,
            not item.is_verified,
            item.full_name.lower(),
            item.id,
        )
    )
    bulk_pending_approval_rows = [provider for provider in prepared_filtered_membership_rows if not provider.is_verified]

    if request.method == "POST":
        provider_id_raw = str(request.POST.get("provider_id") or "").strip()
        provider_verification_action = str(request.POST.get("provider_verification_action") or "").strip()
        membership_action = str(request.POST.get("membership_action") or "").strip()
        redirect_url = core.build_operations_dashboard_redirect_url(request, selected_day)
        bulk_action = str(request.POST.get("bulk_action") or "").strip()
        membership_note = (request.POST.get("membership_note") or request.POST.get("operation_note") or "").strip()
        if len(membership_note) > 240:
            messages.warning(request, "Üyelik notu en fazla 240 karakter olabilir.")
            return core.redirect(redirect_url)
        if bulk_action == "approve_pending_filtered":
            if not bulk_pending_approval_rows:
                messages.warning(request, "Filtrede toplu onaylanacak bekleyen usta yok.")
                return core.redirect(redirect_url)
            now = timezone.now()
            started_trial_count = 0
            for pending_provider in bulk_pending_approval_rows:
                if _approve_provider(pending_provider, membership_note=membership_note, now=now):
                    started_trial_count += 1
            total_count = len(bulk_pending_approval_rows)
            messages.success(
                request,
                f"{total_count} usta toplu olarak onaylandı. {started_trial_count} hesapta deneme süresi başlatıldı.",
            )
            return core.redirect(redirect_url)
        if bulk_action:
            messages.warning(request, "Bilinmeyen toplu işlem.")
            return core.redirect(redirect_url)
        if not provider_id_raw.isdigit():
            messages.warning(request, "Üyelik işlemi için geçerli bir usta seçin.")
            return core.redirect(redirect_url)

        provider = core.get_object_or_404(Provider.objects.select_related("user"), id=int(provider_id_raw))
        membership_note = (request.POST.get("membership_note") or request.POST.get("operation_note") or "").strip()
        if len(membership_note) > 240:
            messages.warning(request, "Üyelik notu en fazla 240 karakter olabilir.")
            return core.redirect(redirect_url)

        now = timezone.now()
        if provider_verification_action == "approve":
            if provider.is_verified:
                messages.info(request, f"{provider.full_name} zaten onaylı.")
                return core.redirect(redirect_url)

            update_fields = ["is_verified", "verified_at"]
            provider.is_verified = True
            trial_days = core.get_provider_membership_trial_days()
            started_trial = False
            if provider.membership_expires_at is None:
                provider.membership_status = "trial"
                provider.membership_expires_at = now + timedelta(days=trial_days)
                update_fields.extend(["membership_status", "membership_expires_at"])
                started_trial = True
            if membership_note and provider.membership_note != membership_note:
                provider.membership_note = membership_note
                update_fields.append("membership_note")
            provider.save(update_fields=list(dict.fromkeys(update_fields)))
            if started_trial:
                messages.success(
                    request,
                    f"{provider.full_name} onaylandı. {trial_days} günlük deneme erişimi başlatıldı.",
                )
            else:
                messages.success(request, f"{provider.full_name} onaylandı.")
        elif membership_action == "renew":
            amount_raw = str(request.POST.get("amount") or "").strip().replace(",", ".")
            period_months_raw = str(request.POST.get("period_months") or "1").strip()
            try:
                amount = Decimal(amount_raw)
            except (InvalidOperation, ValueError):
                messages.warning(request, "Geçerli bir tahsilat tutarı girin.")
                return core.redirect(redirect_url)
            if amount <= 0:
                messages.warning(request, "Tahsilat tutarı sıfırdan büyük olmalıdır.")
                return core.redirect(redirect_url)
            if not period_months_raw.isdigit():
                messages.warning(request, "Geçerli bir üyelik süresi seçin.")
                return core.redirect(redirect_url)
            period_months = max(1, min(12, int(period_months_raw)))
            payment = ProviderPayment.objects.create(
                provider=provider,
                amount=amount,
                period_months=period_months,
                cash_received_at=now,
                received_by=request.user,
                note=membership_note,
            )
            if membership_note and provider.membership_note != membership_note:
                provider.membership_note = membership_note
                provider.save(update_fields=["membership_note"])
            messages.success(
                request,
                f"{provider.full_name} üyeliği {timezone.localtime(payment.membership_extended_until).strftime('%d.%m.%Y %H:%M')} tarihine kadar yenilendi.",
            )
        elif membership_action == "suspend":
            update_fields = []
            if provider.membership_status != "suspended":
                provider.membership_status = "suspended"
                update_fields.append("membership_status")
            if provider.membership_note != membership_note:
                provider.membership_note = membership_note
                update_fields.append("membership_note")
            if update_fields:
                provider.save(update_fields=update_fields)
            messages.success(request, f"{provider.full_name} askıya alındı.")
        elif membership_action == "trial":
            trial_days = core.get_provider_membership_trial_days()
            trial_start = provider.membership_expires_at if provider.membership_expires_at and provider.membership_expires_at > now else now
            provider.membership_status = "trial"
            provider.membership_expires_at = trial_start + timedelta(days=trial_days)
            provider.membership_note = membership_note
            provider.save(update_fields=["membership_status", "membership_expires_at", "membership_note"])
            messages.success(request, f"{provider.full_name} için {trial_days} günlük deneme süresi tanımlandı.")
        elif membership_action == "adjust_days":
            adjust_days_raw = str(request.POST.get("adjust_days") or "").strip()
            try:
                adjust_days = int(adjust_days_raw)
            except (TypeError, ValueError):
                messages.warning(request, "Düzeltme için geçerli bir gün değeri girin.")
                return core.redirect(redirect_url)
            if adjust_days == 0:
                messages.warning(request, "Düzeltme için sıfır dışında bir gün değeri girin.")
                return core.redirect(redirect_url)
            if not -365 <= adjust_days <= 365:
                messages.warning(request, "Gün düzeltme değeri -365 ile 365 arasında olmalıdır.")
                return core.redirect(redirect_url)
            base_expiry = provider.membership_expires_at or now
            provider.membership_expires_at = base_expiry + timedelta(days=adjust_days)
            update_fields = ["membership_expires_at"]
            if membership_note != provider.membership_note:
                provider.membership_note = membership_note
                update_fields.append("membership_note")
            provider.save(update_fields=update_fields)
            messages.success(request, f"{provider.full_name} için üyelik süresi {adjust_days:+} gün düzeltildi.")
        else:
            messages.warning(request, "Bilinmeyen üyelik işlemi.")
            return core.redirect(redirect_url)

        return core.redirect(redirect_url)

    if membership_export == "csv":
        return _build_membership_csv_response(prepared_filtered_membership_rows)

    core.maybe_refresh_marketplace_lifecycle_from_request()

    scheduler_heartbeat = SchedulerHeartbeat.objects.filter(worker_name="marketplace_lifecycle").first()
    scheduler_reference_at = None
    scheduler_age_seconds = None
    scheduler_healthy = False
    stale_after_seconds = core.get_lifecycle_heartbeat_stale_seconds()
    if scheduler_heartbeat:
        scheduler_reference_at = (
            scheduler_heartbeat.last_success_at
            or scheduler_heartbeat.last_started_at
            or scheduler_heartbeat.updated_at
        )
    if scheduler_reference_at:
        scheduler_age_seconds = max(0, int((timezone.now() - scheduler_reference_at).total_seconds()))
        scheduler_healthy = scheduler_age_seconds <= stale_after_seconds
    readiness_items, readiness_summary = _build_readiness_items(
        scheduler_heartbeat=scheduler_heartbeat,
        scheduler_healthy=scheduler_healthy,
        scheduler_age_seconds=scheduler_age_seconds,
        stale_after_seconds=stale_after_seconds,
    )

    selected_day_error_count = ErrorLog.objects.filter(created_at__date=selected_day).count()

    activity_qs = (
        ActivityLog.objects.select_related("actor_user", "service_request", "appointment", "message")
        .filter(created_at__date=selected_day)
        .order_by("-created_at", "-id")
    )
    activity_summary = activity_qs.aggregate(
        total_count=Count("id"),
        request_status_count=Count("id", filter=Q(action_type="request_status")),
        appointment_status_count=Count("id", filter=Q(action_type="appointment_status")),
        message_count=Count("id", filter=Q(action_type="message_sent")),
        request_touch_count=Count("service_request_id", filter=Q(service_request_id__isnull=False), distinct=True),
    )
    activity_page_obj = core.paginate_items(request, activity_qs, per_page=20, page_param="activity_page")
    activity_page_query = core.build_page_query_suffix(request, "activity_page")

    membership_qs = Provider.objects.select_related("user").prefetch_related(
        "service_types",
        Prefetch(
            "membership_payments",
            queryset=ProviderPayment.objects.select_related("received_by").order_by("-cash_received_at", "-id"),
        ),
    )
    if membership_filter_query:
        membership_qs = membership_qs.filter(
            Q(full_name__icontains=membership_filter_query)
            | Q(user__username__icontains=membership_filter_query)
            | Q(phone__icontains=membership_filter_query)
            | Q(city__icontains=membership_filter_query)
            | Q(district__icontains=membership_filter_query)
        )
    all_membership_rows = list(membership_qs)
    membership_now = timezone.now()
    fallback_sort_at = timezone.make_aware(datetime.max.replace(microsecond=0))
    for provider in all_membership_rows:
        membership = core.build_provider_membership_context(provider, now=membership_now)
        provider.membership_state = membership["state"]
        provider.membership_state_label = core.get_provider_membership_state_label(membership["state"])
        provider.membership_remaining_label = core.build_provider_membership_remaining_label(
            provider,
            membership,
            now=membership_now,
        )
        provider.membership_ui = membership
        payments = list(provider.membership_payments.all())
        provider.latest_membership_payment = payments[0] if payments else None
        provider.membership_is_expiring_soon = False
        provider.membership_sort_rank = core.get_provider_membership_state_rank(membership["state"])
        provider.membership_sort_at = provider.membership_expires_at or membership.get("grace_until") or fallback_sort_at
        provider.membership_attention_deadline = None
        provider.membership_attention_label = ""
        provider.pending_wait_label = core.build_waiting_duration_label(provider.created_at, now=membership_now)
        provider.membership_filter_token = provider.user.username if provider.user_id and provider.user else provider.full_name
        service_names = [service.name for service in provider.service_types.all()]
        provider.service_type_summary = ", ".join(service_names[:2])
        if len(service_names) > 2:
            provider.service_type_summary = f"{provider.service_type_summary} +{len(service_names) - 2}"

        if provider.membership_expires_at and membership["state"] in {"active", "trial"}:
            remaining_seconds = (provider.membership_expires_at - membership_now).total_seconds()
            if 0 <= remaining_seconds <= 7 * 86400:
                provider.membership_is_expiring_soon = True
                provider.membership_attention_deadline = provider.membership_expires_at
                provider.membership_attention_label = "Esas bitiş"
        elif membership["state"] == "grace" and membership.get("grace_until"):
            remaining_seconds = (membership["grace_until"] - membership_now).total_seconds()
            if 0 <= remaining_seconds <= 7 * 86400:
                provider.membership_is_expiring_soon = True
                provider.membership_attention_deadline = membership["grace_until"]
                provider.membership_attention_label = "Ek süre biter"

    membership_summary = {
        "active_count": sum(1 for provider in all_membership_rows if provider.membership_state == "active"),
        "trial_count": sum(1 for provider in all_membership_rows if provider.membership_state == "trial"),
        "grace_count": sum(1 for provider in all_membership_rows if provider.membership_state == "grace"),
        "suspended_count": sum(1 for provider in all_membership_rows if provider.membership_state == "suspended"),
        "expiring_soon_count": sum(1 for provider in all_membership_rows if provider.membership_is_expiring_soon),
        "pending_verification_count": sum(1 for provider in all_membership_rows if not provider.is_verified),
    }

    pending_provider_rows = sorted(
        [provider for provider in all_membership_rows if not provider.is_verified],
        key=lambda item: (item.created_at, item.id),
    )[:5]
    expiring_membership_rows = sorted(
        [provider for provider in all_membership_rows if provider.membership_is_expiring_soon],
        key=lambda item: (item.membership_attention_deadline or fallback_sort_at, item.full_name.lower(), item.id),
    )[:6]

    attention_items = []
    pending_selection_cutoff = membership_now - timedelta(hours=ATTENTION_SELECTION_STALE_HOURS)
    matched_without_appointment_cutoff = membership_now - timedelta(hours=ATTENTION_MATCHED_STALE_HOURS)
    attention_detail_open = attention_view == "all"
    pending_selection_qs = (
        ServiceRequest.objects.filter(status="pending_customer", created_at__lte=pending_selection_cutoff)
        .select_related("service_type")
        .order_by("created_at", "id")
    )
    if not attention_detail_open:
        pending_selection_qs = pending_selection_qs[:4]
    pending_selection_rows = list(pending_selection_qs)
    for service_request in pending_selection_rows:
        attention_items.append(
            {
                "tone": "warning",
                "badge_label": "Müşteri Kararı",
                "request_code": core.get_request_display_code(service_request),
                "title": "Müşteri seçimi uzun süredir bekliyor",
                "reason": "Kabul verilen teklifler arasından henüz bir usta seçilmedi.",
                "next_step": "Müşteriye ulaşılıp seçim yapması hatırlatılmalı.",
                "waited_label": core.build_waiting_duration_label(service_request.created_at, now=membership_now),
                "service_name": service_request.service_type.name,
                "customer_name": service_request.customer_name,
                "customer_phone": service_request.customer_phone,
                "provider_name": "",
                "provider_phone": "",
                "sort_at": service_request.created_at,
            }
        )

    matched_attention_closed_appointments = ServiceAppointment.objects.filter(
        service_request_id=OuterRef("pk"),
        status__in=["rejected", "cancelled"],
    )
    matched_attention_qs = (
        ServiceRequest.objects.filter(status="matched")
        .filter(
            Q(matched_at__lte=matched_without_appointment_cutoff)
            | Q(matched_at__isnull=True, created_at__lte=matched_without_appointment_cutoff),
            Q(appointment__isnull=True) | Q(appointment__status__in=["rejected", "cancelled"]),
        )
        .annotate(has_closed_appointment=Exists(matched_attention_closed_appointments))
        .select_related("service_type", "matched_provider")
        .order_by("matched_at", "created_at", "id")
    )
    if not attention_detail_open:
        matched_attention_qs = matched_attention_qs[:4]
    matched_attention_rows = list(matched_attention_qs)
    for service_request in matched_attention_rows:
        reference_at = service_request.matched_at or service_request.created_at
        attention_items.append(
            {
                "tone": "warning",
                "badge_label": "Randevu Yok",
                "request_code": core.get_request_display_code(service_request),
                "title": "Eşleşme var ama yeni randevu yok",
                "reason": (
                    "Önceki randevu kapandı, yeni saat seçilmedi."
                    if service_request.has_closed_appointment
                    else "Eşleşme tamamlandı ama henüz randevu oluşturulmadı."
                ),
                "next_step": "Taraflardan biri yeni randevu saati belirlemeli.",
                "waited_label": core.build_waiting_duration_label(reference_at, now=membership_now),
                "service_name": service_request.service_type.name,
                "customer_name": service_request.customer_name,
                "customer_phone": service_request.customer_phone,
                "provider_name": service_request.matched_provider.full_name if service_request.matched_provider_id else "",
                "provider_phone": service_request.matched_provider.phone if service_request.matched_provider_id else "",
                "sort_at": reference_at,
            }
        )

    provider_warning_cutoff = membership_now - timedelta(
        minutes=max(ATTENTION_APPOINTMENT_STALE_MINUTES, core.get_appointment_provider_confirm_minutes() // 2)
    )
    provider_danger_cutoff = membership_now - timedelta(
        minutes=max(ATTENTION_APPOINTMENT_STALE_MINUTES, core.get_appointment_provider_confirm_minutes())
    )
    provider_appointment_cutoff = provider_warning_cutoff
    pending_provider_appointments_qs = (
        ServiceAppointment.objects.filter(status="pending", created_at__lte=provider_appointment_cutoff)
        .select_related("service_request", "service_request__service_type", "provider")
        .order_by("created_at", "id")
    )
    if not attention_detail_open:
        pending_provider_appointments_qs = pending_provider_appointments_qs[:3]
    pending_provider_appointments = list(pending_provider_appointments_qs)
    for appointment in pending_provider_appointments:
        attention_items.append(
            {
                "tone": "danger" if appointment.created_at <= provider_danger_cutoff else "warning",
                "badge_label": "Usta Onayı",
                "request_code": core.get_request_display_code(appointment.service_request),
                "title": "Randevu uzun süredir usta onayında",
                "reason": "Usta, seçilen randevu saatine henüz dönüş yapmadı.",
                "next_step": "Bugün dönüş alınmazsa randevu otomatik kapanacak.",
                "waited_label": core.build_waiting_duration_label(appointment.created_at, now=membership_now),
                "service_name": appointment.service_request.service_type.name,
                "customer_name": appointment.service_request.customer_name,
                "customer_phone": appointment.service_request.customer_phone,
                "provider_name": appointment.provider.full_name,
                "provider_phone": appointment.provider.phone,
                "sort_at": appointment.created_at,
            }
        )

    customer_warning_cutoff = membership_now - timedelta(
        minutes=max(ATTENTION_APPOINTMENT_STALE_MINUTES, core.get_appointment_customer_confirm_minutes() // 2)
    )
    customer_danger_cutoff = membership_now - timedelta(
        minutes=max(ATTENTION_APPOINTMENT_STALE_MINUTES, core.get_appointment_customer_confirm_minutes())
    )
    customer_appointment_cutoff = customer_warning_cutoff
    pending_customer_appointments_qs = (
        ServiceAppointment.objects.filter(status="pending_customer", updated_at__lte=customer_appointment_cutoff)
        .select_related("service_request", "service_request__service_type", "provider")
        .order_by("updated_at", "id")
    )
    if not attention_detail_open:
        pending_customer_appointments_qs = pending_customer_appointments_qs[:3]
    pending_customer_appointments = list(pending_customer_appointments_qs)
    for appointment in pending_customer_appointments:
        attention_items.append(
            {
                "tone": "danger" if appointment.updated_at <= customer_danger_cutoff else "warning",
                "badge_label": "Müşteri Onayı",
                "request_code": core.get_request_display_code(appointment.service_request),
                "title": "Randevu uzun süredir müşteri onayında",
                "reason": "Müşteri, önerilen randevu saatini henüz onaylamadı.",
                "next_step": "Müşteriye ulaşılıp randevu saatini netleştirmek gerekiyor.",
                "waited_label": core.build_waiting_duration_label(appointment.updated_at, now=membership_now),
                "service_name": appointment.service_request.service_type.name,
                "customer_name": appointment.service_request.customer_name,
                "customer_phone": appointment.service_request.customer_phone,
                "provider_name": appointment.provider.full_name,
                "provider_phone": appointment.provider.phone,
                "sort_at": appointment.updated_at,
            }
        )

    attention_items.sort(key=lambda item: (item["sort_at"], item["request_code"]))
    full_attention_items = attention_items
    attention_total_count = len(full_attention_items)
    attention_preview_items = full_attention_items[:8]
    attention_page_obj = core.paginate_items(request, full_attention_items, per_page=12, page_param="attention_page")
    attention_page_query = core.build_page_query_suffix(request, "attention_page")
    attention_open_url = f"{core.build_query_url(request, updates={'day': selected_day.isoformat(), 'attention': 'all'}, remove=['attention_page'])}#attention-management"
    attention_close_url = f"{core.build_query_url(request, updates={'day': selected_day.isoformat()}, remove=['attention', 'attention_page'])}#attention-management"

    membership_rows = list(prepared_filtered_membership_rows)
    membership_page_obj = core.paginate_items(request, membership_rows, per_page=12, page_param="membership_page")
    membership_page_query = core.build_page_query_suffix(request, "membership_page")
    membership_export_url = core.build_query_url(
        request,
        updates={"day": selected_day.isoformat(), "membership_export": "csv"},
        remove=["membership_page"],
    )

    return core.render(
        request,
        "Myapp/operations_dashboard.html",
        {
            "today_date": today,
            "selected_date": selected_day,
            "selected_date_input": selected_day.isoformat(),
            "is_today_selected": selected_day == today,
            "previous_date_input": (selected_day - timedelta(days=1)).isoformat(),
            "next_date_input": (selected_day + timedelta(days=1)).isoformat(),
            "can_go_next_date": selected_day < today,
            "readiness_items": readiness_items,
            "readiness_summary": readiness_summary,
            "unresolved_error_count": ErrorLog.objects.filter(resolved_at__isnull=True).count(),
            "selected_day_error_count": selected_day_error_count,
            "recent_errors": ErrorLog.objects.select_related("user")
            .filter(created_at__date=selected_day)
            .order_by("-created_at", "-id")[:8],
            "activity_page_obj": activity_page_obj,
            "activity_rows": list(activity_page_obj.object_list),
            "activity_page_query": activity_page_query,
            "activity_summary": activity_summary,
            "membership_summary": membership_summary,
            "membership_page_obj": membership_page_obj,
            "membership_rows": list(membership_page_obj.object_list),
            "membership_page_query": membership_page_query,
            "membership_filter_query": membership_filter_query,
            "membership_filter_state": membership_filter_state,
            "membership_filter_options": membership_filter_options,
            "membership_filtered_count": len(membership_rows),
            "membership_period_options": [1, 3, 6, 12],
            "membership_export_url": membership_export_url,
            "bulk_pending_approval_count": len(bulk_pending_approval_rows),
            "provider_membership_trial_days": core.get_provider_membership_trial_days(),
            "pending_provider_rows": pending_provider_rows,
            "attention_items": attention_preview_items,
            "attention_total_count": attention_total_count,
            "attention_detail_open": attention_detail_open,
            "attention_page_obj": attention_page_obj,
            "attention_page_rows": list(attention_page_obj.object_list),
            "attention_page_query": attention_page_query,
            "attention_open_url": attention_open_url,
            "attention_close_url": attention_close_url,
            "attention_selection_stale_hours": ATTENTION_SELECTION_STALE_HOURS,
            "attention_matched_stale_hours": ATTENTION_MATCHED_STALE_HOURS,
            "attention_appointment_stale_minutes": ATTENTION_APPOINTMENT_STALE_MINUTES,
            "expiring_membership_rows": expiring_membership_rows,
            "scheduler_heartbeat": scheduler_heartbeat,
            "scheduler_healthy": scheduler_healthy,
            "scheduler_age_seconds": scheduler_age_seconds,
            "scheduler_stale_after_seconds": stale_after_seconds,
        },
    )
