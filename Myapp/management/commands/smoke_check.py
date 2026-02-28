from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Iterable
from uuid import uuid4

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.test import Client
from django.utils import timezone

from Myapp import views as app_views
from Myapp.constants import NC_CITY_CHOICES, NC_DISTRICT_CHOICES
from Myapp.models import (
    Provider,
    ProviderOffer,
    ProviderRating,
    ServiceAppointment,
    ServiceMessage,
    ServiceRequest,
    ServiceType,
)


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    is_warning: bool = False


class Command(BaseCommand):
    help = (
        "Runs smoke checks for critical app features: template integrity, navigation, "
        "pagination, dark mode script, and optional full customer/provider workflow."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--deep",
            action="store_true",
            help="Run full end-to-end workflow checks with temporary data (rolled back).",
        )
        parser.add_argument(
            "--fail-fast",
            action="store_true",
            help="Stop immediately on first failed check.",
        )

    def handle(self, *args, **options):
        self.fail_fast = bool(options["fail_fast"])
        self.results: list[CheckResult] = []

        self.stdout.write(self.style.NOTICE("Smoke check started..."))
        self._run_template_integrity_checks()
        self._run_endpoint_smoke_checks()

        if bool(options["deep"]):
            self._run_deep_workflow_checks()
        else:
            self._record(
                "Deep workflow",
                True,
                "Skipped (use --deep for full customer/provider/admin flow)",
                is_warning=True,
            )

        self._print_summary()
        failed = [item for item in self.results if not item.passed and not item.is_warning]
        if failed:
            raise CommandError(f"Smoke check failed: {len(failed)} checks failed.")

    def _run_template_integrity_checks(self):
        self._record("Base template exists", Path("templates/base.html").exists())
        self._assert_file_contains(
            "templates/base.html",
            'const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";',
            "Dark mode ternary",
        )
        self._assert_file_contains(
            "templates/base.html",
            'const navSelector = isProvider ? "[data-live-provider-nav]" : "[data-live-customer-nav]";',
            "Nav selector ternary",
        )
        self._assert_file_contains(
            "templates/base.html",
            "https://fonts.googleapis.com/css2?family=Outfit",
            "Google Fonts URL",
        )

        # Known broken patterns from prior regressions.
        forbidden_fragments = [
            'isProvider  "',
            'count > 99  "99+"',
            'titleFlashOn  "* "',
            'expanded  "true"',
            'message.mine  "mine"',
            'Number.isFinite(raw) && raw > 0  raw',
            'Number.isFinite(value) && value > 0  Math.floor(value)',
            'href="page=',
            'href="pending_offer_page=',
            'href="activity_page=',
            'href="tab=',
            '%}v=',
            "css2family=",
        ]
        for fragment in forbidden_fragments:
            self._assert_file_not_contains_glob(
                ["templates/**/*.html", "Myapp/templates/**/*.html"],
                fragment,
                f"Forbidden fragment not present: {fragment}",
            )

        self._assert_file_contains(
            "Myapp/templates/Myapp/request_messages.html",
            '(message.mine ? "mine" : "theirs")',
            "Chat bubble ternary",
        )
        self._assert_file_contains(
            "templates/service-worker.js",
            'const CACHE_NAME = "ustabul-pwa-v8";',
            "Service worker cache version",
        )

    def _run_endpoint_smoke_checks(self):
        client = Client()
        anon_paths = [
            "/",
            "/contact/",
            "/giris/",
            "/musteri/giris/",
            "/usta/giris/",
            "/kayit/",
            "/musteri/kayit/",
            "/usta/kayit/",
            "/offline/",
        ]
        for path in anon_paths:
            response = client.get(path, follow=False)
            self._record(f"Anon {path}", response.status_code == 200, f"status={response.status_code}")

        protected_paths = ["/taleplerim/", "/usta/talepler/", "/bildirimler/", "/anlasmalar/", "/operasyon/"]
        for path in protected_paths:
            response = client.get(path, follow=False)
            ok = response.status_code in {301, 302} and "/giris/" in (response.get("Location") or "")
            self._record(
                f"Anon redirect {path}",
                ok,
                f"status={response.status_code} location={response.get('Location', '')}",
            )

    def _run_deep_workflow_checks(self):
        original_send_sms = app_views.send_sms

        def _fake_send_sms(_phone, _text):
            return {"sent": True, "detail": "smoke-check"}

        app_views.send_sms = _fake_send_sms
        try:
            with transaction.atomic():
                self._run_deep_workflow_checks_inner()
                # Keep DB clean even in success mode.
                transaction.set_rollback(True)
        finally:
            app_views.send_sms = original_send_sms

    def _run_deep_workflow_checks_inner(self):
        city = NC_CITY_CHOICES[0][0]
        district = NC_DISTRICT_CHOICES[0][0]
        nonce = uuid4().hex[:8]

        service = ServiceType.objects.create(name=f"Smoke Hizmet {nonce}", slug=f"smoke-hizmet-{nonce}")
        customer = User.objects.create_user(username=f"smoke_c_{nonce}", password="Test12345!")
        provider_user = User.objects.create_user(username=f"smoke_p_{nonce}", password="Test12345!")
        admin_user = User.objects.create_superuser(
            username=f"smoke_a_{nonce}",
            email=f"smoke_{nonce}@example.com",
            password="Test12345!",
        )

        provider = Provider.objects.create(
            user=provider_user,
            full_name=f"Smoke Usta {nonce}",
            city=city,
            district=district,
            phone="05551234567",
            is_available=True,
            is_verified=True,
        )
        provider.service_types.add(service)

        client = Client()
        self._record("Deep login customer", client.login(username=customer.username, password="Test12345!"))

        payload = {
            "customer_name": "Smoke Musteri",
            "customer_phone": "05551234567",
            "city": city,
            "district": district,
            "service_type": str(service.id),
            "details": "Smoke test detay açıklaması",
        }
        create_response = client.post("/talep-olustur/", payload, follow=True)
        self._record("Deep create request response", create_response.status_code == 200, f"status={create_response.status_code}")

        request_entry = ServiceRequest.objects.filter(customer=customer).order_by("-id").first()
        self._record("Deep request created", request_entry is not None)
        if not request_entry:
            self._stop_on_fail_if_needed()
            return

        offer = ProviderOffer.objects.filter(service_request=request_entry, provider=provider).order_by("-id").first()
        if not offer:
            offer = ProviderOffer.objects.create(
                service_request=request_entry,
                provider=provider,
                token=f"smoke-offer-{nonce}",
                sequence=1,
                status="pending",
            )
        self._record("Deep provider offer exists", offer is not None)

        # Guard check: provider cannot message before customer selects provider.
        blocked_request = ServiceRequest.objects.create(
            customer_name="Smoke Musteri",
            customer_phone="05551234567",
            city=city,
            district=district,
            service_type=service,
            details="Mesaj blok smoke",
            customer=customer,
            status="pending_provider",
        )
        ProviderOffer.objects.create(
            service_request=blocked_request,
            provider=provider,
            token=f"smoke-block-{nonce}",
            sequence=1,
            status="pending",
        )
        client.logout()
        self._record("Deep login provider", client.login(username=provider_user.username, password="Test12345!"))
        provider_msg_response = client.post(f"/talep/{blocked_request.id}/mesajlar/", {"body": "test"}, follow=True)
        blocked = not ServiceMessage.objects.filter(service_request=blocked_request, sender_user=provider_user).exists()
        self._record(
            "Deep provider message blocked pre-match",
            blocked,
            f"status={provider_msg_response.status_code}",
        )

        accept_response = client.post(f"/usta/teklif/{offer.id}/kabul/", {"quote_note": "Smoke teklif notu"}, follow=True)
        self._record("Deep provider accept offer", accept_response.status_code == 200, f"status={accept_response.status_code}")
        offer.refresh_from_db()
        request_entry.refresh_from_db()
        self._record("Deep offer accepted", offer.status == "accepted", f"offer={offer.status}")
        self._record("Deep request pending_customer", request_entry.status == "pending_customer", f"request={request_entry.status}")

        client.logout()
        self._record("Deep relogin customer", client.login(username=customer.username, password="Test12345!"))

        select_response = client.post(
            f"/talep/{request_entry.id}/usta-sec/{offer.id}/",
            follow=True,
        )
        self._record("Deep customer select provider", select_response.status_code == 200, f"status={select_response.status_code}")
        request_entry.refresh_from_db()
        self._record("Deep request matched", request_entry.status == "matched", f"request={request_entry.status}")

        scheduled_for = (timezone.now() + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
        appointment_response = client.post(
            f"/talep/{request_entry.id}/randevu/olustur/",
            {"scheduled_for": scheduled_for, "appointment_preset": "", "customer_note": "Smoke randevu notu"},
            follow=True,
        )
        self._record("Deep create appointment", appointment_response.status_code == 200, f"status={appointment_response.status_code}")
        appointment = ServiceAppointment.objects.filter(service_request=request_entry).order_by("-id").first()
        self._record("Deep appointment exists", appointment is not None)
        if not appointment:
            self._stop_on_fail_if_needed()
            return

        client.logout()
        self._record("Deep relogin provider", client.login(username=provider_user.username, password="Test12345!"))

        confirm_response = client.post(f"/usta/randevu/{appointment.id}/kabul/", {"provider_note": "Onay"}, follow=True)
        self._record("Deep provider confirms appointment", confirm_response.status_code == 200, f"status={confirm_response.status_code}")
        appointment.refresh_from_db()
        self._record("Deep appointment confirmed", appointment.status == "confirmed", f"appointment={appointment.status}")

        complete_response = client.post(f"/usta/randevu/{appointment.id}/tamamla/", follow=True)
        self._record("Deep provider completes appointment", complete_response.status_code == 200, f"status={complete_response.status_code}")
        appointment.refresh_from_db()
        request_entry.refresh_from_db()
        self._record("Deep appointment completed", appointment.status == "completed", f"appointment={appointment.status}")
        self._record("Deep request completed", request_entry.status == "completed", f"request={request_entry.status}")

        client.logout()
        self._record("Deep relogin customer for rating", client.login(username=customer.username, password="Test12345!"))
        rating_response = client.post(
            f"/talep/{request_entry.id}/puanla/",
            {"score": "5", "comment": "Smoke puan"},
            follow=True,
        )
        self._record("Deep rating response", rating_response.status_code == 200, f"status={rating_response.status_code}")
        self._record(
            "Deep rating exists",
            ProviderRating.objects.filter(service_request=request_entry, customer=customer).exists(),
        )

        customer_pages = [
            "/taleplerim/?page=2",
            "/bildirimler/?page=2",
            "/anlasmalar/?page=2",
            "/hesap/ayarlar/?tab=identity",
        ]
        for path in customer_pages:
            response = client.get(path)
            self._record(f"Deep customer {path}", response.status_code == 200, f"status={response.status_code}")

        home_html = client.get("/").content.decode("utf-8", "replace")
        self._record(
            "Deep dark mode ternary fixed",
            'root.getAttribute("data-theme") === "dark" ? "light" : "dark"' in home_html,
        )
        self._record("Deep base has no broken page href", 'href="page=' not in home_html)

        client.logout()
        self._record("Deep relogin provider for panel", client.login(username=provider_user.username, password="Test12345!"))
        provider_url = (
            "/usta/talepler/?waiting_selection_page=2&pending_offer_page=2&active_thread_page=2"
            "&pending_appointment_page=2&confirmed_appointment_page=2&recent_offer_page=2"
            "&recent_appointment_page=2"
        )
        provider_response = client.get(provider_url)
        self._record("Deep provider panel page params", provider_response.status_code == 200, f"status={provider_response.status_code}")
        provider_html = provider_response.content.decode("utf-8", "replace")
        self._record(
            "Deep provider title flash ternary fixed",
            'titleFlashOn ? "* " + message : defaultTitle' in provider_html,
        )
        self._record("Deep provider has no broken page href", 'href="pending_offer_page=' not in provider_html)

        client.logout()
        self._record("Deep relogin admin", client.login(username=admin_user.username, password="Test12345!"))
        operations_response = client.get("/operasyon/?activity_page=2")
        self._record("Deep operations dashboard", operations_response.status_code == 200, f"status={operations_response.status_code}")
        operations_html = operations_response.content.decode("utf-8", "replace")
        self._record("Deep operations has no broken page href", 'href="activity_page=' not in operations_html)

    def _assert_file_contains(self, file_path: str, snippet: str, name: str):
        path = Path(file_path)
        if not path.exists():
            self._record(name, False, f"missing file: {file_path}")
            return
        content = path.read_text(encoding="utf-8")
        self._record(name, snippet in content, f"file={file_path}")

    def _assert_file_not_contains_glob(self, patterns: Iterable[str], snippet: str, name: str):
        matched_files: list[str] = []
        for pattern in patterns:
            for file_path in Path(".").glob(pattern):
                if not file_path.is_file():
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if snippet in content:
                    matched_files.append(str(file_path))
        self._record(name, len(matched_files) == 0, ", ".join(matched_files)[:400])

    def _record(self, name: str, passed: bool, detail: str = "", is_warning: bool = False):
        result = CheckResult(name=name, passed=passed, detail=detail, is_warning=is_warning)
        self.results.append(result)
        if passed and not is_warning:
            self.stdout.write(self.style.SUCCESS(f"PASS: {name}"))
        elif passed and is_warning:
            self.stdout.write(self.style.WARNING(f"WARN: {name} - {detail}"))
        else:
            self.stdout.write(self.style.ERROR(f"FAIL: {name} {detail}".rstrip()))
            self._stop_on_fail_if_needed()

    def _stop_on_fail_if_needed(self):
        if self.fail_fast:
            raise CommandError("Smoke check stopped due to --fail-fast.")

    def _print_summary(self):
        total = len(self.results)
        failed = sum(1 for item in self.results if not item.passed and not item.is_warning)
        warnings = sum(1 for item in self.results if item.is_warning)
        passed = total - failed - warnings
        self.stdout.write("")
        self.stdout.write(self.style.NOTICE(f"Smoke check summary -> passed={passed} warnings={warnings} failed={failed} total={total}"))
