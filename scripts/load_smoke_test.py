#!/usr/bin/env python
"""Concurrent load smoke test for public and authenticated Django endpoints.

This script:
1) Ensures deterministic local fixture users/data exist.
2) Starts the local Django dev server.
3) Logs in as customer and provider to obtain session cookies.
4) Runs concurrent GET load scenarios and prints latency/error metrics.
"""

from __future__ import annotations

import concurrent.futures
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
HOST = "127.0.0.1"
PORT = 8050
BASE_URL = f"http://{HOST}:{PORT}"
SERVER_START_TIMEOUT_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 10

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass
class RequestResult:
    ok: bool
    status: int
    latency_ms: float
    error: str = ""


@dataclass(frozen=True)
class Target:
    path: str
    headers: Optional[Dict[str, str]] = None


def wait_for_server(url: str, timeout_seconds: int) -> bool:
    start = time.perf_counter()
    while time.perf_counter() - start < timeout_seconds:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if 200 <= resp.status < 500:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def fetch(target: Target) -> RequestResult:
    url = f"{BASE_URL}{target.path}"
    start = time.perf_counter()
    try:
        headers = {"User-Agent": "load-smoke-test/2.0"}
        if target.headers:
            headers.update(target.headers)
        req = urllib.request.Request(url, method="GET", headers=headers)
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            _ = resp.read()
            latency_ms = (time.perf_counter() - start) * 1000
            return RequestResult(ok=(200 <= resp.status < 400), status=resp.status, latency_ms=latency_ms)
    except urllib.error.HTTPError as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        return RequestResult(ok=False, status=exc.code, latency_ms=latency_ms, error=f"http-{exc.code}")
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        return RequestResult(ok=False, status=0, latency_ms=latency_ms, error=str(exc))


def percentile(sorted_values: List[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if pct <= 0:
        return sorted_values[0]
    if pct >= 100:
        return sorted_values[-1]
    rank = (len(sorted_values) - 1) * (pct / 100.0)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = rank - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def discover_provider_detail_path() -> Optional[str]:
    try:
        req = urllib.request.Request(f"{BASE_URL}/", method="GET")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None
    match = re.search(r'href="(/usta/\d+/)"', html)
    if not match:
        return None
    return match.group(1)


def run_scenario(name: str, targets: List[Target], total_requests: int, concurrency: int) -> Dict[str, object]:
    results: List[RequestResult] = []
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for i in range(total_requests):
            target = targets[i % len(targets)]
            futures.append(executor.submit(fetch, target))
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    duration = time.perf_counter() - start

    latencies = sorted(result.latency_ms for result in results)
    status_counts: Dict[int, int] = {}
    error_counts: Dict[str, int] = {}
    ok_count = 0
    for result in results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
        if result.ok:
            ok_count += 1
        elif result.error:
            error_counts[result.error] = error_counts.get(result.error, 0) + 1

    rps = (len(results) / duration) if duration > 0 else 0.0
    success_rate = (ok_count / len(results) * 100.0) if results else 0.0

    return {
        "name": name,
        "total_requests": len(results),
        "concurrency": concurrency,
        "duration_s": duration,
        "rps": rps,
        "success_rate": success_rate,
        "status_counts": status_counts,
        "error_counts": error_counts,
        "latency_avg_ms": statistics.fmean(latencies) if latencies else 0.0,
        "latency_p50_ms": percentile(latencies, 50),
        "latency_p90_ms": percentile(latencies, 90),
        "latency_p95_ms": percentile(latencies, 95),
        "latency_p99_ms": percentile(latencies, 99),
        "latency_max_ms": max(latencies) if latencies else 0.0,
    }


def print_report(report: Dict[str, object]) -> None:
    print("")
    print(f"Scenario: {report['name']}")
    print(f"  requests        : {report['total_requests']}")
    print(f"  concurrency     : {report['concurrency']}")
    print(f"  duration (s)    : {report['duration_s']:.2f}")
    print(f"  throughput (rps): {report['rps']:.2f}")
    print(f"  success rate    : {report['success_rate']:.2f}%")
    print(f"  latency avg (ms): {report['latency_avg_ms']:.2f}")
    print(f"  latency p50 (ms): {report['latency_p50_ms']:.2f}")
    print(f"  latency p90 (ms): {report['latency_p90_ms']:.2f}")
    print(f"  latency p95 (ms): {report['latency_p95_ms']:.2f}")
    print(f"  latency p99 (ms): {report['latency_p99_ms']:.2f}")
    print(f"  latency max (ms): {report['latency_max_ms']:.2f}")
    print(f"  status counts   : {report['status_counts']}")
    if report["error_counts"]:
        print(f"  error counts    : {report['error_counts']}")


def extract_csrf_token(html: str) -> str:
    match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    if not match:
        return ""
    return match.group(1)


def cookie_header_from_jar(jar: CookieJar) -> str:
    cookies = [f"{cookie.name}={cookie.value}" for cookie in jar]
    return "; ".join(cookies)


def login_and_get_cookie_header(login_path: str, username: str, password: str) -> str:
    login_url = f"{BASE_URL}{login_path}"
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    with opener.open(urllib.request.Request(login_url, method="GET"), timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        html = resp.read().decode("utf-8", errors="ignore")
    csrf_token = extract_csrf_token(html)
    if not csrf_token:
        raise RuntimeError(f"CSRF token parse failed for {login_path}")

    payload = urllib.parse.urlencode(
        {"csrfmiddlewaretoken": csrf_token, "username": username, "password": password}
    ).encode("utf-8")
    post_req = urllib.request.Request(
        login_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": login_url,
            "Origin": BASE_URL,
            "User-Agent": "load-smoke-test/2.0",
        },
    )
    with opener.open(post_req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
        final_url = resp.geturl()
        _ = resp.read()

    if final_url.rstrip("/") == login_url.rstrip("/"):
        raise RuntimeError(f"Login failed for {username} at {login_path}")

    cookie_header = cookie_header_from_jar(jar)
    if "sessionid=" not in cookie_header:
        raise RuntimeError(f"Session cookie missing after login for {username}")
    return cookie_header


def ensure_auth_fixtures() -> Dict[str, object]:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Companywebsite.settings")

    import django

    django.setup()

    from django.contrib.auth.models import User
    from django.utils import timezone

    from Myapp.models import CustomerProfile, Provider, ProviderOffer, ServiceMessage, ServiceRequest, ServiceType

    password = "LoadTest_123!"
    customer_username = "loadtest_customer"
    provider_username = "loadtest_provider"

    customer_user, _ = User.objects.get_or_create(
        username=customer_username,
        defaults={"email": "loadtest_customer@example.com", "is_active": True},
    )
    if (not customer_user.check_password(password)) or (not customer_user.is_active):
        customer_user.set_password(password)
        customer_user.is_active = True
        customer_user.save(update_fields=["password", "is_active"])
    CustomerProfile.objects.update_or_create(
        user=customer_user,
        defaults={"phone": "5550001111", "city": "Istanbul", "district": "Kadikoy"},
    )

    provider_user, _ = User.objects.get_or_create(
        username=provider_username,
        defaults={"email": "loadtest_provider@example.com", "is_active": True},
    )
    if (not provider_user.check_password(password)) or (not provider_user.is_active):
        provider_user.set_password(password)
        provider_user.is_active = True
        provider_user.save(update_fields=["password", "is_active"])

    provider_defaults = {
        "full_name": "Load Test Provider",
        "city": "Istanbul",
        "district": "Kadikoy",
        "phone": "5550002222",
        "description": "Fixture provider for load testing.",
        "is_available": True,
        "is_verified": True,
    }
    provider, created = Provider.objects.get_or_create(user=provider_user, defaults=provider_defaults)
    provider_dirty = created
    for field_name, value in provider_defaults.items():
        if getattr(provider, field_name) != value:
            setattr(provider, field_name, value)
            provider_dirty = True
    if provider.user_id != provider_user.id:
        provider.user = provider_user
        provider_dirty = True
    if provider_dirty:
        provider.save()

    service_type, _ = ServiceType.objects.get_or_create(
        slug="load-test-service",
        defaults={"name": "Load Test Service"},
    )
    provider.service_types.add(service_type)

    service_request = (
        ServiceRequest.objects.filter(request_fingerprint="load-smoke-request", customer=customer_user)
        .order_by("-id")
        .first()
    )
    if not service_request:
        service_request = ServiceRequest.objects.create(
            customer_name="Load Test Customer",
            customer_phone="5550001111",
            city="Istanbul",
            district="Kadikoy",
            service_type=service_type,
            details="Fixture request for auth load scenarios.",
            customer=customer_user,
            status="matched",
            created_ip="127.0.0.1",
            request_fingerprint="load-smoke-request",
            matched_provider=provider,
        )
    else:
        request_dirty = False
        if service_request.service_type_id != service_type.id:
            service_request.service_type = service_type
            request_dirty = True
        if service_request.customer_id != customer_user.id:
            service_request.customer = customer_user
            request_dirty = True
        if service_request.status != "matched":
            service_request.status = "matched"
            request_dirty = True
        if service_request.matched_provider_id != provider.id:
            service_request.matched_provider = provider
            request_dirty = True
        if request_dirty:
            service_request.save()

    offer, _ = ProviderOffer.objects.get_or_create(
        service_request=service_request,
        provider=provider,
        defaults={
            "token": uuid4().hex[:24],
            "sequence": 1,
            "status": "accepted",
            "quote_note": "Fixture accepted quote",
            "responded_at": timezone.now(),
        },
    )
    offer_dirty = False
    if offer.status != "accepted":
        offer.status = "accepted"
        offer_dirty = True
    if offer.responded_at is None:
        offer.responded_at = timezone.now()
        offer_dirty = True
    if offer_dirty:
        offer.save(update_fields=["status", "responded_at"])

    if service_request.matched_offer_id != offer.id or service_request.matched_provider_id != provider.id:
        service_request.matched_offer = offer
        service_request.matched_provider = provider
        if service_request.matched_at is None:
            service_request.matched_at = timezone.now()
        service_request.status = "matched"
        service_request.save(update_fields=["matched_offer", "matched_provider", "matched_at", "status"])

    if not ServiceMessage.objects.filter(service_request=service_request).exists():
        ServiceMessage.objects.create(
            service_request=service_request,
            sender_user=customer_user,
            sender_role="customer",
            body="Load test fixture message from customer.",
        )
        ServiceMessage.objects.create(
            service_request=service_request,
            sender_user=provider_user,
            sender_role="provider",
            body="Load test fixture reply from provider.",
        )

    return {
        "customer_username": customer_username,
        "provider_username": provider_username,
        "password": password,
        "request_id": service_request.id,
    }


def main() -> int:
    print("Preparing local fixture data for authenticated load scenarios...")
    fixture = ensure_auth_fixtures()

    print("Starting local Django server for load smoke test...")
    server = subprocess.Popen(
        [sys.executable, "manage.py", "runserver", f"{HOST}:{PORT}", "--noreload"],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_server(f"{BASE_URL}/", SERVER_START_TIMEOUT_SECONDS):
            print("ERROR: Server did not start in time.")
            return 2

        public_targets: List[Target] = [
            Target("/"),
            Target("/giris/"),
            Target("/kayit/"),
            Target("/usta/giris/"),
            Target("/usta/kayit/"),
            Target("/contact/"),
        ]
        provider_path = discover_provider_detail_path()
        if provider_path:
            public_targets.append(Target(provider_path))

        print(f"Public targets: {[item.path for item in public_targets]}")

        print("Logging in as fixture customer/provider...")
        customer_cookie = login_and_get_cookie_header(
            "/giris/",
            str(fixture["customer_username"]),
            str(fixture["password"]),
        )
        provider_cookie = login_and_get_cookie_header(
            "/usta/giris/",
            str(fixture["provider_username"]),
            str(fixture["password"]),
        )
        request_id = int(fixture["request_id"])

        customer_targets: List[Target] = [
            Target("/taleplerim/", headers={"Cookie": customer_cookie}),
            Target("/bildirimler/", headers={"Cookie": customer_cookie}),
            Target("/api/customer/requests-snapshot/", headers={"Cookie": customer_cookie, "Accept": "application/json"}),
            Target(f"/talep/{request_id}/mesajlar/", headers={"Cookie": customer_cookie}),
            Target(
                f"/api/talep/{request_id}/mesajlar/?after_id=0",
                headers={"Cookie": customer_cookie, "Accept": "application/json"},
            ),
        ]

        provider_targets: List[Target] = [
            Target("/usta/talepler/", headers={"Cookie": provider_cookie}),
            Target("/usta/profil/", headers={"Cookie": provider_cookie}),
            Target("/bildirimler/", headers={"Cookie": provider_cookie}),
            Target("/api/provider/panel-snapshot/", headers={"Cookie": provider_cookie, "Accept": "application/json"}),
            Target(f"/talep/{request_id}/mesajlar/", headers={"Cookie": provider_cookie}),
            Target(
                f"/api/talep/{request_id}/mesajlar/?after_id=0",
                headers={"Cookie": provider_cookie, "Accept": "application/json"},
            ),
        ]

        mixed_targets = customer_targets + provider_targets

        warmup = run_scenario("warmup-public", public_targets, total_requests=50, concurrency=10)
        print_report(warmup)

        public_moderate = run_scenario("public-moderate", public_targets, total_requests=300, concurrency=25)
        print_report(public_moderate)

        customer_auth = run_scenario("customer-auth", customer_targets, total_requests=280, concurrency=20)
        print_report(customer_auth)

        provider_auth = run_scenario("provider-auth", provider_targets, total_requests=280, concurrency=20)
        print_report(provider_auth)

        mixed_auth_high = run_scenario("mixed-auth-high", mixed_targets, total_requests=900, concurrency=60)
        print_report(mixed_auth_high)

        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
