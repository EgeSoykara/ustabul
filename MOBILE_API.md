# Mobile API Guide

Taban adres:

```text
/mobile/api/v1/
```

## Authentication

### `POST /mobile/api/v1/auth/login/`

Request:

```json
{
  "username": "kullanici",
  "password": "sifre"
}
```

Response:

```json
{
  "access": "jwt-access-token",
  "refresh": "jwt-refresh-token",
  "user": {
    "id": 12,
    "username": "kullanici",
    "role": "customer"
  },
  "snapshot": {}
}
```

### `POST /mobile/api/v1/auth/refresh/`

Request:

```json
{
  "refresh": "jwt-refresh-token"
}
```

Response:

```json
{
  "access": "new-access-token"
}
```

## Profile

### `GET /mobile/api/v1/me/`

Header:

```text
Authorization: Bearer <access-token>
```

## Customer

### `GET /mobile/api/v1/customer/requests/?limit=20&offset=0`

Musteri talepleri + okunmamis mesaj sayilari.

## Provider

### `GET /mobile/api/v1/provider/dashboard/?thread_limit=20`

Usta panel snapshot + aktif is listesi.

## Messages

### `GET /mobile/api/v1/requests/<request_id>/messages/?after_id=0`

### `POST /mobile/api/v1/requests/<request_id>/messages/`

Request:

```json
{
  "body": "Merhaba, 30 dk icinde gelebilirim."
}
```

## Push token

### `POST /mobile/api/v1/devices/register/`

Request:

```json
{
  "platform": "android",
  "device_id": "android-12345",
  "push_token": "fcm-token",
  "app_version": "1.0.0",
  "locale": "tr_TR",
  "timezone": "Europe/Istanbul"
}
```

## Settings

`.env`:

```env
MOBILE_JWT_ACCESS_MINUTES=30
MOBILE_JWT_REFRESH_DAYS=14
```
