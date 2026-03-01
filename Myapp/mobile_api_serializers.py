from django.contrib.auth import authenticate
from rest_framework import serializers

from .models import MobileDevice, ServiceRequest


class MobileLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True, trim_whitespace=False, style={"input_type": "password"})

    def validate(self, attrs):
        request = self.context.get("request")
        username = (attrs.get("username") or "").strip()
        password = attrs.get("password") or ""

        user = authenticate(request=request, username=username, password=password)
        if user is None:
            raise serializers.ValidationError("Kullanici adi veya sifre hatali.")
        if not user.is_active:
            raise serializers.ValidationError("Bu hesap pasif durumda.")

        attrs["user"] = user
        attrs["username"] = username
        return attrs


class MobileDeviceRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = MobileDevice
        fields = ("platform", "device_id", "push_token", "app_version", "locale", "timezone")

    def validate_push_token(self, value):
        token = (value or "").strip()
        if not token:
            return None
        if len(token) < 32:
            raise serializers.ValidationError("Push token gecersiz gorunuyor.")
        return token

    def validate_device_id(self, value):
        device_id = (value or "").strip()
        if len(device_id) < 6:
            raise serializers.ValidationError("device_id en az 6 karakter olmalidir.")
        return device_id


class MobileServiceRequestSerializer(serializers.ModelSerializer):
    service_type = serializers.CharField(source="service_type.name", read_only=True)
    matched_provider_name = serializers.SerializerMethodField()
    appointment_status = serializers.SerializerMethodField()
    unread_messages = serializers.SerializerMethodField()

    class Meta:
        model = ServiceRequest
        fields = (
            "id",
            "status",
            "service_type",
            "city",
            "district",
            "details",
            "created_at",
            "matched_provider_name",
            "appointment_status",
            "unread_messages",
        )

    def get_matched_provider_name(self, obj):
        if obj.matched_provider_id:
            return obj.matched_provider.full_name
        return ""

    def get_appointment_status(self, obj):
        appointment_map = self.context.get("appointment_map") or {}
        appointment = appointment_map.get(obj.id)
        return appointment.status if appointment else ""

    def get_unread_messages(self, obj):
        unread_map = self.context.get("unread_map") or {}
        return int(unread_map.get(obj.id, 0))
