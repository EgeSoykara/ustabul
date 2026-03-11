import os
import sys
from pathlib import Path

import django

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

SUPERUSER_USERNAME = os.getenv("AUTO_SUPERUSER_USERNAME", "egesoykara").strip()
SUPERUSER_EMAIL = os.getenv("AUTO_SUPERUSER_EMAIL", "admin@ustabul.local").strip()
SUPERUSER_PASSWORD = os.getenv("AUTO_SUPERUSER_PASSWORD", "egebaba31").strip()
SUPERUSER_FIRST_NAME = os.getenv("AUTO_SUPERUSER_FIRST_NAME", "Ustabul").strip()
SUPERUSER_LAST_NAME = os.getenv("AUTO_SUPERUSER_LAST_NAME", "Admin").strip()
SYNC_PASSWORD = os.getenv("AUTO_SUPERUSER_SYNC_PASSWORD", "1").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Companywebsite.settings")
django.setup()

from django.contrib.auth import get_user_model


def ensure_superuser():
    user_model = get_user_model()

    user, created = user_model.objects.get_or_create(
        username=SUPERUSER_USERNAME,
        defaults={
            "email": SUPERUSER_EMAIL,
            "first_name": SUPERUSER_FIRST_NAME,
            "last_name": SUPERUSER_LAST_NAME,
            "is_staff": True,
            "is_superuser": True,
            "is_active": True,
        },
    )

    needs_save = created

    if user.email != SUPERUSER_EMAIL:
        user.email = SUPERUSER_EMAIL
        needs_save = True
    if hasattr(user, "first_name") and user.first_name != SUPERUSER_FIRST_NAME:
        user.first_name = SUPERUSER_FIRST_NAME
        needs_save = True
    if hasattr(user, "last_name") and user.last_name != SUPERUSER_LAST_NAME:
        user.last_name = SUPERUSER_LAST_NAME
        needs_save = True
    if not user.is_staff:
        user.is_staff = True
        needs_save = True
    if not user.is_superuser:
        user.is_superuser = True
        needs_save = True
    if hasattr(user, "is_active") and not user.is_active:
        user.is_active = True
        needs_save = True
    if created or (SYNC_PASSWORD and not user.check_password(SUPERUSER_PASSWORD)):
        user.set_password(SUPERUSER_PASSWORD)
        needs_save = True

    if needs_save:
        user.save()

    if created:
        print(f"Created superuser '{SUPERUSER_USERNAME}'.")
    else:
        print(f"Superuser '{SUPERUSER_USERNAME}' is ready.")


if __name__ == "__main__":
    ensure_superuser()
