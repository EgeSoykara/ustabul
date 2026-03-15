from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("Myapp", "0037_notificationcursor_preferences"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="provider",
            name="last_cash_payment_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="provider",
            name="membership_expires_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name="provider",
            name="membership_note",
            field=models.CharField(blank=True, max_length=240),
        ),
        migrations.AddField(
            model_name="provider",
            name="membership_status",
            field=models.CharField(
                choices=[("trial", "Deneme"), ("active", "Aktif"), ("suspended", "Askıda")],
                default="active",
                max_length=16,
            ),
        ),
        migrations.CreateModel(
            name="ProviderPayment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("amount", models.DecimalField(decimal_places=2, max_digits=10)),
                ("period_months", models.PositiveSmallIntegerField(default=1)),
                ("cash_received_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("note", models.CharField(blank=True, max_length=240)),
                ("membership_extended_from", models.DateTimeField(blank=True, editable=False, null=True)),
                ("membership_extended_until", models.DateTimeField(blank=True, editable=False, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="membership_payments",
                        to="Myapp.provider",
                    ),
                ),
                (
                    "received_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="provider_payments_received",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-cash_received_at", "-id"],
            },
        ),
    ]
