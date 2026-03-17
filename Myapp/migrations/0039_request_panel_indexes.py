from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("Myapp", "0038_provider_membership"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="servicerequest",
            index=models.Index(fields=["status", "created_at"], name="sr_status_created_idx"),
        ),
        migrations.AddIndex(
            model_name="servicerequest",
            index=models.Index(fields=["customer", "status", "created_at"], name="sr_customer_status_idx"),
        ),
        migrations.AddIndex(
            model_name="servicerequest",
            index=models.Index(fields=["matched_provider", "status", "created_at"], name="sr_matched_status_idx"),
        ),
        migrations.AddIndex(
            model_name="serviceappointment",
            index=models.Index(fields=["status", "created_at"], name="sa_status_created_idx"),
        ),
        migrations.AddIndex(
            model_name="serviceappointment",
            index=models.Index(fields=["status", "updated_at"], name="sa_status_updated_idx"),
        ),
        migrations.AddIndex(
            model_name="serviceappointment",
            index=models.Index(fields=["provider", "status", "scheduled_for"], name="sa_provider_sched_idx"),
        ),
        migrations.AddIndex(
            model_name="provideroffer",
            index=models.Index(fields=["provider", "status", "created_at"], name="po_provider_status_idx"),
        ),
        migrations.AddIndex(
            model_name="provideroffer",
            index=models.Index(fields=["service_request", "status", "sequence"], name="po_request_status_idx"),
        ),
        migrations.AddIndex(
            model_name="provideroffer",
            index=models.Index(fields=["status", "expires_at"], name="po_status_expires_idx"),
        ),
    ]
