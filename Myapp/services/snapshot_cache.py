from django.core.cache import cache


def _delete_snapshot_keys(prefix, entity_id):
    if not entity_id:
        return
    cache.delete(f"snapshot:{prefix}:{int(entity_id)}:calendar-on")
    cache.delete(f"snapshot:{prefix}:{int(entity_id)}:calendar-off")


def invalidate_customer_snapshot_cache(user_id):
    _delete_snapshot_keys("customer", user_id)


def invalidate_provider_snapshot_cache(provider_id):
    _delete_snapshot_keys("provider", provider_id)

