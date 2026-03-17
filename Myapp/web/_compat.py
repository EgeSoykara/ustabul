from .. import core_views


def bind_core_runtime():
    from .. import views as compat_views

    compat_views._sync_core_bindings()
    return core_views


def forward(function_name):
    def _wrapped(*args, **kwargs):
        core = bind_core_runtime()
        return getattr(core, function_name)(*args, **kwargs)

    _wrapped.__name__ = function_name
    return _wrapped
