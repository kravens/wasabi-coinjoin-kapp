# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors
#
# (MIT header trimmed for brevity in this patch file; full header in the PR.)
"""Minimal registry for optional add-on features (extensions).

Proposed for the official Krux repo so add-ons like coinjoin/batch-signing or
silent payments can plug in without editing core modules. Extensions live in
``krux/extensions/<name>/`` and self-register on import; the installed set is
listed in a build-time generated ``_installed.py``.
"""
_sign_menu_hooks = []
_loaded = False


def register_sign_menu(fn):
    """Registers a callable ``fn(ctx) -> [(label, handler), ...]`` whose
    entries are appended to the Sign submenu."""
    _sign_menu_hooks.append(fn)


def _ensure_loaded():
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        from . import _installed
    except ImportError:
        return
    for name in _installed.EXTENSIONS:
        try:
            __import__("krux.extensions." + name)
        except Exception:
            pass


def sign_menu_entries(ctx):
    """Entries contributed by all installed extensions for the Sign submenu."""
    _ensure_loaded()
    entries = []
    for fn in _sign_menu_hooks:
        try:
            entries.extend(fn(ctx))
        except Exception:
            pass
    return entries
