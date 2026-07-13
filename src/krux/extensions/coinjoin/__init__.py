# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""CoinJoin / batch-signing over USB, as a Krux extension.

The maintainer of the official repo prefers the coinjoin vocabulary stay out
of the tree, so this ships as a self-contained add-on: it adds one entry to
the Sign menu and touches no official module. The same signer also does plain
batched (multi-wallet) transaction signing — coinjoin is one policy over it.
"""
NAME = "CoinJoin USB"


def _label():
    try:
        from krux.krux_settings import t

        return "%s USB" % t("CoinJoin")
    except Exception:
        return "CoinJoin USB"


def run(ctx):
    """Kapp-style entry point (selfcustody/krux#485): every Krux app exposes
    ``run(ctx)``. Building this in now means the same code drops into the
    signed-apps (kapps) distribution once that framework lands, with no rework
    — the only change is packaging (frozen extension today, signed .mpy then).
    """
    from .signer import CoinJoinSigner

    return CoinJoinSigner(ctx).run_signer()


def menu_entries(ctx):
    """Sign-submenu entries this extension contributes: (label, handler)."""
    return [(_label(), lambda: run(ctx))]


# Self-register with the host's extension registry when present (the upstream
# hooks PR). Harmless no-op if the registry isn't installed; apply.py's
# fallback patch wires the menu directly in that case.
try:
    from krux import extensions as _ext

    _ext.register_sign_menu(menu_entries)
except Exception:
    pass
