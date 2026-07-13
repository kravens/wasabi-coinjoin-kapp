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
"""CoinJoin / batch-signing over USB, as a signed Krux App (kapp).

Self-contained single file per the kapps contract (selfcustody/krux#485):
module attributes plus a ``run(ctx)`` entry point. Bundles the framed USB
link, SLIP-19 proofs, and the coinjoin PSBT policy signer so nothing is
imported from other flash apps.

The signing policy (round budget, max fee rate, min self-transfer) is proposed
by the host wallet software and approved physically on the device once per
session, Trezor-style. There is no device settings menu to pre-configure.
"""
import os

# Kapp convention: don't import sibling modules from the flash app VFS.
os.chdir("/")

import hashlib
import hmac
import time
from io import BytesIO

from embit import bip32, bip39, compact, ec, script

from krux.pages import Page, MENU_CONTINUE
from krux.psbt import PSBTSigner
from krux.qr import FORMAT_NONE
from krux.sats_vb import SatsVB

VERSION = "0.1.0"
NAME = "CoinJoin USB"
# No ALLOW_STARTUP: signing needs a loaded wallet, so this never runs at boot.

# --- link transport -------------------------------------------------------

try:
    from machine import UART

    _ON_DEVICE = True
except ImportError:
    import socket

    _ON_DEVICE = False

TCP_PORT = 52123
UART_BAUDRATE = 115200
FRAME_MAX = 1024 * 1024
_INTERBYTE_TIMEOUT_MS = 5000
MAGIC = b"KXJ1"


class LinkTimeout(Exception):
    """No complete frame arrived in time."""


class Link:
    """Framed link over UARTHS (device) or TCP (simulator)."""

    def __init__(self):
        self._uart = None
        self._server = None
        self._conn = None

    def open(self):
        if _ON_DEVICE:
            try:
                import micropython

                micropython.kbd_intr(-1)
            except Exception:
                pass
            self._uart = UART(UART.UARTHS, UART_BAUDRATE, read_buf_len=8192)
        else:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("127.0.0.1", TCP_PORT))
            self._server.listen(1)
            self._server.settimeout(0.05)

    def close(self):
        if _ON_DEVICE:
            if self._uart:
                self._uart.deinit()
                self._uart = None
        else:
            for sock in (self._conn, self._server):
                if sock:
                    sock.close()
            self._conn = None
            self._server = None

    def _read_exact(self, num_bytes, first_timeout_ms):
        chunks = b""
        timeout_ms = first_timeout_ms
        deadline = time.ticks_add(time.ticks_ms(), first_timeout_ms) if _ON_DEVICE else 0
        while len(chunks) < num_bytes:
            if _ON_DEVICE:
                data = self._uart.read(num_bytes - len(chunks))
                if data:
                    chunks += data
                    deadline = time.ticks_add(time.ticks_ms(), _INTERBYTE_TIMEOUT_MS)
                    continue
                if time.ticks_diff(deadline, time.ticks_ms()) <= 0:
                    if chunks:
                        raise LinkTimeout("frame stalled")
                    return None
                time.sleep_ms(5)
            else:
                if self._conn is None:
                    try:
                        self._conn, _ = self._server.accept()
                    except socket.timeout:
                        return None
                self._conn.settimeout(timeout_ms / 1000)
                try:
                    data = self._conn.recv(num_bytes - len(chunks))
                except socket.timeout:
                    if chunks:
                        raise LinkTimeout("frame stalled")
                    return None
                if not data:
                    self._conn.close()
                    self._conn = None
                    if chunks:
                        raise LinkTimeout("client disconnected mid-frame")
                    return None
                chunks += data
                timeout_ms = _INTERBYTE_TIMEOUT_MS
        return chunks

    def _sync_to_magic(self, first_timeout_ms):
        window = b""
        timeout_ms = first_timeout_ms
        while True:
            byte = self._read_exact(1, timeout_ms)
            if byte is None:
                return False
            window = (window + byte)[-len(MAGIC):]
            if window == MAGIC:
                return True
            timeout_ms = _INTERBYTE_TIMEOUT_MS

    def read_frame(self, timeout_ms=100):
        if not self._sync_to_magic(timeout_ms):
            return None
        header = self._read_exact(4, _INTERBYTE_TIMEOUT_MS)
        if header is None:
            raise LinkTimeout("frame length missing")
        length = int.from_bytes(header, "big")
        if length > FRAME_MAX:
            raise ValueError("frame too large: %d" % length)
        if length == 0:
            return b""
        payload = self._read_exact(length, _INTERBYTE_TIMEOUT_MS)
        if payload is None:
            raise LinkTimeout("frame header without payload")
        return payload

    def write_frame(self, payload):
        data = MAGIC + len(payload).to_bytes(4, "big") + payload
        if _ON_DEVICE:
            self._uart.write(data)
        else:
            if self._conn is None:
                raise LinkTimeout("no client connected")
            self._conn.sendall(data)


# --- SLIP-19 proofs -------------------------------------------------------

SLIP19_MAGIC = b"\x53\x4c\x00\x19"
USER_CONFIRMATION = 1
RESERVED_FLAGS = 0xFE
P2WPKH = "p2wpkh"
P2TR = "p2tr"
_OWNERSHIP_LABELS = ["SLIP-0019", "Ownership identification key"]


def _script_bytes(spk):
    return spk.data if hasattr(spk, "data") else spk


def _ser_string(data):
    return compact.to_bytes(len(data)) + data


def slip21_key(seed, labels):
    node = hmac.new(b"Symmetric key seed", seed, digestmod="sha512").digest()
    for label in labels:
        if isinstance(label, str):
            label = label.encode()
        node = hmac.new(node[:32], b"\x00" + label, digestmod="sha512").digest()
    return node[32:]


def ownership_id(ownership_key, spk):
    return hmac.new(ownership_key, _script_bytes(spk), digestmod="sha256").digest()


def wallet_ownership_key(key):
    seed = bip39.mnemonic_to_seed(key.mnemonic, key.passphrase)
    return slip21_key(seed, _OWNERSHIP_LABELS)


def _sign_p2wpkh(root, derivation, message_hash):
    child = root.derive(derivation)
    return child.sign(message_hash), child.key.get_public_key()


def _sign_p2tr(root, derivation, message_hash):
    child = root.derive(derivation)
    tweaked = child.taproot_tweak()
    return tweaked.schnorr_sign(message_hash), child.key.get_public_key()


def proof_body(flags, ownership_ids):
    if flags & RESERVED_FLAGS:
        raise ValueError("reserved SLIP-19 flags set")
    return (
        SLIP19_MAGIC
        + bytes([flags])
        + compact.to_bytes(len(ownership_ids))
        + b"".join(ownership_ids)
    )


def proof_digest(body, spk, commitment_data):
    if commitment_data is None:
        raise ValueError("missing commitment data")
    script_data = _script_bytes(spk)
    return hashlib.sha256(
        body + _ser_string(script_data) + _ser_string(commitment_data)
    ).digest()


def create_proof(key, script_type, spk, derivation, commitment_data, flags=0):
    if script_type not in (P2WPKH, P2TR):
        raise ValueError("unsupported SLIP-19 script type")
    if commitment_data is None:
        raise ValueError("missing commitment data")
    script_data = _script_bytes(spk)
    own_id = ownership_id(wallet_ownership_key(key), script_data)
    body = proof_body(flags, [own_id])
    digest = proof_digest(body, script_data, commitment_data)
    if script_type == P2WPKH:
        sig, pubkey = _sign_p2wpkh(key.root, derivation, digest)
        expected = script.p2wpkh(pubkey)
        witness = script.witness_p2wpkh(sig, pubkey)
    else:
        sig, pubkey = _sign_p2tr(key.root, derivation, digest)
        expected = script.p2tr(pubkey)
        witness = script.Witness([sig.serialize()])
    if expected.data != script_data:
        raise ValueError("derivation does not match scriptPubKey")
    return body + script.Script().serialize() + witness.serialize()


# --- CoinJoin PSBT signer -------------------------------------------------


class CoinJoinPSBTSigner(PSBTSigner):
    """PSBTSigner that signs only the wallet's own inputs of a coinjoin."""

    def validate(self):
        # Coinjoin PSBTs carry foreign inputs; own-input checks live in
        # coinjoin_amounts() instead of the single-wallet homogeneity check.
        return

    def _coinjoin_policy(self, policy):
        if policy is None:
            raise ValueError("coinjoin not authorized")
        return policy

    def _coinjoin_derivations(self, scope, script_type):
        if script_type == P2TR:
            return [
                (pub, der_info[1])
                for pub, der_info in scope.taproot_bip32_derivations.items()
            ]
        return list(scope.bip32_derivations.items())

    def _own_coinjoin_derivation(self, pub, derivation, script_type, account_prefix):
        if derivation.fingerprint != self.wallet.key.fingerprint:
            return False
        prefix = bip32.parse_path(account_prefix)
        full_path = derivation.derivation
        if full_path[: len(prefix)] != prefix:
            return False
        derived = self.wallet.key.root.derive(full_path)
        if script_type == P2TR:
            return derived.xonly() == pub.xonly()
        return derived.key.sec() == pub.sec()

    def _coinjoin_scope_is_own(self, scope, script_type, account_prefix):
        for pub, der in self._coinjoin_derivations(scope, script_type):
            if self._own_coinjoin_derivation(pub, der, script_type, account_prefix):
                return True
        return False

    def _check_coinjoin_sighashes(self, input_types):
        from embit.transaction import SIGHASH

        for i, inp in enumerate(self.psbt.inputs):
            script_type = input_types[i]
            if script_type == P2WPKH and inp.sighash_type not in (None, SIGHASH.ALL):
                raise ValueError("coinjoin input %d must use SIGHASH_ALL" % i)
            if script_type == P2TR and inp.sighash_type not in (None, SIGHASH.DEFAULT):
                raise ValueError("coinjoin input %d must use SIGHASH_DEFAULT" % i)

    def _in_vbytes_x100(self, script_type):
        if script_type == P2WPKH:
            return int(SatsVB.P2WPKH_IN_SIZE * 100)
        if script_type == P2TR:
            return int(SatsVB.P2TR_IN_SIZE * 100)
        raise ValueError("unsupported coinjoin input script")

    def _out_vbytes_x100(self, script_type):
        if script_type == P2WPKH:
            return int(SatsVB.P2WPKH_OUT_SIZE * 100)
        if script_type == P2TR:
            return int(SatsVB.P2TR_OUT_SIZE * 100)
        raise ValueError("unsupported coinjoin output script")

    def coinjoin_amounts(self, policy=None):
        policy = self._coinjoin_policy(policy)
        if not policy.get("enabled", False):
            raise ValueError("coinjoin policy disabled")
        wallet_fingerprint = policy.get("wallet_fingerprint")
        if wallet_fingerprint and wallet_fingerprint != self.wallet.key.fingerprint:
            raise ValueError("coinjoin wallet fingerprint mismatch")

        allowed_scripts = policy.get("allowed_scripts", (P2WPKH, P2TR))
        account_prefix = policy.get("allowed_account_prefix", self.wallet.key.derivation)
        own_in_value = 0
        own_in_vb_x100 = 0
        own_out_vb_x100 = 0
        own_self_transfer = 0
        input_types = []

        for i, inp in enumerate(self.psbt.inputs):
            if not inp.witness_utxo:
                raise ValueError("coinjoin input %d missing witness UTXO" % i)
            script_type = inp.witness_utxo.script_pubkey.script_type()
            if script_type not in allowed_scripts:
                raise ValueError("unsupported coinjoin input script")
            input_types.append(script_type)
            if self._coinjoin_scope_is_own(inp, script_type, account_prefix):
                own_in_value += inp.witness_utxo.value
                own_in_vb_x100 += self._in_vbytes_x100(script_type)

        if own_in_value <= 0:
            raise ValueError("coinjoin PSBT has no own inputs")

        for i, out in enumerate(self.psbt.outputs):
            script_type = self.psbt.tx.vout[i].script_pubkey.script_type()
            if script_type not in allowed_scripts:
                raise ValueError("unsupported coinjoin output script")
            if self._coinjoin_scope_is_own(out, script_type, account_prefix):
                own_self_transfer += self.psbt.tx.vout[i].value
                own_out_vb_x100 += self._out_vbytes_x100(script_type)

        leak = own_in_value - own_self_transfer
        min_threshold = policy.get("min_self_transfer_pct", 95)
        min_denominator = 100
        if "min_self_transfer_bps" in policy:
            min_threshold = policy["min_self_transfer_bps"]
            min_denominator = 10000
        if not 0 <= min_threshold <= min_denominator:
            raise ValueError("coinjoin self-transfer policy out of range")
        if own_self_transfer * min_denominator < own_in_value * min_threshold:
            raise ValueError("coinjoin self-transfer below policy")
        max_fee_rate = policy.get("max_fee_rate_sat_vb", 5)
        if max_fee_rate < 0:
            raise ValueError("coinjoin fee rate policy out of range")
        # Effective fee rate = leak / own weight (inputs + outputs); input
        # weight alone overstates it for coinjoin fan-out.
        own_vb_x100 = own_in_vb_x100 + own_out_vb_x100
        if max_fee_rate and leak * 100 > own_vb_x100 * max_fee_rate:
            raise ValueError("coinjoin fee rate above policy")

        self._check_coinjoin_sighashes(input_types)
        return {
            "own_input_value": own_in_value,
            "own_self_transfer_value": own_self_transfer,
            "fee_leak": leak,
        }

    def sign_coinjoin(self, policy=None, trim=True):
        self.coinjoin_amounts(policy)
        self.sign(trim=trim)


# --- USB signer page ------------------------------------------------------

CMD_INFO = 1
CMD_PROOF = 2
CMD_SIGN = 3
CMD_AUTHORIZE = 4
_OK = b"\x00"
_ERR = b"\x01"
_SCRIPT_TYPES = {0: "p2wpkh", 1: "p2tr"}
_MAX_ROUNDS_CAP = 0xFFFF


def _t(text):
    try:
        from krux.krux_settings import t

        return t(text)
    except Exception:
        return text


# Official Wasabi "W" logo rasterized (viewBox 75x57) to a 50x38 grid of
# horizontal on-pixel runs [col, length] per row. Shown while authorized so it
# reads unambiguously as Wasabi coinjoin (not another protocol). Generated
# offline from the SVG so the device does no rasterization at runtime.
_LOGO_W = 50
_LOGO_H = 38
_LOGO_RUNS = [[[8,1],[28,1],[40,10]],[[6,3],[26,3],[40,10]],[[4,5],[24,5],[40,10]],[[3,6],[23,6],[40,10]],[[1,9],[21,8],[40,10]],[[0,10],[20,10],[40,10]],[[0,10],[20,10],[40,10]],[[1,9],[21,9],[40,10]],[[1,10],[21,10],[40,10]],[[1,10],[21,10],[40,10]],[[2,10],[21,11]],[[2,10],[22,10]],[[2,11],[22,11]],[[3,10],[23,10]],[[3,11],[23,11]],[[4,10],[23,11]],[[4,11],[24,11]],[[4,11],[24,11]],[[5,11],[25,11]],[[6,43]],[[6,43]],[[7,42]],[[7,42]],[[8,41]],[[9,40]],[[9,40]],[[10,39]],[[11,13],[31,13]],[[12,13],[32,13]],[[13,14],[33,14]],[[14,14],[34,14]],[[15,14],[34,15]],[[16,12],[36,12]],[[17,10],[37,10]],[[18,8],[38,8]],[[19,6],[39,6]],[[20,4],[40,4]],[[22,1],[42,1]]]


def _unpack565(color):
    """Krux stores RGB565 byte-swapped; return (r, g, b) 5/6/5 bits."""
    v = ((color & 0xFF) << 8) | (color >> 8)
    return (v >> 11) & 0x1F, (v >> 5) & 0x3F, v & 0x1F


def _pack565(r, g, b):
    v = (r << 11) | (g << 5) | b
    return ((v & 0xFF) << 8) | (v >> 8)


def _lerp_color(c0, c1, t):
    """Interpolate between two Krux colors; t in 0..1."""
    r0, g0, b0 = _unpack565(c0)
    r1, g1, b1 = _unpack565(c1)
    return _pack565(
        int(r0 + (r1 - r0) * t),
        int(g0 + (g1 - g0) * t),
        int(b0 + (b1 - b0) * t),
    )


_ORANGE = _pack565(31, 41, 0)  # signing-state accent, independent of theme


class CoinJoinSigner(Page):
    """Serves host-authorized CoinJoin signing requests over USB."""

    def __init__(self, ctx):
        super().__init__(ctx, None)
        self.ctx = ctx
        self.authorized = False
        self.policy = None
        self.rounds_used = 0
        self.max_rounds = 0
        self._pulse = 0  # phase for the breathing Wasabi logo
        self._logo = None  # (cell_px, x0, y0) computed once per screen

    def run_signer(self):
        link = Link()
        link.open()
        try:
            self._serve(link)
        finally:
            link.close()
        return MENU_CONTINUE

    def _serve(self, link):
        from krux.auto_shutdown import auto_shutdown

        self._draw_status()
        drawn = self._status_key()
        while True:
            auto_shutdown.feed()
            if self.ctx.input.wait_for_button(block=False) is not None:
                self.ctx.display.clear()
                if self.prompt(
                    _t("Exit remote signing?"), self.ctx.display.height() // 2
                ):
                    return
                self._draw_status()
                drawn = self._status_key()
                continue
            try:
                frame = link.read_frame(50)
            except Exception:
                continue
            if frame is None:
                if self.authorized:
                    self._pulse += 1
                    self._draw_logo()  # breathe while idle between rounds
                continue
            try:
                response = _OK + self._dispatch(frame)
            except Exception as e:
                response = _ERR + str(e).encode()
            try:
                link.write_frame(response)
            except Exception:
                pass
            # Always repaint after a sign so the orange 'Signing' screen clears
            # (even when a sign is rejected and the counter did not move).
            if frame[0] == CMD_SIGN or self._status_key() != drawn:
                self._draw_status()
                drawn = self._status_key()

    def _status_key(self):
        return (self.authorized, self.rounds_used, self.max_rounds)

    def _draw_status(self):
        from krux.themes import theme
        from krux.display import BOTTOM_LINE, FONT_HEIGHT, STATUS_BAR_HEIGHT

        disp = self.ctx.display
        key = self.ctx.wallet.key
        disp.clear()
        if self.authorized:
            # Trezor-style persistent banner while the session is authorized.
            disp.fill_rectangle(0, 0, disp.width(), STATUS_BAR_HEIGHT, theme.go_color)
            disp.draw_hcentered_text(
                _t("CoinJoin Authorized"), 2, theme.bg_color, theme.go_color
            )
            top = STATUS_BAR_HEIGHT
            footer = [
                key.fingerprint_hex_str(True),
                key.derivation_str(True),
                _t("Rounds") + ": %d/%d" % (self.rounds_used, self.max_rounds),
            ]
        else:
            disp.draw_hcentered_text(NAME, 2)
            top = FONT_HEIGHT + 4
            footer = [
                key.fingerprint_hex_str(True),
                # From the device's view the host is what we wait on: Wasabi
                # must connect and propose the policy before we can authorize.
                _t("Waiting for Wasabi Wallet"),
            ]
        # Wasabi "W" logo, centered ~1/3 screen wide. Static+dim while waiting,
        # breathing once authorized (_serve pulses it).
        cell = max(1, disp.width() // 3 // _LOGO_W)
        x0 = (disp.width() - cell * _LOGO_W) // 2
        y0 = top + FONT_HEIGHT // 2
        self._logo = (cell, x0, y0)
        self._draw_logo()
        disp.draw_hcentered_text("\n".join(footer), y0 + cell * _LOGO_H + FONT_HEIGHT)
        # Krux pins the navigation hint to the bottom line.
        disp.draw_hcentered_text(_t("Back"), BOTTOM_LINE)

    def _draw_logo(self):
        """Draws the Wasabi logo at the current breathing intensity, in the
        user's theme accent color. Only the lit pixels are repainted, so this
        is cheap enough to call between USB polls."""
        if not self._logo:
            return
        from krux.themes import theme

        cell, x0, y0 = self._logo
        if self.authorized:
            # triangle wave 0.30..1.0 over a ~2s period at ~20 idle ticks/s
            period = 40
            phase = self._pulse % period
            half = period // 2
            tri = phase if phase < half else (period - phase)
            intensity = 0.30 + 0.70 * (tri / half)
        else:
            intensity = 0.45  # static, dim, while waiting for Wasabi
        color = _lerp_color(theme.bg_color, theme.highlight_color, intensity)
        self._paint_logo(cell, x0, y0, color)

    def _paint_logo(self, cell, x0, y0, color):
        """Fills the logo's lit pixels with one color at the given geometry."""
        disp = self.ctx.display
        for r in range(_LOGO_H):
            for start, length in _LOGO_RUNS[r]:
                disp.fill_rectangle(
                    x0 + start * cell, y0 + r * cell, length * cell, cell, color
                )

    def _draw_signing(self):
        """Active-signing state: 'Signing' plus the W filling with orange from
        the bottom up (a charging fill, not a pulse), then holding solid."""
        if not self._logo:
            return
        from krux.themes import theme
        from krux.display import FONT_HEIGHT, STATUS_BAR_HEIGHT

        disp = self.ctx.display
        cell, x0, y0 = self._logo
        disp.clear()
        disp.fill_rectangle(0, 0, disp.width(), STATUS_BAR_HEIGHT, _ORANGE)
        disp.draw_hcentered_text(_t("Signing"), 2, theme.bg_color, _ORANGE)
        dim = _lerp_color(theme.bg_color, _ORANGE, 0.25)
        for r in range(_LOGO_H):
            for start, length in _LOGO_RUNS[r]:
                disp.fill_rectangle(
                    x0 + start * cell, y0 + r * cell, length * cell, cell, dim
                )
        for r in range(_LOGO_H - 1, -1, -1):  # sweep orange up through the W
            for start, length in _LOGO_RUNS[r]:
                disp.fill_rectangle(
                    x0 + start * cell, y0 + r * cell, length * cell, cell, _ORANGE
                )
        disp.draw_hcentered_text(
            self.ctx.wallet.key.fingerprint_hex_str(True),
            y0 + cell * _LOGO_H + FONT_HEIGHT,
        )

    def _dispatch(self, frame):
        cmd = frame[0]
        if cmd == CMD_INFO:
            return (
                self.ctx.wallet.key.fingerprint
                + self.rounds_used.to_bytes(2, "big")
                + self.max_rounds.to_bytes(2, "big")
                + (b"\x01" if self.authorized else b"\x00")
            )
        if cmd == CMD_AUTHORIZE:
            return self._authorize(frame[1:])
        if cmd == CMD_PROOF:
            self._require_authorized()
            return self._ownership_proof(frame[1:])
        if cmd == CMD_SIGN:
            self._require_authorized()
            return self._sign_round(frame[1:])
        raise ValueError("unknown command")

    def _require_authorized(self):
        if not self.authorized:
            raise ValueError("session not authorized")

    def _authorize(self, body):
        if len(body) < 5:
            raise ValueError("short authorization")
        max_rounds = int.from_bytes(body[0:2], "big")
        max_fee_rate = int.from_bytes(body[2:4], "big")
        min_self_transfer_pct = body[4]
        if not 0 <= min_self_transfer_pct <= 100:
            raise ValueError("invalid self-transfer percent")
        if max_rounds == 0 or max_rounds > _MAX_ROUNDS_CAP:
            raise ValueError("invalid max rounds")

        key = self.ctx.wallet.key
        proposal = "\n".join(
            [
                _t("Authorize CoinJoin?"),
                key.fingerprint_hex_str(True),
                key.derivation_str(True),
                _t("Max rounds") + ": %d" % max_rounds,
                _t("Max fee rate sat/vB") + ": %d" % max_fee_rate,
                _t("Min self-transfer %") + ": %d" % min_self_transfer_pct,
            ]
        )
        from krux.themes import theme
        from krux.display import FONT_HEIGHT

        disp = self.ctx.display
        disp.clear()
        # Dim Wasabi logo in the lower area so the confirm screen is branded
        # too. Drawn before the (blocking) Yes/No prompt, which paints its text
        # near the top and does not clear, so the logo persists below it.
        cell = max(1, disp.width() // 5 // _LOGO_W)
        x0 = (disp.width() - cell * _LOGO_W) // 2
        y0 = disp.height() - cell * _LOGO_H - FONT_HEIGHT
        self._paint_logo(
            cell, x0, y0, _lerp_color(theme.bg_color, theme.highlight_color, 0.40)
        )
        if not self.prompt(proposal, self.ctx.display.height() // 5):
            raise ValueError("authorization declined")

        self.policy = {
            "enabled": True,
            "wallet_fingerprint": key.fingerprint,
            "allowed_scripts": (P2WPKH, P2TR),
            "allowed_account_prefix": key.derivation,
            "min_self_transfer_pct": min_self_transfer_pct,
            "max_fee_rate_sat_vb": max_fee_rate,
        }
        self.max_rounds = max_rounds
        self.rounds_used = 0
        self.authorized = True
        return b""

    def _ownership_proof(self, body):
        if len(body) < 2:
            raise ValueError("short proof request")
        script_type = _SCRIPT_TYPES.get(body[0])
        if script_type is None:
            raise ValueError("unsupported script type")
        path_len = body[1]
        if len(body) < 2 + 4 * path_len:
            raise ValueError("short derivation path")
        path = [
            int.from_bytes(body[2 + 4 * i : 6 + 4 * i], "big") for i in range(path_len)
        ]
        commitment = body[2 + 4 * path_len :]
        if not commitment:
            raise ValueError("missing commitment data")

        key = self.ctx.wallet.key
        prefix = bip32.parse_path(key.derivation)
        if len(path) != len(prefix) + 2 or path[: len(prefix)] != prefix:
            raise ValueError("derivation outside wallet account")

        child = key.root.derive(path)
        pubkey = child.key.get_public_key()
        spk = script.p2tr(pubkey) if script_type == "p2tr" else script.p2wpkh(pubkey)
        return create_proof(key, script_type, spk, path, commitment, USER_CONFIRMATION)

    def _sign_round(self, body):
        if self.max_rounds and self.rounds_used >= self.max_rounds:
            # Authorization is spent: end the session so the host must
            # re-propose the policy and the user re-approves it on the device.
            self.authorized = False
            self.policy = None
            raise ValueError("round budget exhausted, re-authorize")
        self._draw_signing()  # orange 'Signing' state during the blocking sign
        signer = CoinJoinPSBTSigner(self.ctx.wallet, body, FORMAT_NONE)
        signer.sign_coinjoin(self.policy)
        self.rounds_used += 1
        return signer.psbt.serialize()


def run(ctx):
    """Kapp entry point: serve USB coinjoin signing.

    Kapps launch from the pre-login Tools menu, so no wallet is loaded yet.
    Run the standard Load-Mnemonic flow (seed source + network/script choice),
    which sets ctx.wallet, then serve. The chosen account must match the
    watch-only wallet imported into Wasabi.
    """
    if not getattr(ctx, "wallet", None) or ctx.wallet.key is None:
        from krux.pages.login import Login

        Login(ctx).load_key()
    if not getattr(ctx, "wallet", None) or ctx.wallet.key is None:
        return  # user cancelled loading
    CoinJoinSigner(ctx).run_signer()
