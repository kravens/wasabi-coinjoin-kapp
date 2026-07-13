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
"""Pre-approved CoinJoin / batch-signing remote signer served over USB.

The signing policy (round budget, max fee rate, min self-transfer) is proposed
by the host from the wallet software's settings and approved physically on the
device once per session, mirroring Trezor's AuthorizeCoinJoin. There is no
device settings menu to configure beforehand.

Wire protocol (one request frame -> one response frame):
  request:  cmd(1) + body
  response: 0x00 + body on success, 0x01 + utf8 error message on failure

  CMD_INFO      0x01: () -> fingerprint(4) + rounds_used(2 BE)
                          + max_rounds(2 BE) + authorized(1)
  CMD_PROOF     0x02: script_type(1: 0=p2wpkh 1=p2tr) + path_len(1)
                          + path_len*uint32 BE + commitment_data(rest)
                          -> SLIP-19 proof bytes    (requires authorization)
  CMD_SIGN      0x03: raw PSBT -> signed trimmed PSBT   (requires authorization)
  CMD_AUTHORIZE 0x04: max_rounds(2 BE) + max_fee_rate_sat_vb(2 BE)
                          + min_self_transfer_pct(1)
                          -> () ; shows the proposal, waits for physical confirm
"""
from embit import bip32, script

from krux.pages import Page, MENU_CONTINUE
from krux.qr import FORMAT_NONE

from .link import Link
from .psbt_coinjoin import CoinJoinPSBTSigner
from .slip19 import P2TR, P2WPKH, USER_CONFIRMATION, create_proof

CMD_INFO = 1
CMD_PROOF = 2
CMD_SIGN = 3
CMD_AUTHORIZE = 4
_OK = b"\x00"
_ERR = b"\x01"
_SCRIPT_TYPES = {0: "p2wpkh", 1: "p2tr"}
_MAX_ROUNDS_CAP = 0xFFFF


def _t(text):
    """Translate if the running Krux exposes a catalog, else identity."""
    try:
        from krux.krux_settings import t

        return t(text)
    except Exception:
        return text


class CoinJoinSigner(Page):
    """Serves host-authorized CoinJoin signing requests over USB."""

    def __init__(self, ctx):
        super().__init__(ctx, None)
        self.ctx = ctx
        self.authorized = False
        self.policy = None
        self.rounds_used = 0
        self.max_rounds = 0

    def run_signer(self):
        """Entry point: open the link and serve until the user exits."""
        link = Link()
        link.open()
        try:
            self._serve(link)
        finally:
            link.close()
        return MENU_CONTINUE

    def _serve(self, link):
        """Answers link requests until the user confirms leaving the session."""
        from krux.auto_shutdown import auto_shutdown

        self._draw_status()
        drawn_state = self._status_key()
        while True:
            # Unattended session the user approved; do not let the inactivity
            # timer reboot the device between rounds.
            auto_shutdown.feed()
            if self.ctx.input.wait_for_button(block=False) is not None:
                self.ctx.display.clear()
                if self.prompt(
                    _t("Exit remote signing?"), self.ctx.display.height() // 2
                ):
                    return
                self._draw_status()
                drawn_state = self._status_key()
                continue
            try:
                frame = link.read_frame(50)
            except Exception:
                continue  # stalled or oversized frame; sender gets no reply
            if frame is None:
                continue
            try:
                response = _OK + self._dispatch(frame)
            except Exception as e:
                response = _ERR + str(e).encode()
            try:
                link.write_frame(response)
            except Exception:
                pass  # client went away; keep serving
            if self._status_key() != drawn_state:
                self._draw_status()
                drawn_state = self._status_key()

    def _status_key(self):
        return (self.authorized, self.rounds_used, self.max_rounds)

    def _draw_status(self):
        key = self.ctx.wallet.key
        if self.authorized:
            body = (
                _t("CoinJoin") + " USB\n"
                + key.fingerprint_hex_str(True) + "\n"
                + key.derivation_str(True) + "\n"
                + _t("Rounds") + ": %d/%d\n" % (self.rounds_used, self.max_rounds)
                + _t("Back")
            )
        else:
            body = (
                _t("CoinJoin") + " USB\n"
                + key.fingerprint_hex_str(True) + "\n"
                + _t("Waiting for authorization") + "\n"
                + _t("Back")
            )
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(body)

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
        """Shows the host-proposed policy and waits for physical approval."""
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
        self.ctx.display.clear()
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
        """Builds a SLIP-19 proof for a wallet-owned derivation.

        The scriptPubKey is derived on the device from the requested path,
        never taken from the host, so proofs can only ever cover our own
        scripts. The path must be exactly account prefix + change + index.
        """
        if len(body) < 2:
            raise ValueError("short proof request")
        script_type = _SCRIPT_TYPES.get(body[0])
        if script_type is None:
            raise ValueError("unsupported script type")
        path_len = body[1]
        if len(body) < 2 + 4 * path_len:
            raise ValueError("short derivation path")
        path = [
            int.from_bytes(body[2 + 4 * i : 6 + 4 * i], "big")
            for i in range(path_len)
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
        script_pubkey = (
            script.p2tr(pubkey) if script_type == "p2tr" else script.p2wpkh(pubkey)
        )
        return create_proof(
            key, script_type, script_pubkey, path, commitment, USER_CONFIRMATION
        )

    def _sign_round(self, body):
        """Signs one coinjoin PSBT under the authorized session policy."""
        if self.max_rounds and self.rounds_used >= self.max_rounds:
            raise ValueError("round budget exhausted")
        signer = CoinJoinPSBTSigner(self.ctx.wallet, body, FORMAT_NONE)
        signer.sign_coinjoin(self.policy)  # raises on any policy violation
        self.rounds_used += 1
        return signer.psbt.serialize()
