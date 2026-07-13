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
"""CoinJoin PSBT signer, as a subclass of the stock PSBTSigner.

Everything coinjoin-specific lives here so the official ``krux.psbt`` is not
edited. A coinjoin PSBT carries other participants' inputs, so ``validate()``
(which asserts every input shares one wallet policy) is skipped; own-input
validation happens in ``coinjoin_amounts`` instead. The signing policy is
supplied by the host and approved on the device (see the signer), never read
from a device settings menu.
"""
from krux.psbt import PSBTSigner
from krux.sats_vb import SatsVB

from .slip19 import P2TR, P2WPKH


class CoinJoinPSBTSigner(PSBTSigner):
    """PSBTSigner that signs only the wallet's own inputs of a coinjoin."""

    def validate(self):
        # Coinjoin PSBTs mix foreign inputs; the stock homogeneity check would
        # reject them. coinjoin_amounts() validates our own inputs instead.
        return

    def _coinjoin_policy(self, policy):
        """Returns the host-proposed, device-approved signing policy."""
        if policy is None:
            raise ValueError("coinjoin not authorized")
        return policy

    def _coinjoin_derivations(self, scope, script_type):
        """Returns derivation entries relevant to the script type."""
        if script_type == P2TR:
            return [
                (pub, der_info[1])
                for pub, der_info in scope.taproot_bip32_derivations.items()
            ]
        return list(scope.bip32_derivations.items())

    def _own_coinjoin_derivation(self, pub, derivation, script_type, account_prefix):
        """Checks fingerprint, account prefix, and derived pubkey."""
        from embit import bip32

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
        """Returns true when a PSBT input/output scope belongs to the wallet."""
        for pub, der in self._coinjoin_derivations(scope, script_type):
            if self._own_coinjoin_derivation(pub, der, script_type, account_prefix):
                return True
        return False

    def _check_coinjoin_sighashes(self, input_types):
        """CoinJoin mode only allows ALL for P2WPKH and DEFAULT for P2TR."""
        from embit.transaction import SIGHASH

        for i, inp in enumerate(self.psbt.inputs):
            script_type = input_types[i]
            if script_type == P2WPKH and inp.sighash_type not in (None, SIGHASH.ALL):
                raise ValueError("coinjoin input %d must use SIGHASH_ALL" % i)
            if script_type == P2TR and inp.sighash_type not in (None, SIGHASH.DEFAULT):
                raise ValueError("coinjoin input %d must use SIGHASH_DEFAULT" % i)

    def _coinjoin_input_vbytes_x100(self, script_type):
        """Returns signed owned-input vbytes multiplied by 100."""
        if script_type == P2WPKH:
            return int(SatsVB.P2WPKH_IN_SIZE * 100)
        if script_type == P2TR:
            return int(SatsVB.P2TR_IN_SIZE * 100)
        raise ValueError("unsupported coinjoin input script")

    def _coinjoin_output_vbytes_x100(self, script_type):
        """Returns owned-output vbytes multiplied by 100."""
        if script_type == P2WPKH:
            return int(SatsVB.P2WPKH_OUT_SIZE * 100)
        if script_type == P2TR:
            return int(SatsVB.P2TR_OUT_SIZE * 100)
        raise ValueError("unsupported coinjoin output script")

    def coinjoin_amounts(self, policy=None):
        """Validates CoinJoin policy and returns own input/return/leak amounts."""
        policy = self._coinjoin_policy(policy)
        if not policy.get("enabled", False):
            raise ValueError("coinjoin policy disabled")
        wallet_fingerprint = policy.get("wallet_fingerprint")
        if wallet_fingerprint and wallet_fingerprint != self.wallet.key.fingerprint:
            raise ValueError("coinjoin wallet fingerprint mismatch")

        allowed_scripts = policy.get("allowed_scripts", (P2WPKH, P2TR))
        account_prefix = policy.get(
            "allowed_account_prefix", self.wallet.key.derivation
        )
        own_input_value = 0
        own_input_vbytes_x100 = 0
        own_output_vbytes_x100 = 0
        own_self_transfer_value = 0
        input_types = []

        for i, inp in enumerate(self.psbt.inputs):
            if not inp.witness_utxo:
                raise ValueError("coinjoin input %d missing witness UTXO" % i)
            script_type = inp.witness_utxo.script_pubkey.script_type()
            if script_type not in allowed_scripts:
                raise ValueError("unsupported coinjoin input script")
            input_types.append(script_type)
            if self._coinjoin_scope_is_own(inp, script_type, account_prefix):
                own_input_value += inp.witness_utxo.value
                own_input_vbytes_x100 += self._coinjoin_input_vbytes_x100(script_type)

        if own_input_value <= 0:
            raise ValueError("coinjoin PSBT has no own inputs")

        for i, out in enumerate(self.psbt.outputs):
            script_type = self.psbt.tx.vout[i].script_pubkey.script_type()
            if script_type not in allowed_scripts:
                raise ValueError("unsupported coinjoin output script")
            if self._coinjoin_scope_is_own(out, script_type, account_prefix):
                own_self_transfer_value += self.psbt.tx.vout[i].value
                own_output_vbytes_x100 += self._coinjoin_output_vbytes_x100(
                    script_type
                )

        leak = own_input_value - own_self_transfer_value
        min_threshold = policy.get("min_self_transfer_pct", 95)
        min_denominator = 100
        if "min_self_transfer_bps" in policy:
            min_threshold = policy["min_self_transfer_bps"]
            min_denominator = 10000
        if not 0 <= min_threshold <= min_denominator:
            raise ValueError("coinjoin self-transfer policy out of range")
        if own_self_transfer_value * min_denominator < own_input_value * min_threshold:
            raise ValueError("coinjoin self-transfer below policy")
        max_fee_rate = policy.get("max_fee_rate_sat_vb", 5)
        if max_fee_rate < 0:
            raise ValueError("coinjoin fee rate policy out of range")
        # Effective fee rate is the value we lose divided by our own weight in
        # the tx (inputs + outputs). Dividing by input weight alone overstates
        # it for coinjoins, which fan one input out into many owned outputs.
        own_vbytes_x100 = own_input_vbytes_x100 + own_output_vbytes_x100
        if max_fee_rate and leak * 100 > own_vbytes_x100 * max_fee_rate:
            raise ValueError("coinjoin fee rate above policy")

        self._check_coinjoin_sighashes(input_types)
        return {
            "own_input_value": own_input_value,
            "own_self_transfer_value": own_self_transfer_value,
            "fee_leak": leak,
        }

    def sign_coinjoin(self, policy=None, trim=True):
        """Signs a policy-approved CoinJoin PSBT."""
        self.coinjoin_amounts(policy)
        self.sign(trim=trim)
