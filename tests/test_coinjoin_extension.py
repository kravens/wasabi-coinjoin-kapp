"""Extension test suite. Copied into a patched Krux checkout's tests/ tree at
validation time so it can use Krux's conftest fixtures (m5stickv) and the
tests.pages.create_ctx helper.
"""
import pytest

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _key():
    from embit.networks import NETWORKS
    from krux.key import Key, P2WPKH, TYPE_SINGLESIG

    return Key(MNEMONIC, TYPE_SINGLESIG, NETWORKS["test"], script_type=P2WPKH)


class FakeWallet:
    def __init__(self, key):
        self.key = key
        self.policy = {"type": "p2wpkh"}
        self.descriptor = None

    def is_miniscript(self):
        return False

    def is_multisig(self):
        return False

    def is_loaded(self):
        return True


def _coinjoin_psbt(key, foreign=False):
    """Own input, own change, external output; optional foreign input."""
    from embit import bip32, ec, script
    from embit.psbt import DerivationPath, PSBT
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    input_path = bip32.parse_path("m/84h/1h/0h/0/0")
    output_path = bip32.parse_path("m/84h/1h/0h/1/0")
    input_pub = key.root.derive(input_path).key.get_public_key()
    output_pub = key.root.derive(output_path).key.get_public_key()
    external_pub = key.root.derive("m/84h/1h/1h/0/0").key.get_public_key()

    vin = [TransactionInput(b"\x01" * 32, 0)]
    if foreign:
        vin.append(TransactionInput(b"\x02" * 32, 0))
    tx = Transaction(
        vin=vin,
        vout=[
            TransactionOutput(9600, script.p2wpkh(output_pub)),
            TransactionOutput(300, script.p2wpkh(external_pub)),
        ],
    )
    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(10000, script.p2wpkh(input_pub))
    psbt.inputs[0].bip32_derivations[input_pub] = DerivationPath(
        key.fingerprint, input_path
    )
    if foreign:
        foreign_pub = ec.PrivateKey(b"\x11" * 32).get_public_key()
        psbt.inputs[1].witness_utxo = TransactionOutput(
            10000, script.p2wpkh(foreign_pub)
        )
    psbt.outputs[0].bip32_derivations[output_pub] = DerivationPath(
        key.fingerprint, output_path
    )
    return psbt


def _policy(**over):
    p = {
        "enabled": True,
        "allowed_scripts": ("p2wpkh",),
        "allowed_account_prefix": "m/84h/1h/0h",
        "min_self_transfer_pct": 95,
        "max_fee_rate_sat_vb": 6,
    }
    p.update(over)
    return p


# --- SLIP-19 proofs -------------------------------------------------------


def test_slip19_proof_roundtrip_p2wpkh(m5stickv):
    from embit import bip32, script
    from krux.extensions.coinjoin.slip19 import create_proof, verify_proof

    key = _key()
    path = bip32.parse_path("m/84h/1h/0h/0/0")
    spk = script.p2wpkh(key.root.derive(path).key.get_public_key())
    proof = create_proof(key, "p2wpkh", spk, path, b"coordinator", flags=1)
    assert verify_proof(proof, spk, b"coordinator", require_confirmation=True)


def test_slip19_proof_roundtrip_p2tr(m5stickv):
    from embit import bip32, script
    from krux.extensions.coinjoin.slip19 import create_proof, verify_proof

    key = _key()
    path = bip32.parse_path("m/86h/1h/0h/0/0")
    spk = script.p2tr(key.root.derive(path).key.get_public_key())
    proof = create_proof(key, "p2tr", spk, path, b"coordinator", flags=1)
    assert verify_proof(proof, spk, b"coordinator", require_confirmation=True)


# --- CoinJoin policy signer ----------------------------------------------


def test_policy_signs_and_rejects(m5stickv):
    from krux.extensions.coinjoin.psbt_coinjoin import CoinJoinPSBTSigner

    wallet = FakeWallet(_key())

    signer = CoinJoinPSBTSigner(wallet, _coinjoin_psbt(wallet.key).serialize(), None)
    assert signer.coinjoin_amounts(_policy())["fee_leak"] == 400
    signer.sign_coinjoin(_policy(), trim=False)
    assert signer.psbt.inputs[0].partial_sigs

    # effective fee rate = 400 / (67.75 + 31) = 4.05 sat/vB -> 4 rejects
    signer = CoinJoinPSBTSigner(wallet, _coinjoin_psbt(wallet.key).serialize(), None)
    with pytest.raises(ValueError, match="fee rate above"):
        signer.sign_coinjoin(_policy(max_fee_rate_sat_vb=4))

    signer = CoinJoinPSBTSigner(wallet, _coinjoin_psbt(wallet.key).serialize(), None)
    with pytest.raises(ValueError, match="self-transfer below"):
        signer.sign_coinjoin(_policy(min_self_transfer_pct=99))

    with pytest.raises(ValueError, match="not authorized"):
        CoinJoinPSBTSigner(
            wallet, _coinjoin_psbt(wallet.key).serialize(), None
        ).sign_coinjoin(None)


def test_policy_signs_only_own_input_in_mixed_psbt(m5stickv):
    from embit.psbt import PSBT
    from krux.extensions.coinjoin.psbt_coinjoin import CoinJoinPSBTSigner

    wallet = FakeWallet(_key())
    signer = CoinJoinPSBTSigner(
        wallet, _coinjoin_psbt(wallet.key, foreign=True).serialize(), None
    )
    signer.sign_coinjoin(_policy(), trim=False)
    psbt = PSBT.parse(signer.psbt.serialize())
    assert psbt.inputs[0].partial_sigs
    assert not psbt.inputs[1].partial_sigs


# --- Signer authorize flow ------------------------------------------------


def _signer(mocker, m5):
    from tests.pages import create_ctx
    from krux.extensions.coinjoin.signer import CoinJoinSigner

    ctx = create_ctx(mocker, [None], wallet=FakeWallet(_key()))
    return CoinJoinSigner(ctx)


def _authorize_body(max_rounds=100, max_fee=5, min_self=95):
    return (
        bytes([4])
        + max_rounds.to_bytes(2, "big")
        + max_fee.to_bytes(2, "big")
        + bytes([min_self])
    )


def test_requires_authorization_before_proof_or_sign(mocker, m5stickv):
    signer = _signer(mocker, m5stickv)
    with pytest.raises(ValueError, match="not authorized"):
        signer._dispatch(bytes([2]) + b"\x00\x00")
    with pytest.raises(ValueError, match="not authorized"):
        signer._dispatch(bytes([3]) + b"")
    info = signer._dispatch(bytes([1]))
    assert info[8] == 0  # authorized flag off


def test_authorize_then_info_and_sign(mocker, m5stickv):
    from embit.psbt import PSBT

    signer = _signer(mocker, m5stickv)
    signer.prompt = mocker.MagicMock(return_value=True)  # user confirms

    assert signer._dispatch(_authorize_body(max_rounds=2, max_fee=6)) == b""
    info = signer._dispatch(bytes([1]))
    assert info[8] == 1  # authorized
    assert int.from_bytes(info[6:8], "big") == 2  # max_rounds from host

    signed = signer._dispatch(bytes([3]) + _coinjoin_psbt(signer.ctx.wallet.key).serialize())
    assert signer.rounds_used == 1
    assert any(inp.partial_sigs for inp in PSBT.parse(signed).inputs)


def test_authorization_declined(mocker, m5stickv):
    signer = _signer(mocker, m5stickv)
    signer.prompt = mocker.MagicMock(return_value=False)  # user declines
    with pytest.raises(ValueError, match="declined"):
        signer._dispatch(_authorize_body())
    assert not signer.authorized


def test_round_budget_enforced(mocker, m5stickv):
    signer = _signer(mocker, m5stickv)
    signer.prompt = mocker.MagicMock(return_value=True)
    signer._dispatch(_authorize_body(max_rounds=1, max_fee=6))
    signer._dispatch(bytes([3]) + _coinjoin_psbt(signer.ctx.wallet.key).serialize())
    with pytest.raises(ValueError, match="round budget exhausted"):
        signer._dispatch(bytes([3]) + _coinjoin_psbt(signer.ctx.wallet.key).serialize())


# --- Link framing ---------------------------------------------------------


def _link_reading(stream):
    from krux.extensions.coinjoin.link import Link

    link = Link()
    buf = bytearray(stream)

    def fake_read_exact(num_bytes, _timeout):
        if not buf:
            return None
        out = bytes(buf[:num_bytes])
        del buf[:num_bytes]
        return out

    link._read_exact = fake_read_exact
    return link


def test_link_resyncs_past_noise(m5stickv):
    from krux.extensions.coinjoin.link import MAGIC

    payload = b"hello world"
    stream = b"[LoBo]\r\n\x00" + MAGIC + len(payload).to_bytes(4, "big") + payload
    assert _link_reading(stream).read_frame(100) == payload


def test_link_idle_returns_none(m5stickv):
    assert _link_reading(b"").read_frame(100) is None
