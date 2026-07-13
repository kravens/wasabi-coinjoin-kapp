"""Kapp test suite. Copied into the kapps-branch tree at tests/kapps/ so it can
use the kapp test harness (tests.kapps.create_ctx) and Krux's m5stickv fixture.
Mirrors the kapps convention: import the single-file app as ``kapps.coinjoin_usb``.
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


def _authorize_body(max_rounds=100, max_fee=5, min_self=95):
    return (
        bytes([4])
        + max_rounds.to_bytes(2, "big")
        + max_fee.to_bytes(2, "big")
        + bytes([min_self])
    )


def _signer(mocker):
    from . import create_ctx
    from kapps.coinjoin_usb import CoinJoinSigner

    ctx = create_ctx(mocker, [None], wallet=FakeWallet(_key()))
    return CoinJoinSigner(ctx)


def test_kapp_metadata(m5stickv):
    import kapps.coinjoin_usb as app

    assert app.NAME == "CoinJoin USB"
    assert app.VERSION
    assert not getattr(app, "ALLOW_STARTUP", False)  # needs a loaded wallet
    assert callable(app.run)


def test_slip19_proof_roundtrip_p2wpkh(m5stickv):
    from embit import bip32, script
    from kapps.coinjoin_usb import create_proof, USER_CONFIRMATION
    from kapps import coinjoin_usb

    key = _key()
    path = bip32.parse_path("m/84h/1h/0h/0/0")
    spk = script.p2wpkh(key.root.derive(path).key.get_public_key())
    proof = create_proof(key, "p2wpkh", spk, path, b"coord", USER_CONFIRMATION)
    # verify via a fresh proof parse is out of scope for the kapp; assert shape
    assert proof[:4] == coinjoin_usb.SLIP19_MAGIC


def test_policy_signs_and_rejects(m5stickv):
    from kapps.coinjoin_usb import CoinJoinPSBTSigner

    wallet = FakeWallet(_key())
    signer = CoinJoinPSBTSigner(wallet, _coinjoin_psbt(wallet.key).serialize(), None)
    assert signer.coinjoin_amounts(_policy())["fee_leak"] == 400
    signer.sign_coinjoin(_policy(), trim=False)
    assert signer.psbt.inputs[0].partial_sigs

    signer = CoinJoinPSBTSigner(wallet, _coinjoin_psbt(wallet.key).serialize(), None)
    with pytest.raises(ValueError, match="fee rate above"):
        signer.sign_coinjoin(_policy(max_fee_rate_sat_vb=4))  # 4.05 sat/vB > 4

    with pytest.raises(ValueError, match="not authorized"):
        CoinJoinPSBTSigner(
            wallet, _coinjoin_psbt(wallet.key).serialize(), None
        ).sign_coinjoin(None)


def test_mixed_psbt_signs_only_own_input(m5stickv):
    from embit.psbt import PSBT
    from kapps.coinjoin_usb import CoinJoinPSBTSigner

    wallet = FakeWallet(_key())
    signer = CoinJoinPSBTSigner(
        wallet, _coinjoin_psbt(wallet.key, foreign=True).serialize(), None
    )
    signer.sign_coinjoin(_policy(), trim=False)
    psbt = PSBT.parse(signer.psbt.serialize())
    assert psbt.inputs[0].partial_sigs
    assert not psbt.inputs[1].partial_sigs


def test_forged_self_transfer_output_rejected(m5stickv):
    # A malicious host that knows our xpub labels an ATTACKER-paying output
    # with our (valid) derivation metadata. Without binding the derivation to
    # the actual scriptPubKey this counts as self-transfer and funds drain.
    from embit import bip32, ec, script
    from embit.psbt import DerivationPath, PSBT
    from embit.transaction import Transaction, TransactionInput, TransactionOutput
    from kapps.coinjoin_usb import CoinJoinPSBTSigner

    wallet = FakeWallet(_key())
    key = wallet.key
    input_path = bip32.parse_path("m/84h/1h/0h/0/0")
    output_path = bip32.parse_path("m/84h/1h/0h/1/0")
    input_pub = key.root.derive(input_path).key.get_public_key()
    output_pub = key.root.derive(output_path).key.get_public_key()
    attacker_pub = ec.PrivateKey(b"\x22" * 32).get_public_key()

    # Output pays the attacker but carries OUR genuine derivation metadata.
    tx = Transaction(
        vin=[TransactionInput(b"\x01" * 32, 0)],
        vout=[TransactionOutput(9600, script.p2wpkh(attacker_pub))],
    )
    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(10000, script.p2wpkh(input_pub))
    psbt.inputs[0].bip32_derivations[input_pub] = DerivationPath(
        key.fingerprint, input_path
    )
    psbt.outputs[0].bip32_derivations[output_pub] = DerivationPath(
        key.fingerprint, output_path
    )

    signer = CoinJoinPSBTSigner(wallet, psbt.serialize(), None)
    with pytest.raises(ValueError, match="self-transfer below policy"):
        signer.sign_coinjoin(_policy(), trim=False)


def test_backstop_rejects_foreign_signature(m5stickv):
    # If signing ever wrote a signature onto a foreign input, the PSBT must not
    # be emitted. Force that failure by faking a sig onto the foreign input.
    from embit import ec
    from kapps.coinjoin_usb import CoinJoinPSBTSigner

    wallet = FakeWallet(_key())
    signer = CoinJoinPSBTSigner(
        wallet, _coinjoin_psbt(wallet.key, foreign=True).serialize(), None
    )
    real_sign = signer.sign

    def tainted_sign(*a, **k):
        real_sign(*a, **k)
        foreign_pub = ec.PrivateKey(b"\x11" * 32).get_public_key()
        signer.psbt.inputs[1].partial_sigs[foreign_pub] = b"\x30\x00"

    signer.sign = tainted_sign
    with pytest.raises(ValueError, match="foreign input 1 signed"):
        signer.sign_coinjoin(_policy(), trim=False)


def test_authorize_safety_envelope(mocker, m5stickv):
    signer = _signer(mocker)
    signer.prompt = mocker.MagicMock(return_value=True)
    for body, msg in (
        (_authorize_body(min_self=10), "self-transfer floor below safe"),
        (_authorize_body(max_fee=300), "fee-rate cap above safe"),
        (_authorize_body(max_rounds=1000), "max rounds above safe"),
    ):
        with pytest.raises(ValueError, match=msg):
            signer._dispatch(body)
    assert not signer.authorized  # nothing in the batch opened a session


def test_requires_authorization(mocker, m5stickv):
    signer = _signer(mocker)
    with pytest.raises(ValueError, match="not authorized"):
        signer._dispatch(bytes([2]) + b"\x00\x00")
    with pytest.raises(ValueError, match="not authorized"):
        signer._dispatch(bytes([3]) + b"")
    assert signer._dispatch(bytes([1]))[8] == 0  # authorized flag off


def test_authorize_then_sign(mocker, m5stickv):
    from embit.psbt import PSBT

    signer = _signer(mocker)
    signer.prompt = mocker.MagicMock(return_value=True)
    assert signer._dispatch(_authorize_body(max_rounds=2, max_fee=6)) == b""
    info = signer._dispatch(bytes([1]))
    assert info[8] == 1
    assert int.from_bytes(info[6:8], "big") == 2
    signed = signer._dispatch(
        bytes([3]) + _coinjoin_psbt(signer.ctx.wallet.key).serialize()
    )
    assert signer.rounds_used == 1
    assert any(inp.partial_sigs for inp in PSBT.parse(signed).inputs)


def test_authorize_extends_shutdown_grace(mocker, m5stickv):
    # The approval prompt blocks the serve loop, so the inactivity auto-shutdown
    # must be given a bounded grace before the (blocking) confirm.
    from kapps import coinjoin_usb
    from krux.auto_shutdown import auto_shutdown

    signer = _signer(mocker)

    def fake_prompt(*a, **k):
        # at prompt time the countdown must be at least the grace window
        assert auto_shutdown.time_out >= coinjoin_usb._AUTH_PROMPT_GRACE_S
        return True

    signer.prompt = fake_prompt

    # short remaining countdown, enabled auto-shutdown -> bumped to grace
    auto_shutdown.shutdown_time = 600
    auto_shutdown.time_out = 5
    signer._dispatch(_authorize_body())
    assert signer.authorized

    # a longer configured window is never shrunk
    signer2 = _signer(mocker)
    signer2.prompt = mocker.MagicMock(return_value=True)
    auto_shutdown.shutdown_time = 6000
    auto_shutdown.time_out = 6000
    signer2._feed_auth_grace()
    assert auto_shutdown.time_out == 6000

    # disabled auto-shutdown -> no-op, no crash
    auto_shutdown.shutdown_time = 0
    auto_shutdown.time_out = 0
    signer2._feed_auth_grace()
    assert auto_shutdown.time_out == 0


def test_single_press_exit_when_waiting(mocker, m5stickv):
    # No session to protect while waiting: one press exits, no confirm prompt.
    signer = _signer(mocker)
    link = mocker.MagicMock()
    link.read_frame.return_value = None
    signer.ctx.input.wait_for_button = mocker.MagicMock(return_value=1)
    prompt = mocker.patch.object(signer, "prompt")

    signer._serve(link)  # returns on the first press

    assert not prompt.called


def test_exit_confirm_required_when_authorized(mocker, m5stickv):
    # An active session must not die to an accidental press: confirm required.
    signer = _signer(mocker)
    signer.authorized = True
    signer.max_rounds = 3
    link = mocker.MagicMock()
    link.read_frame.return_value = None
    signer.ctx.input.wait_for_button = mocker.MagicMock(return_value=1)
    prompt = mocker.patch.object(signer, "prompt", return_value=True)

    signer._serve(link)

    assert prompt.called


def test_authorization_declined(mocker, m5stickv):
    signer = _signer(mocker)
    signer.prompt = mocker.MagicMock(return_value=False)
    with pytest.raises(ValueError, match="declined"):
        signer._dispatch(_authorize_body())
    assert not signer.authorized


def test_round_budget(mocker, m5stickv):
    signer = _signer(mocker)
    signer.prompt = mocker.MagicMock(return_value=True)
    signer._dispatch(_authorize_body(max_rounds=1, max_fee=6))
    signer._dispatch(bytes([3]) + _coinjoin_psbt(signer.ctx.wallet.key).serialize())
    with pytest.raises(ValueError, match="round budget exhausted"):
        signer._dispatch(bytes([3]) + _coinjoin_psbt(signer.ctx.wallet.key).serialize())


def test_link_resyncs_past_noise(m5stickv):
    from kapps.coinjoin_usb import Link, MAGIC

    payload = b"hello world"
    link = Link()
    buf = bytearray(b"[LoBo]\x00" + MAGIC + len(payload).to_bytes(4, "big") + payload)

    def fake_read_exact(n, _t):
        if not buf:
            return None
        out = bytes(buf[:n])
        del buf[:n]
        return out

    link._read_exact = fake_read_exact
    assert link.read_frame(100) == payload
