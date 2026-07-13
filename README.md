# Krux CoinJoin / Batch-Signing USB extension

Pre-approved **remote signing over USB** for [Krux](https://github.com/selfcustody/krux):
SLIP-19 ownership proofs and policy-checked PSBT signing, for WabiSabi coinjoin
rounds and for plain batched (multi-wallet) transactions. Pairs with
[Wasabi Wallet `feature/krux-coinjoin`](https://github.com/kravens/WalletWasabi/tree/feature/krux-coinjoin)
and the [kruxd](https://github.com/kravens/coinjoin.nl/tree/main/kruxd) bridge.

Shipped as a **self-contained extension** — it adds one Sign-menu entry and
edits no core Krux module, so it applies cleanly on top of any recent Krux
version (and leaves the "coinjoin" vocabulary out of the official tree).

## Why an extension

The official Krux repo keeps coinjoin terminology out of the codebase. This
add-on keeps all of it in `krux/extensions/coinjoin/`:

- `slip19.py` — SLIP-19/21 proofs, self-contained (no methods added to `Key`)
- `psbt_coinjoin.py` — `CoinJoinPSBTSigner`, a subclass of the stock
  `PSBTSigner` (skips the single-wallet homogeneity check; validates and signs
  only our own inputs; effective fee rate = leak / own (input+output) vbytes)
- `signer.py` — the `CoinJoin USB` page and the USB command protocol
- `link.py` — framed transport (UART on device, TCP on the simulator)

The only core touch-point is a generic **extension registry + one Sign-menu
line**, proposed to the official repo separately (`upstream-hooks/`) so future
add-ons (e.g. Silent Payments) can reuse it. Until that lands, `apply.py`
patches that one line as a fallback.

## Install flow

```
git clone --recurse-submodules https://github.com/selfcustody/krux
python krux-coinjoin-extension/apply.py ./krux     # copy + register + hook
cd krux && ./krux build maixpy_wonder_mv           # or any supported device
# flash as usual (ktool)
```

`apply.py` is idempotent: copies the package, installs the registry if absent,
records the extension as installed, and applies the fallback Sign-menu hook
only when the upstream hook isn't present.

## Host-proposed policy (Trezor-style)

There is **no device settings menu** to configure before loading a seed. The
signing policy is proposed by the wallet software and approved physically on
the device, once per session:

```
CMD_AUTHORIZE  max_rounds, max_fee_rate_sat_vb, min_self_transfer_pct
   -> device shows the proposal, user confirms -> session authorized
CMD_PROOF      SLIP-19 ownership proof   (requires authorization)
CMD_SIGN       policy-checked PSBT sign  (requires authorization)
CMD_INFO       fingerprint, rounds used/max, authorized flag
```

Frames are `MAGIC("KXJ1") + u32 length + payload`; the reader resyncs to the
magic so device boot-console noise can't be misread as a frame.

## Tests

`tests/test_coinjoin_extension.py` runs inside a patched Krux checkout (uses
Krux's own conftest fixtures). See `apply.py` output for where it lands; run
with `PYTHONPATH=src pytest tests/test_coinjoin_extension.py`.
