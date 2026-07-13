# Krux CoinJoin / Batch-Signing USB — a Krux App (kapp)

Pre-approved **remote signing over USB** for [Krux](https://github.com/selfcustody/krux):
SLIP-19 ownership proofs and policy-checked PSBT signing, for WabiSabi coinjoin
rounds and plain batched (multi-wallet) transactions. Pairs with
[Wasabi Wallet `feature/krux-coinjoin`](https://github.com/kravens/WalletWasabi/tree/feature/krux-coinjoin)
and the [kruxd](https://github.com/kravens/coinjoin.nl/tree/main/kruxd) bridge.

Built as a **signed Krux App (kapp)** on the apps framework from
[selfcustody/krux#485](https://github.com/selfcustody/krux/pull/485)
(`tadeubas/krux` branch `kapps`). Distributed via
[selfcustody/kapps](https://github.com/selfcustody/kapps) with a PGP signature
and SHA256 of the released `.mpy`.

## The kapp

`kapps/coinjoin_usb.py` — one self-contained file per the #485 contract:

- module attributes `VERSION`, `NAME`; entry point `run(ctx)`; `os.chdir("/")`
  guard so no sibling flash module is imported
- bundles the framed USB link, SLIP-19 proofs, and `CoinJoinPSBTSigner`
  (a subclass of the stock `PSBTSigner` — skips the single-wallet homogeneity
  check, validates/signs only our own inputs, effective fee rate =
  leak / own (input+output) vbytes)
- imports only from frozen Krux modules (`krux.psbt`, `krux.pages`,
  `krux.sats_vb`) and `embit`

No core Krux files are modified — the app plugs into the #485 apps loader
(`Tools > Krux Apps`, gated by the `allow_kapp` setting).

## Host-proposed policy (Trezor-style)

No device settings menu to configure before loading a seed. The wallet software
proposes the policy and the user approves it physically on the device, once per
session:

```
CMD_AUTHORIZE  max_rounds, max_fee_rate_sat_vb, min_self_transfer_pct
   -> device shows the proposal, user confirms -> session authorized
CMD_PROOF      SLIP-19 ownership proof   (requires authorization)
CMD_SIGN       policy-checked PSBT sign  (requires authorization)
CMD_INFO       fingerprint, rounds used/max, authorized flag
```

Frames are `MAGIC("KXJ1") + u32 length + payload`; the reader resyncs to the
magic so device boot-console noise can't be misread as a frame.

## Build, sign, install

```
./build_kapp.sh /path/to/krux-kapps-checkout  signer_privkey.pem
# -> dist/coinjoin_usb.mpy, coinjoin_usb.mpy.sig, coinjoin_usb.sha256
```

Copy the `.mpy` + `.mpy.sig` to the device (SD or flash). The device verifies
the signature against its trusted `SIGNER_PUBKEY`. On the device: enable
`allow_kapp`, load a wallet, then `Tools > Krux Apps > CoinJoin USB`.

## Tests

`tests/test_coinjoin_usb.py` runs inside the kapps-branch tree (copied to
`tests/kapps/`), using its `create_ctx` helper and Krux's `m5stickv` fixture:

```
cp tests/test_coinjoin_usb.py <krux-kapps>/tests/kapps/
cp kapps/coinjoin_usb.py       <krux-kapps>/kapps/
cd <krux-kapps> && PYTHONPATH=src pytest tests/kapps/test_coinjoin_usb.py
```

## Pre-#485 build-time extension (superseded)

`src/krux/extensions/`, `apply.py`, and `upstream-hooks/` are the earlier
build-time-frozen extension approach, kept for history. The kapp above is the
current path now that #485 provides the apps framework.
