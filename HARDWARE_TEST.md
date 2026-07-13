# Hardware test recipe — CoinJoin USB kapp

End-to-end on a WonderMV (or any supported Krux), using the PR #485 apps
framework (`tadeubas/krux` branch `kapps`). The device only runs `.mpy` apps
whose signature verifies against the firmware's `SIGNER_PUBKEY`, so a test run
builds firmware that trusts a throwaway signing key.

## 1. Signing key (throwaway, for testing only)

```
cd <krux-kapps checkout>
./krux generate-keypair              # -> privkey.pem, pubkey.pem  (keep private!)
# compressed pubkey for SIGNER_PUBKEY (embit form):
python -c "from embit import ec; pk=ec.PublicKey.parse(bytes.fromhex(open('pub.hex').read().strip())); pk.compressed=True; print(pk.sec().hex())"
```

The real release is signed with your own key and distributed via
[selfcustody/kapps](https://github.com/selfcustody/kapps) with a PGP signature
+ SHA256; users configure trust in that key. Never commit `privkey.pem`.

## 2. Firmware trusting the test key

Edit `src/krux/metadata.py`:

```python
SIGNER_PUBKEY = "<compressed pubkey hex from step 1>"
```

Build + flash:

```
./krux build maixpy_wonder_mv
python firmware/Kboot/build/ktool.py -B dan -p COM8 -b 2000000 build/kboot.kfpkg
```

## 3. Compile + sign the kapp

```
./build_kapp.sh <krux-kapps checkout> <krux-kapps>/privkey.pem
# -> dist/coinjoin_usb.mpy, coinjoin_usb.mpy.sig, coinjoin_usb.sha256
```

Copy `coinjoin_usb.mpy` and `coinjoin_usb.mpy.sig` to the device's SD card (or
the flash apps directory).

## 4. Run on device

1. Settings: enable **Allow Krux Apps** (`allow_kapp`).
2. Load your wallet (seed / SeedQR) — no coinjoin pre-config needed.
3. `Tools > Krux Apps > CoinJoin USB`. The screen shows the fingerprint and
   "Waiting for authorization".

## 5. Drive from Wasabi

```
python coinjoin.nl/kruxd/kruxd.py COM8       # bridge holds the port
```

Start coinjoin on the Krux wallet in Wasabi (`feature/krux-coinjoin`). Wasabi
proposes the policy over `/authorize`; the device shows **Authorize CoinJoin?**
with max rounds / max fee rate / min self-transfer. Approve on the device.
Rounds then sign unattended; the on-device counter ticks per round.

## Notes

- kruxd and the kapp share the `KXJ1` frame magic; a version mismatch shows as
  framing errors.
- The device account script type (segwit `m/84'/1'/0'` vs taproot
  `m/86'/1'/0'`) must match the imported Wasabi wallet, else proofs are
  rejected `derivation outside wallet account`.
