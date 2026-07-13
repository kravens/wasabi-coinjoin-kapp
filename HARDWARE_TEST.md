# Hardware test recipe — CoinJoin USB kapp

End-to-end on a WonderMV (or any supported Krux), using the hardened kapps
firmware ([kravens/krux `kapps-develop`](https://github.com/kravens/krux/tree/kapps-develop),
based on PR #485). The device only runs `.mpy` apps whose signature verifies
against one of the firmware's trusted `KAPP_SIGNER_PUBKEYS` (a dedicated set of
kapp keys, separate from the firmware signer key), so a test run builds
firmware that trusts a throwaway signing key.

## 1. Signing key (throwaway, for testing only)

```
openssl ecparam -name secp256k1 -genkey -noout -out privkey.pem
# compressed pubkey hex for KAPP_SIGNER_PUBKEYS:
openssl ec -in privkey.pem -pubout -conv_form compressed -outform DER 2>/dev/null | tail -c 33 | xxd -p -c 66
```

The real release is signed by the kapps maintainer and distributed via
[selfcustody/kapps](https://github.com/selfcustody/kapps) with a PGP signature
+ SHA256. Never commit `privkey.pem`.

## 2. Firmware trusting the test key

Edit `src/krux/metadata.py` in the `kapps-develop` checkout:

```python
KAPP_SIGNER_PUBKEYS = (
    "<compressed pubkey hex from step 1>",
)
```

Build + flash:

```
./krux build maixpy_wonder_mv
python firmware/Kboot/build/ktool.py -B dan -p COM8 -b 2000000 build/kboot.kfpkg
```

## 3. Compile + sign the kapp

```
./build_kapp.sh <krux checkout> privkey.pem
# -> dist/coinjoin_usb.mpy, coinjoin_usb.mpy.sig, coinjoin_usb.sha256
```

Copy `coinjoin_usb.mpy` and `coinjoin_usb.mpy.sig` to the device's SD card.

## 4. Run on device

1. Settings: enable **Allow Krux Apps** (`allow_kapp`).
2. `Tools > Krux Apps > Load from SD card` — device verifies the signature,
   shows the SHA256, stores the app in flash. (On the hardened firmware the
   signature is re-verified on every subsequent execution too.)
3. Open the app; it walks you through loading your wallet (seed / SeedQR).
   The screen then shows the fingerprint and "Waiting for Wasabi Wallet".

## 5. Drive from Wasabi

```
python coinjoin.nl/kruxd/kruxd.py COM8       # bridge holds the port
```

Start coinjoin on the Krux wallet in Wasabi (`feature/krux-coinjoin`). Wasabi
proposes the policy over `/authorize`; the device shows **Authorize CoinJoin?**
with max rounds / max fee rate / min self-transfer. Approve on the device.
Rounds then sign unattended; the on-device counter ticks per round. When the
round budget is exhausted the session ends and Wasabi must re-propose (new
physical approval).

## Notes

- On the hardened firmware every kapp exit restarts the device (deliberate:
  no tainted session state survives a kapp).
- kruxd and the kapp share the `KXJ1` frame magic; a version mismatch shows as
  framing errors.
- The device account script type (segwit `m/84'/1'/0'` vs taproot
  `m/86'/1'/0'`) must match the imported Wasabi wallet, else proofs are
  rejected `derivation outside wallet account`.
