#!/usr/bin/env bash
# Build and sign the CoinJoin USB kapp for distribution.
#
# Produces, from kapps/coinjoin_usb.py:
#   dist/coinjoin_usb.mpy       compiled MicroPython bytecode (K210 / MaixPy)
#   dist/coinjoin_usb.mpy.sig   ECDSA-secp256k1 signature (70-byte DER)
#   dist/coinjoin_usb.sha256    SHA256 of the .mpy
#
# The device verifies the .sig against its configured SIGNER_PUBKEY, so the
# private key here must correspond to the pubkey the user trusts on-device.
# For the kapps repo (selfcustody/kapps) release, also attach a PGP signature
# of dist/coinjoin_usb.sha256 (see README).
#
# Usage: build_kapp.sh <path-to-krux-checkout> <signer_privkey.pem>
#   <krux-checkout>  a Krux tree with mpy-cross available (the kapps branch),
#                    used both for mpy-cross and its `./krux sign` helper.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KRUX="${1:?path to krux checkout}"
PRIVKEY="${2:?signer private key pem}"
SRC="$HERE/kapps/coinjoin_usb.py"
OUT="$HERE/dist"
mkdir -p "$OUT"

# 1) find an mpy-cross matching the device MicroPython (built with the firmware)
MPY_CROSS="$(find "$KRUX" -name 'mpy-cross' -type f -perm -u+x 2>/dev/null | head -1 || true)"
if [ -z "$MPY_CROSS" ]; then
  echo "mpy-cross not found under $KRUX; build the firmware once so it is compiled." >&2
  exit 1
fi

# 2) compile to .mpy (target the device arch; -mno-unicode matches MaixPy builds)
"$MPY_CROSS" -o "$OUT/coinjoin_usb.mpy" "$SRC"
echo "compiled -> $OUT/coinjoin_usb.mpy"

# 3) hash
sha256sum "$OUT/coinjoin_usb.mpy" | awk '{print $1}' > "$OUT/coinjoin_usb.sha256"
echo "sha256 -> $(cat "$OUT/coinjoin_usb.sha256")"

# 4) sign (reuses the krux repo helper: strict 70-byte secp256k1 DER)
( cd "$KRUX" && ./krux sign "$OUT/coinjoin_usb.mpy" "$PRIVKEY" )
echo "signed -> $OUT/coinjoin_usb.mpy.sig"

echo
echo "Copy coinjoin_usb.mpy + coinjoin_usb.mpy.sig to the device (SD or flash)."
echo "For the kapps repo release, PGP-sign coinjoin_usb.sha256 and publish both."
