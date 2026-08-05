#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Clone (or use) labwired-core, run secure-boot smoke with ephemeral OEM key,
# write cra-evidence-pack/.
set -euo pipefail
export PATH="${HOME}/.cargo/bin:/usr/local/cargo/bin:${PATH:-}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS="$REPO_ROOT/scripts"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/out/nrf52840-secure-boot-evidence}"
PACK_DIR="${PACK_DIR:-$OUT_DIR/cra-evidence-pack}"
CORE_REF="${LABWIRED_CORE_REF:-$(tr -d '[:space:]' < "$REPO_ROOT/LABWIRED_CORE_REF")}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/lw-cra-XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "==> work=$WORK out=$OUT_DIR"
mkdir -p "$OUT_DIR" "$WORK/gen"

# Resolve labwired-core
if [ -n "${LABWIRED_CORE_DIR:-}" ]; then
  CORE="$(cd "$LABWIRED_CORE_DIR" && pwd)"
  echo "==> using LABWIRED_CORE_DIR=$CORE"
else
  CORE="$WORK/labwired-core"
  echo "==> clone labwired-core @ $CORE_REF"
  git clone --depth 1 https://github.com/w1ne/labwired-core.git "$CORE"
  git -C "$CORE" fetch --depth 1 origin "$CORE_REF"
  git -C "$CORE" checkout "$CORE_REF"
fi

LAB="$CORE/examples/nrf52840-secure-boot-lab"
test -d "$LAB" || { echo "missing $LAB — pin a core that has the secure-boot lab" >&2; exit 2; }

# 1. Firmware
echo "==> build firmware-nrf52840-secure-boot"
(
  cd "$CORE"
  rustup target add thumbv7em-none-eabi 2>/dev/null || true
  cargo build -p firmware-nrf52840-secure-boot --release --target thumbv7em-none-eabi
)
FW="$CORE/target/thumbv7em-none-eabi/release/firmware-nrf52840-secure-boot"
test -f "$FW"

# 2. Ephemeral packages
echo "==> make_packages.py --ephemeral"
python3 "$SCRIPTS/make_packages.py" --ephemeral --out-dir "$WORK/gen"
PUBHEX="$(tr -d ' \n' < "$WORK/gen/oem-verify-pubkey.hex")"
test "${#PUBHEX}" -eq 128

# 3. system.yaml with oem_pubkey_hex + absolute chip path
export LAB WORK CORE PUBHEX
python3 <<'PY'
from pathlib import Path
import os
lab = Path(os.environ["LAB"])
work = Path(os.environ["WORK"])
core = Path(os.environ["CORE"])
pub = os.environ["PUBHEX"]
src = (lab / "system.yaml").read_text()
chip = (core / "configs" / "chips" / "nrf52840.yaml").resolve()
src = src.replace('chip: "../../configs/chips/nrf52840.yaml"', f'chip: "{chip}"')
old = """  - id: "se"
    type: "atecc608a"
    connection: "i2c0"
    config:
      i2c_address: 0x60
"""
new = f"""  - id: "se"
    type: "atecc608a"
    connection: "i2c0"
    config:
      i2c_address: 0x60
      oem_pubkey_hex: "{pub}"
"""
if old not in src:
    # already has oem_pubkey_hex or formatting drift — append under se config
    if "oem_pubkey_hex" not in src:
        src = src.replace(
            "i2c_address: 0x60\n",
            f'i2c_address: 0x60\n      oem_pubkey_hex: "{pub}"\n',
            1,
        )
    (work / "system.yaml").write_text(src)
else:
    (work / "system.yaml").write_text(src.replace(old, new, 1))
print("wrote", work / "system.yaml")
PY

# 4. Assemble smoke
python3 "$SCRIPTS/assemble_smoke.py" \
  --packages "$WORK/gen/packages.yaml" \
  --digests "$WORK/gen/digests.json" \
  --system "$WORK/system.yaml" \
  --firmware "$FW" \
  --out "$WORK/secure-boot-smoke.yaml"

# 5. labwired-cli test
echo "==> labwired-cli test"
(
  cd "$CORE"
  cargo run -q -p labwired-cli -- test \
    --script "$WORK/secure-boot-smoke.yaml" \
    --output-dir "$OUT_DIR" \
    --run-manifest \
    --junit "$OUT_DIR/junit.xml"
)

# 6. Pack
echo "==> build_evidence_pack.py"
set +e
python3 "$SCRIPTS/build_evidence_pack.py" \
  --out-dir "$OUT_DIR" \
  --pack-dir "$PACK_DIR" \
  --claims-map "$SCRIPTS/claims-map.json" \
  --pubkey-hex "$WORK/gen/oem-verify-pubkey.hex"
PACK_RC=$?
set -e

if find "$PACK_DIR" -name "*.pem" 2>/dev/null | grep -q .; then
  echo "error: private key leaked into evidence pack" >&2
  exit 3
fi

echo "==> pack exit=$PACK_RC dir=$PACK_DIR"
ls -la "$PACK_DIR"
exit "$PACK_RC"
