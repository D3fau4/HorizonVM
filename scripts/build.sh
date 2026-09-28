#!/usr/bin/env bash
# Build the unmodified Atmosphère NX debug components used by HorizonVM and one package2 per INI1 profile.
# HVM_FW=<firmware dump> (Processed/ + sysupdate-*/) also enables the ams and stock profiles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AMS="$ROOT/third_party/Atmosphere"
OUT=nintendo_nx_arm64_armv8a/debug
export DEVKITPRO="${DEVKITPRO:-/opt/devkitpro}"
MODULES=(sm spl pm loader ncm boot)

make -C "$AMS/mesosphere" nx_debug -j"$(nproc)"
make -C "$AMS/exosphere" nx_debug -j"$(nproc)"
make -C "$AMS/libraries/libstratosphere" nx_debug -j"$(nproc)"
for m in "${MODULES[@]}"; do
    make -C "$AMS/stratosphere/$m" nx_debug ATMOSPHERE_CHECKED_LIBSTRATOSPHERE=1 -j"$(nproc)"
done

kip() { echo "--kip=$AMS/stratosphere/$1/out/$OUT/$1.kip"; }
pkg2() {
    local name="$1"; shift
    python3 "$ROOT/tools/mkpkg2.py" "$AMS/mesosphere/out/$OUT/mesosphere.bin" -o "$ROOT/build/package2-$name.bin" "$@"
}

mkdir -p "$ROOT/build"
pkg2 empty
pkg2 core "$(kip sm)" "$(kip spl)"
if [ -n "${HVM_FW:-}" ]; then
    FWK="$HVM_FW/Processed/BootImagePackage/romfs/nx/package2.storage"
    # fusee's order (build_package3.py) with Nintendo's FS appended (fusee_stratosphere.cpp).
    pkg2 ams "$(kip loader)" "$(kip ncm)" "$(kip pm)" "$(kip sm)" "$(kip boot)" "$(kip spl)" --kip="$FWK/kips/FS.kip1"
    pkg2 stock --ini1="$FWK/INI1.bin"
fi
