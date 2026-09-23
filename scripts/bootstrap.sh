#!/usr/bin/env bash
# Fetch submodules, apply our tegra_qemu patches and build qemu-system-aarch64 into build/qemu.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TQ="$ROOT/third_party/tegra_qemu"
QEMU_BUILD="$ROOT/build/qemu"

git -C "$ROOT" submodule update --init --recommend-shallow

for p in "$ROOT"/patches/tegra_qemu/*.patch; do
    if git -C "$TQ" apply --reverse --check "$p" 2>/dev/null; then
        echo "already applied: $(basename "$p")"
    else
        git -C "$TQ" apply "$p"
        echo "applied: $(basename "$p")"
    fi
done

mkdir -p "$QEMU_BUILD"
cd "$QEMU_BUILD"
if [ ! -f build.ninja ]; then
    # aarch64 only: on tegra_iommu, hw/sd/sdhci.c calls tegra_mc_* and would break other targets.
    "$TQ/configure" --target-list=aarch64-softmmu --enable-gcrypt --enable-plugins \
        --disable-werror ${QEMU_CONFIGURE_EXTRA:-}
fi
ninja -j"$(nproc)" qemu-system-aarch64

# HorizonVM TCG plugin (SMC/MMIO tracing with secret redaction).
mkdir -p "$ROOT/build/plugins"
cc -O2 -Wall -shared -fPIC -I"$TQ/include/qemu" $(pkg-config --cflags glib-2.0) \
    "$ROOT/plugins/hvmtrace.c" -o "$ROOT/build/plugins/libhvmtrace.so"
