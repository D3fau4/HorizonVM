#!/usr/bin/env bash
# Boot HorizonVM: CCPLEX core 0 starts at EL3 in exosphere, which hands off to Mesosphere (no fusee/BPMP).
# usage: run.sh [--soc erista|mariko] [--gdb] [-- extra qemu args]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HVM="${HORIZONVM_HOME:-$HOME/.horizonvm}"
OUT=nintendo_nx_arm64_armv8a/debug
AMS="$ROOT/third_party/Atmosphere"
SOC=erista
GDB=()

while [ $# -gt 0 ]; do
    case "$1" in
        --soc) SOC="$2"; shift 2 ;;
        --gdb) GDB=(-s -S); shift ;;
        --) shift; break ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$SOC" in
    erista) MACHINE=tegrax1 ;;
    mariko) MACHINE=tegrax1plus ;;
    *) echo "unknown soc: $SOC" >&2; exit 2 ;;
esac

ID="$HVM/identity/$SOC"
if [ ! -f "$ID/fuses.bin" ] || ! ls "$ID"/aeskeyslot*.bin >/dev/null 2>&1; then
    echo "missing identity for $SOC; run:" >&2
    echo "  tools/mkfuses.py --soc $SOC && tools/hvm_keys.py --soc $SOC --prod-keys <prod.keys>" >&2
    exit 1
fi

SECRETS=(-object "secret,id=tegra.fuse.cache,file=$ID/fuses.bin")
for f in "$ID"/aeskeyslot*.bin; do
    n="${f##*aeskeyslot}"; n="${n%.bin}"
    SECRETS+=(-object "secret,id=se.aeskeyslot$n,file=$f")
done

EXTRA=()
if [ "$SOC" = mariko ]; then
    # exosphere copies the Mariko fatal program from 0x80020000 into TZRAM (secmon_boot_setup.cpp LoadMarikoProgram).
    EXTRA+=(-device "loader,addr=0x80020000,force-raw=on,file=$AMS/exosphere/mariko_fatal/out/$OUT/mariko_fatal.bin")
fi

umask 077
mkdir -p "$HVM/logs"

# Replaces fusee: 0x400000F8 is SecureMonitorParameters.bootloader_state (4 = BootloaderState_Done),
# 0xA9800000 is where exosphere expects the plaintext package2 (secmon_memory_layout.hpp).
exec "$ROOT/build/qemu/qemu-system-aarch64" \
    -machine "$MACHINE" -m 8G -nographic \
    -global driver=tegra.evp,property=cpu-reset-vector,value=0x40030000 \
    -global driver=tegra.flow,property=cop-halted,value=on \
    -device "loader,addr=0x40030000,force-raw=on,file=$AMS/exosphere/out/$OUT/exosphere.bin" \
    -device "loader,addr=0xA9800000,force-raw=on,file=$ROOT/build/package2.bin" \
    -device loader,addr=0x400000F8,data-len=4,data=4 \
    "${SECRETS[@]}" "${EXTRA[@]}" \
    -d int,guest_errors -D "$HVM/logs/qemu-$SOC.log" \
    "${GDB[@]}" "$@"
