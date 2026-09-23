#!/usr/bin/env bash
# Boot HorizonVM: CCPLEX core 0 starts at EL3 in exosphere, which hands off to Mesosphere (no fusee/BPMP).
# usage: run.sh [--soc erista|mariko] [--ini empty|core|ams|stock] [--nand image|dir|none] [--persist] [--user-exc]
#               [--gdb] [--trace] [-- extra qemu args]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HVM="${HORIZONVM_HOME:-$HOME/.horizonvm}"
OUT=nintendo_nx_arm64_armv8a/debug
AMS="$ROOT/third_party/Atmosphere"
SOC=erista
INI=
NAND=
SNAPSHOT=on
EXO0_ARGS=()
GDB=()
TRACE=()

while [ $# -gt 0 ]; do
    case "$1" in
        --soc) SOC="$2"; shift 2 ;;
        --ini) INI="$2"; shift 2 ;;
        --user-exc) EXO0_ARGS+=(--user-exc); shift ;;
        --nand) NAND="$2"; shift 2 ;;
        --persist) SNAPSHOT=off; shift ;;
        --gdb) GDB=(-s -S); shift ;;
        --trace) TRACE=(-plugin "$ROOT/build/plugins/libhvmtrace.so,out=$HVM/logs/hvmtrace-SOC.log"); shift ;;
        --) shift; break ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$SOC" in
    erista) MACHINE=tegrax1 ;;
    mariko) MACHINE=tegrax1plus ;;
    *) echo "unknown soc: $SOC" >&2; exit 2 ;;
esac

if [ -z "$INI" ]; then
    INI=empty
    [ -f "$ROOT/build/package2-ams.bin" ] && INI=ams
fi
PKG2="$ROOT/build/package2-$INI.bin"
[ -f "$PKG2" ] || { echo "missing $PKG2 (scripts/build.sh; ams/stock need HVM_FW)" >&2; exit 1; }

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
IMG="$HVM/nand/$SOC/emmc.img"
[ -z "$NAND" ] && { [ -f "$IMG" ] && NAND=image || NAND=none; }
case "$NAND" in
    # SDMMC4 eMMC (tegrax1.c: sd index 3). snapshot=on keeps the image pristine; its overlay goes to $TMPDIR.
    image) [ -f "$IMG" ] || { echo "missing $IMG (tools/mknand.py --soc $SOC --fw <FW> --image)" >&2; exit 1; }
           EXTRA+=(-drive "if=sd,index=3,format=raw,file=$IMG,snapshot=$SNAPSHOT") ;;
    # Live from the folder tree: hvm_nbd composes and encrypts the eMMC on the fly, exits when QEMU disconnects.
    dir) SOCK="$HVM/run/nbd-$SOC.sock"
         rm -f "$SOCK"
         python3 "$ROOT/tools/hvm_nbd.py" serve --soc "$SOC" --socket "$SOCK" &
         for _ in $(seq 1 240); do [ -S "$SOCK" ] && break; sleep 0.25; done
         [ -S "$SOCK" ] || { echo "hvm_nbd did not start" >&2; exit 1; }
         EXTRA+=(-drive "if=sd,index=3,format=raw,file.driver=nbd,file.server.type=unix,file.server.path=$SOCK") ;;
    none) ;;
    *) echo "unknown nand backend: $NAND" >&2; exit 2 ;;
esac
if [ "$SOC" = mariko ]; then
    # exosphere copies the Mariko fatal program from 0x80020000 into TZRAM (secmon_boot_setup.cpp LoadMarikoProgram).
    EXTRA+=(-device "loader,addr=0x80020000,force-raw=on,file=$AMS/exosphere/mariko_fatal/out/$OUT/mariko_fatal.bin")
fi

umask 077
mkdir -p "$HVM/logs" "$HVM/run" "$HVM/tmp"
export TMPDIR="$HVM/tmp"
TRACE=("${TRACE[@]/SOC/$SOC}")
python3 "$ROOT/tools/mkexo0.py" -o "$HVM/run/exo0-$SOC.bin" "${EXO0_ARGS[@]}"

# Replaces fusee: 0x400000F8 is SecureMonitorParameters.bootloader_state (4 = BootloaderState_Done),
# 0xA9800000 is where exosphere expects the plaintext package2 (secmon_memory_layout.hpp),
# 0x8000F000 is the EXO0 storage configuration (secmon_monitor_context.hpp).
exec "$ROOT/build/qemu/qemu-system-aarch64" \
    -machine "$MACHINE" -m 8G -display none \
    -chardev "stdio,id=uart,mux=on,logfile=$HVM/logs/uart-$SOC.log" -serial chardev:uart -mon chardev=uart \
    -global driver=tegra.evp,property=cpu-reset-vector,value=0x40030000 \
    -global driver=tegra.flow,property=cop-halted,value=on \
    -device "loader,addr=0x40030000,force-raw=on,file=$AMS/exosphere/out/$OUT/exosphere.bin" \
    -device "loader,addr=0xA9800000,force-raw=on,file=$PKG2" \
    -device "loader,addr=0x8000F000,force-raw=on,file=$HVM/run/exo0-$SOC.bin" \
    -device loader,addr=0x400000F8,data-len=4,data=4 \
    "${SECRETS[@]}" "${EXTRA[@]}" \
    -d int,guest_errors -D "$HVM/logs/qemu-$SOC.log" \
    "${TRACE[@]}" "${GDB[@]}" "$@"
