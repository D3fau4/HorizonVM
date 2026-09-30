#!/usr/bin/env bash
# Boot HorizonVM: CCPLEX core 0 starts at EL3 in exosphere, which hands off to Mesosphere (no fusee/BPMP).
# usage: run.sh [--soc erista|mariko] [--ini empty|core|ams|stock] [--nand image|dir|none] [--sd image|dir|none]
#               [--eth ax88772|none] [--persist] [--maintenance] [--display] [--realtime] [--user-exc] [--gdb]
#               [--trace] [-- extra qemu args]
# HVM_OTG_DEVICE="<qemu -device spec>" (debug): plug that USB device into the USB-C port instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HVM="${HORIZONVM_HOME:-$HOME/.horizonvm}"
OUT=nintendo_nx_arm64_armv8a/debug
AMS="$ROOT/third_party/Atmosphere"
SOC=erista
INI=
NAND=
SD=
ETH=
SNAPSHOT=on
BUTTONS=0xC0
REALTIME=
DISPLAY_ARGS=(-display none)
EXO0_ARGS=()
GDB=()
TRACE=()

while [ $# -gt 0 ]; do
    case "$1" in
        --soc) SOC="$2"; shift 2 ;;
        --ini) INI="$2"; shift 2 ;;
        --user-exc) EXO0_ARGS+=(--user-exc); shift ;;
        --nand) NAND="$2"; shift 2 ;;
        --sd) SD="$2"; shift 2 ;;
        --eth) ETH="$2"; shift 2 ;;
        --persist) SNAPSHOT=off; shift ;;
        --maintenance) BUTTONS=0; shift ;;
        --realtime) REALTIME=1; shift ;;
        --display) DISPLAY_ARGS=(-display none -vnc "127.0.0.1:$((${HVM_VNC:-5900} - 5900))")
                   echo "display: VNC on 127.0.0.1:${HVM_VNC:-5900}" >&2; shift ;;
        --gdb) GDB=(-s -S); shift ;;
        --trace) TRACE=(-plugin "$ROOT/build/plugins/libhvmtrace.so,out=$HVM/logs/hvmtrace-SOC.log${HVM_TRACE_ARGS:+,$HVM_TRACE_ARGS}"
                        -trace 'enable=bm92t36_*' -trace 'enable=usb_asix_*'
                        -trace 'enable=usb_xhci_run' -trace 'enable=usb_xhci_stop' -trace 'enable=usb_xhci_reset'
                        -trace 'enable=usb_xhci_port_reset' -trace 'enable=usb_xhci_slot_*' -trace 'enable=usb_port_*'
                        -trace 'enable=usb_desc_device' -trace 'enable=usb_desc_config' -trace 'enable=usb_set_config'
                        -trace 'enable=usb_xhci_unimplemented'); shift ;;
        --) shift; break ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# PMIC state fusee leaves behind (fusee_cpu.cpp: pmic::EnableVddCpu, VDD_CPU at 0.95 V), which pcv reads back.
case "$SOC" in
    erista) MACHINE=tegrax1
            BOOT_REGS="1b.00=b7;1b.01=b7;1b.02=b0;1b.03=c1;3c.3b=09;3c.27=00" ;;   # MAX77621 VOUT/DVC/CTRL1/2, MAX77620 GPIO5, LDO2 off
    mariko) MACHINE=tegrax1plus
            BOOT_REGS="31.06=40;31.26=6e;3c.27=00" ;;                   # MAX77812 EN_CTRL, M4VOUT, MAX77620 LDO2 off
    *) echo "unknown soc: $SOC" >&2; exit 2 ;;
esac

if [ -z "$INI" ]; then
    INI=empty
    [ -f "$ROOT/build/package2-ams.bin" ] && INI=ams
fi
PKG2="$ROOT/build/package2-$INI.bin"
if [ -z "$ETH" ]; then                          # the adapter is plugged in once userland can use it
    case "$INI" in ams|stock) ETH=ax88772 ;; *) ETH=none ;; esac
fi
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
NBD_ARGS=(); [ "$SNAPSHOT" = off ] && NBD_ARGS=(--persist)
# attach <emmc|sd> <sd index> <image|dir|none> <image> : snapshot=on keeps an image pristine (overlay in $TMPDIR);
# dir serves the folder live: hvm_nbd composes the disk on the fly and exits when QEMU disconnects.
attach() {
    case "$3" in
        image) [ -f "$4" ] || { echo "missing $4 (tools/mknand.py / tools/mksd.py --soc $SOC ... --image)" >&2; exit 1; }
               EXTRA+=(-drive "if=sd,index=$2,format=raw,file=$4,snapshot=$SNAPSHOT") ;;
        dir) local sock="$HVM/run/nbd-$1-$SOC.sock"
             rm -f "$sock"
             python3 "$ROOT/tools/hvm_nbd.py" serve --disk "$1" --soc "$SOC" --socket "$sock" "${NBD_ARGS[@]}" &
             for _ in $(seq 1 240); do [ -S "$sock" ] && break; sleep 0.25; done
             [ -S "$sock" ] || { echo "hvm_nbd ($1) did not start" >&2; exit 1; }
             EXTRA+=(-drive "if=sd,index=$2,format=raw,file.driver=nbd,file.server.type=unix,file.server.path=$sock") ;;
        none) ;;
        *) echo "unknown $1 backend: $3" >&2; exit 2 ;;
    esac
}
IMG="$HVM/nand/$SOC/emmc.img"
SDIMG="$HVM/sd/$SOC/sd.img"
[ -z "$NAND" ] && { [ -f "$IMG" ] && NAND=image || NAND=none; }
if [ -z "$SD" ]; then                           # the card follows the eMMC backend once userland needs it
    SD=none
    case "$INI:$NAND" in
        ams:image|stock:image) [ -f "$SDIMG" ] && SD=image ;;
        ams:dir|stock:dir) [ -d "$HVM/sd/$SOC/dir" ] && SD=dir ;;
    esac
fi
attach emmc 3 "$NAND" "$IMG"                    # SDMMC4 (tegrax1.c: sd index 3)
attach sd 0 "$SD" "$SDIMG"                      # SDMMC1
if [ -z "$REALTIME" ] && { [ "$INI" = ams ] || [ "$INI" = stock ]; }; then
    # Guest time follows executed instructions (1 ns each), not the host clock: with boot2's sysmodules up, their
    # real-time periodic work (hid polling the touch panel, vsync, audio) otherwise saturates the emulated core 3
    # and starves lower-priority processes. Costs MTTCG (all vCPUs on one host thread).
    EXTRA+=(-icount shift=0,sleep=off)
fi
# USB Ethernet adapter on the USB-C port through an OTG adapter: the PD controller reports a non-PD device, usb
# turns the XUSB host on and eth drives the AX88772. Its MAC is the adapter's (fixed per SoC, locally administered).
case "$ETH" in
    none) ;;
    ax88772) MAC=02:48:56:4d:00:0$([ "$SOC" = erista ] && echo 1 || echo 2)
             EXTRA+=(-global driver=bm92t36,property=state,value=otg -netdev hubport,id=hvmnet,hubid=0
                     -device "usb-ax88772,bus=usb-bus.2,port=1,netdev=hvmnet,mac=$MAC") ;;
    *) echo "unknown --eth: $ETH" >&2; exit 2 ;;
esac
if [ -n "${HVM_OTG_DEVICE:-}" ]; then
    EXTRA+=(-global driver=bm92t36,property=state,value=otg -device "$HVM_OTG_DEVICE,bus=usb-bus.2,port=1")
fi
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
# 0x8000F000 is the EXO0 storage configuration (secmon_monitor_context.hpp); SPARE_REG0 = CLK_M divisor 2
# (fusee_secure_initialize.cpp InitializeClock, required by pcv).
exec "$ROOT/build/qemu/qemu-system-aarch64" \
    -machine "$MACHINE" -m 8G "${DISPLAY_ARGS[@]}" \
    -chardev "stdio,id=uart,mux=on,logfile=$HVM/logs/uart-$SOC.log" -serial chardev:uart -mon chardev=uart \
    -global driver=tegra.evp,property=cpu-reset-vector,value=0x40030000 \
    -global driver=tegra.flow,property=cop-halted,value=on \
    -global "driver=tegra.gpio,property=reset-value-bank5-port3,value=$BUTTONS" \
    -global driver=tegra.car,property=spare-reg0,value=4 \
    -global "driver=max77xpmic,property=boot-regs,value=$BOOT_REGS" \
    -device "loader,addr=0x40030000,force-raw=on,file=$AMS/exosphere/out/$OUT/exosphere.bin" \
    -device "loader,addr=0xA9800000,force-raw=on,file=$PKG2" \
    -device "loader,addr=0x8000F000,force-raw=on,file=$HVM/run/exo0-$SOC.bin" \
    -device loader,addr=0x400000F8,data-len=4,data=4 \
    "${SECRETS[@]}" "${EXTRA[@]}" \
    -d int,guest_errors -D "$HVM/logs/qemu-$SOC.log" \
    "${TRACE[@]}" "${GDB[@]}" "$@"
