#!/usr/bin/env python3
"""Build exosphere's EXO0 storage configuration (what fusee writes at 0x8000F000, fusee_setup_horizon.cpp)."""
import argparse
import struct

EXO0_ADDRESS = 0x8000F000               # secmon::MemoryRegionPhysicalDramMonitorConfiguration
EXO0_SIZE = 0x130                       # sizeof(SecureMonitorStorageConfiguration)
TARGET_FIRMWARE_22_5_0 = 0x16050000     # ams::TargetFirmware_Current @ 6e6af69

# secmon_monitor_context.hpp SecureMonitorConfigurationFlag
FLAG_DEVFN_KERNEL = 1 << 1              # fusee's default
FLAG_DISABLE_USER_EXCEPTION_HANDLERS = 1 << 3

OFFSETS = {'magic': 0x00, 'target_firmware': 0x04, 'flags': 0x08, 'lcd_vendor': 0x10,
           'log_port': 0x12, 'log_flags': 0x13, 'log_baud_rate': 0x14, 'emummc_cfg': 0x20}


def build_exo0(target_firmware=TARGET_FIRMWARE_22_5_0, user_exception_handlers=False):
    flags0 = FLAG_DEVFN_KERNEL
    if not user_exception_handlers:
        # Crashing KIPs get a kernel register dump instead of hanging in their handler waiting for bpc:ams.
        flags0 |= FLAG_DISABLE_USER_EXCEPTION_HANDLERS
    cfg = bytearray(EXO0_SIZE)
    cfg[0:4] = b'EXO0'
    struct.pack_into('<III', cfg, OFFSETS['target_firmware'], target_firmware, flags0, 0)
    cfg[OFFSETS['log_port']] = 0        # uart::Port_ReservedDebug (UART-A), as fusee and the default config
    struct.pack_into('<I', cfg, OFFSETS['log_baud_rate'], 115200)
    return bytes(cfg)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--user-exc', action='store_true', help='keep user-mode exception handlers (fusee default)')
    args = ap.parse_args()
    with open(args.output, 'wb') as f:
        f.write(build_exo0(user_exception_handlers=args.user_exc))


if __name__ == '__main__':
    main()
