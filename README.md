# HorizonVM

Headless ARM64 VM for Horizon OS: [tegra_qemu](https://github.com/yellows8/tegra_qemu) (Tegra X1 / X1+)
boots Atmosphère's exosphere at EL3, which hands off to Mesosphere. No fusee/BPMP: `tools/` generates
the handoff data (plaintext package2, fuse cache, SE keyslots).

## Requirements

devkitPro (devkitA64 + devkitARM), `libglib2.0-dev libpixman-1-dev libfdt-dev libgcrypt20-dev`,
`gdb-multiarch` for debugging, and your own `prod.keys`.

## Setup

```sh
scripts/bootstrap.sh                 # submodules, tegra_qemu patches, build/qemu
HVM_FW=/path/to/firmware scripts/build.sh   # Atmosphère nx_debug + build/package2-<ini>.bin + release dist
                                     # HVM_FW: a 22.5.0 dump (Processed/, sysupdate-*/) for the ams/stock INI1
for soc in erista mariko; do         # per-profile VM identity in ~/.horizonvm (never in the repo)
    tools/mkfuses.py --soc $soc
    tools/hvm_keys.py --soc $soc --prod-keys /path/to/prod.keys --derive-bis
    tools/mknand.py --soc $soc --fw /path/to/firmware --image --verify   # eMMC: folder tree + encrypted image
                                     # PRODINFO: tools/mkcal0.py (synthetic identity; optional factory calibration
                                     # from ~/.horizonvm/ref/prodinfo-ref.bin; es key needs eticket_rsa_kek*_source)
    tools/mksd.py --soc $soc --dist third_party/Atmosphere/out/nintendo_nx_arm64_armv8a/release/atmosphere-*.zip \
        --image --verify                 # SD card (8 GiB, --size): atmosphere/ folder + FAT32 image
done
```

## Run

```sh
scripts/run.sh --soc erista          # UART-A + QEMU monitor on stdio (Ctrl-A c), logs in ~/.horizonvm/logs
scripts/run.sh --ini core            # INI1 profile: empty | core (sm, spl) | ams (+ pm, loader, ncm, boot, FS) | stock
scripts/run.sh --persist             # keep eMMC writes (default: snapshot, the image stays pristine)
scripts/run.sh --nand dir            # eMMC served live from ~/.horizonvm/nand/<soc>/dir over NBD (tools/hvm_nbd.py)
scripts/run.sh --nand dir --persist  # ... and write the guest's changes back into those folders when QEMU exits
scripts/run.sh --sd dir              # SD card from ~/.horizonvm/sd/<soc>/dir (default: follows --nand for ams/stock)
scripts/run.sh --maintenance         # volume buttons held: boot2 launches its maintenance list
scripts/run.sh --realtime            # ams/stock run with -icount (guest clock = instructions) unless this
tools/hvm_nbd.py sync --soc erista --to /tmp/snap   # snapshot folders + pending writes (safe while running)
tools/hvm_nbd.py sync --disk sd --soc erista          # the same for the SD card
scripts/run.sh --soc erista --gdb    # then: gdb-multiarch -x gdb/horizonvm.gdb -ex hvm-trace
scripts/run.sh --soc erista --trace  # + hvmtrace plugin: SMC/MMIO log (secrets redacted at the source)
tools/hvm_log.py --soc erista        # summarize/check SMC, MMIO per device, exceptions
scripts/smoke.sh                     # headless boot check, erista + mariko x every built INI1 profile
tools/hvm_smoke.py --ini ams --long  # ... and the late sysmodules' frontier (+5 min); also --maintenance
tools/hvm_leakscan.py                # look for the VM identities' secrets outside identity/ and the SD
```

Raw logs live in `~/.horizonvm/logs` (private); share only `hvm_log.py` summaries.
