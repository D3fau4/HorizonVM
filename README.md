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
scripts/build.sh                     # Atmosphère nx_debug + build/package2.bin
for soc in erista mariko; do         # per-profile VM identity in ~/.horizonvm (never in the repo)
    tools/mkfuses.py --soc $soc
    tools/hvm_keys.py --soc $soc --prod-keys /path/to/prod.keys
done
```

## Run

```sh
scripts/run.sh --soc erista          # UART-A + QEMU monitor on stdio (Ctrl-A c), logs in ~/.horizonvm/logs
scripts/run.sh --soc erista --gdb    # then: gdb-multiarch -x gdb/horizonvm.gdb -ex hvm-trace
scripts/smoke.sh --soc erista        # headless boot check
```
