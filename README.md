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
HVM_FW=/path/to/firmware scripts/build.sh   # Atmosphère nx_debug + build/package2-<ini>.bin
                                     # HVM_FW: a 22.5.0 dump (Processed/, sysupdate-*/) for the ams/stock INI1
for soc in erista mariko; do         # per-profile VM identity in ~/.horizonvm (never in the repo)
    tools/mkfuses.py --soc $soc
    tools/hvm_keys.py --soc $soc --prod-keys /path/to/prod.keys
done
```

## Run

```sh
scripts/run.sh --soc erista          # UART-A + QEMU monitor on stdio (Ctrl-A c), logs in ~/.horizonvm/logs
scripts/run.sh --ini core            # INI1 profile: empty | core (sm, spl) | ams (+ pm, loader, ncm, boot, FS) | stock
scripts/run.sh --soc erista --gdb    # then: gdb-multiarch -x gdb/horizonvm.gdb -ex hvm-trace
scripts/run.sh --soc erista --trace  # + hvmtrace plugin: SMC/MMIO log (secrets redacted at the source)
tools/hvm_log.py --soc erista        # summarize/check SMC, MMIO per device, exceptions
scripts/smoke.sh                     # headless boot check, erista + mariko x every built INI1 profile
```

Raw logs live in `~/.horizonvm/logs` (private); share only `hvm_log.py` summaries.
