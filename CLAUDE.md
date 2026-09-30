# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

HorizonVM is a headless ARM64 VM for Horizon OS (Nintendo Switch): tegra_qemu (Tegra X1 / X1+) runs Atmosphère's
real exosphere at EL3, which hands off to Mesosphere and the INI1 processes. There is no fusee/BPMP: the host
tools generate everything fusee would normally leave behind. Current status and pending milestones live in
`docs/fase3.md`. The user communicates in Spanish.

## Commands

```sh
scripts/bootstrap.sh                          # submodules + patches/tegra_qemu/*.patch + build/qemu + hvmtrace plugin
HVM_FW=<22.5.0 dump> scripts/build.sh         # Atmosphère nx_debug KIPs, build/package2-{empty,core,ams,stock}.bin,
                                              # release dist (HVM_DIST=1 forces a rebuild of the dist)
python3 -m unittest discover -s tools/tests   # unit tests (many skip without devkitA64, dosfstools/mtools, HVM_FW)
python3 -m unittest discover -s tools/tests -k TestMkcal0              # one class
python3 -m unittest discover -s tools/tests -k TestSd.test_<name>      # one test
tools/hvm_smoke.py --soc erista --ini ams --nand dir                   # one smoke cell (scripts/smoke.sh = full matrix)
tools/hvm_smoke.py --soc erista --ini ams --nand dir --long            # + late sysmodules' frontier (+5 min)
tools/hvm_leakscan.py                                                  # identity secrets outside identity/ and sd/
scripts/run.sh --soc mariko --ini stock --trace && tools/hvm_log.py --soc mariko
```

VM data setup per SoC (`mkfuses`, `hvm_keys --derive-bis`, `mknand`, `mkcal0`, `mksd`) is in `README.md`.
Atmosphère supports firmware ≤ 22.5.0 only.
ams/stock run with `-icount` (guest clock follows instructions, single-threaded TCG; `run.sh --realtime` disables
it): an ams/stock smoke cell takes ~5–7 min, `--long` ~12. Run one VM at a time.

## Architecture

**Boot chain replacing fusee.** `run.sh` assembles the QEMU command line from host-generated data:
- `mkpkg2.py`: plaintext package2 (mesosphere + INI1) as fusee's RebuildPackage2 builds it.
- `mkexo0.py`: exosphere's EXO0 storage config at 0x8000F000.
- `mkfuses.py`: the synthetic fuse cache.
- `hvm_keys.py`: SE keyslot secrets and BIS keys.
- `patches/tegra_qemu/0003`: bootloader register state that pcv needs (CAR SPARE_REG0, PMIC VDD_CPU/LDO2), set per
  SoC through `-global` properties.

**SoC profiles.**
- `erista` (tegrax1, Icosa) and `mariko` (tegrax1plus, Iowa) must both keep working.
- Each has its own synthetic identity in `~/.horizonvm/identity/<soc>/`, plus its own NAND (`~/.horizonvm/nand/<soc>/`)
  and SD (`~/.horizonvm/sd/<soc>/`).

**INI1 profiles.**
- `empty`: kernel only.
- `core`: sm, spl.
- `ams`: Atmosphère loader/ncm/pm/sm/boot/spl/ams_mitm plus Nintendo's FS.kip1. It boots boot2 from the SD's
  `stratosphere.romfs`.
- `stock`: Nintendo's INI1.
- FS is always Nintendo's (`stratosphere/fs` is a stub).

**Storage.**
- `hvm_nand.py` holds the shared layout (GPT, partitions, FAT options, CAL0 CRC).
- The eMMC (SDMMC4) and SD (SDMMC1) are either images, or folders served live by `hvm_nbd.py`. The folder mode
  synthesizes the GPT/MBR and FAT and BIS-XTS-encrypts eMMC partitions on the fly; `--persist` writes guest changes
  back to the folders on exit.
- `mkcal0.py` generates PRODINFO: synthetic identity from the ECID, and only a whitelist (`IMPORTED`) of
  non-identifying calibration from an optional reference in `~/.horizonvm/ref/`.

**Observability.**
- `plugins/hvmtrace.c` (QEMU TCG plugin) logs SMCs, SVCs/IPC headers and MMIO. It **redacts secrets at the source**:
  SE/SE2/PKA MMIO, crypto SMC args/results, and svc 0x7F.
- `hvm_log.py` turns that log, plus the UART and `-d int` logs, into summaries: per-device MMIO allowlists, crashes,
  and leak detection.
- `hvm_smoke.py` boots headless and checks per-profile expectations (READY regex, idle cores, `ams_checks` /
  `stock_checks`, `EXPECTED_CRASHES`). Extend it with every milestone.
- `gdb/horizonvm.gdb` needs `gdb-multiarch` (devkitA64's gdb has no Python).

## Rules

- **Never patch Atmosphère** (submodule pinned at 6e6af69). tegra_qemu gets neutral patches in `patches/tegra_qemu/`
  only when hardware or bootloader state requires it; patch 0001 (no secret dumps) is mandatory before real keys.
- **Secrets and Nintendo data stay in `~/.horizonvm` (0700/0600).**
  - Never print, log, copy or commit key values.
  - Refer to key files (`prod.keys`, identity) only by path.
  - Nintendo firmware and binaries never enter the repo; RE work goes in `~/.horizonvm/tmp/re`.
  - Don't read raw SE logs; share only `hvm_log.py` summaries.
  - With GDB on exosphere, use `set print frame-arguments none`.
  - Never point `watch=` at spl/FS.
- Never mix real and synthetic identity. The reference PRODINFO contains real data: use only the approved whitelist.
- Ask the user before any design decision. Work on milestone branches (`fase3`), with one `Mx:` commit per verified
  milestone and minimal docs. Don't push or merge unless asked.
- The NBD servers die with the shell that launched them: use `hvm_nbd.py sync` for pending writes, check for stale
  locks in `~/.horizonvm/{nand,sd}/<soc>/overlay/lock`, and avoid `pkill -f` (it matches the calling shell).
