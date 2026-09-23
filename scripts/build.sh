#!/usr/bin/env bash
# Build the unmodified Atmosphère NX debug components used by HorizonVM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AMS="$ROOT/third_party/Atmosphere"
export DEVKITPRO="${DEVKITPRO:-/opt/devkitpro}"

make -C "$AMS/mesosphere" nx_debug -j"$(nproc)"
make -C "$AMS/exosphere" nx_debug -j"$(nproc)"
