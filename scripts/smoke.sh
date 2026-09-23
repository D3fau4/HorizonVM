#!/usr/bin/env bash
# Headless boot smoke test. usage: smoke.sh [--soc erista] [--soc mariko] [--timeout S]
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/hvm_smoke.py" "$@"
