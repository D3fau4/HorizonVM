#!/usr/bin/env bash
# Headless boot smoke test (default: erista and mariko). usage: smoke.sh [--soc X]... [--timeout S]
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/hvm_smoke.py" "$@"
