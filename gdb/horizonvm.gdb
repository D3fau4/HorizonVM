# From the repo root, with `scripts/run.sh --gdb` running (needs a Python-enabled aarch64 GDB;
# devkitA64's gdb is built --without-python):
#   gdb-multiarch -x gdb/horizonvm.gdb -ex hvm-trace
set pagination off
set architecture aarch64
target remote :1234
source gdb/horizonvm.py
