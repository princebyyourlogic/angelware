#!/bin/sh
# Decompile LBYM functions headless: tools/ghidra_dec.sh ADDR|NAME|refs:TEXT ...
G=${GHIDRA_INSTALL_DIR:-$HOME/.local/opt/ghidra_12.1.4_PUBLIC}
cd "$(dirname "$0")/.."
"$G/support/analyzeHeadless" ghidra angelware -process LBYM.bin -noanalysis -readOnly \
  -scriptPath ghidra -postScript Decompile.java "$@" 2>&1 \
  | sed -n '/Decompile.java> ====/,/REPORT: Post-analysis/p' \
  | sed 's/^INFO  Decompile.java> //; s/ (GhidraScript) *$//; /REPORT: Post-analysis/d' | grep -v '^ *$'
