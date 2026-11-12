#!/bin/sh
# Rebuilds ghidra/angelware.gpr with LBYM from an extracted disc (see docs/svr2007-analysis.md).
set -e
G=${GHIDRA_INSTALL_DIR:-$HOME/.local/opt/ghidra_12.1.4_PUBLIC}
cd "$(dirname "$0")/.."
mkdir -p work
python3 tools/unpac.py disc/BIN/BIN.PAC disc/overlays
python3 tools/snr2.py disc/overlays/LBYM.bin disc/SLUS_214.27 work/LBYM
"$G/support/analyzeHeadless" ghidra angelware -import work/LBYM.bin -overwrite \
  -loader BinaryLoader -loader-baseAddr 0x0 -processor r5900:LE:32:default \
  -scriptPath ghidra -preScript ApplySnr2Symbols.java work/LBYM.syms.tsv 0xce040 \
  -postScript NameFromAsserts.java -postScript ApplyNames.java ghidra/LBYM.names.tsv
