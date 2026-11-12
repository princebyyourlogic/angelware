"""Prepare a Yuke's SNR2 overlay (from BIN/BIN.PAC) for Ghidra.

SNR2 layout (SvR 2007), all little-endian u32:
  0x00 'SNR2'     0x04 reloc table   0x08 reloc count   0x0c symbol table
  0x10 sym count  0x14 module path   0x18 entry         0x1c ctor runner
  0x2c file size
Relocations are 12 bytes (offset, type | sym << 8, addend), types 4/5/6 =
R_MIPS_32/26/HI16/LO16 (2/4/5/6), and only ever reference undefined symbols (imports from
the main ELF). Symbols are 12 bytes (name offset, value, hash). Names are GCC
2.9x-mangled and obfuscated with a repeating 11-byte additive keystream over
the 94 printable characters 0x21..0x7e. The main ELF carries an export table
of the same 12-byte entries, which resolves the imports.

Writes <out>.bin (the overlay with import references pointed at EXTERN stubs)
and <out>.syms.tsv (address, kind, mangled name, demangled
name, main ELF address).
"""
import argparse
import os
import subprocess
import struct
from pathlib import Path

KEY = (6, 62, 62, 17, 93, 10, 79, 69, 86, 62, 13)
EXTERN_BASE = 0x02000000
ELF_VADDR_DELTA = 0xFF000  # SLUS_214.27: file offset 0x1000 -> 0x100000


def deobfuscate(raw):
    out = []
    for i, c in enumerate(raw):
        p = c - KEY[i % len(KEY)]
        if p < 0x21:
            p += 94
        out.append(chr(p))
    return ''.join(out)


def cstr(data, off):
    return data[off:data.index(b'\0', off)]


def elf_exports(elf):
    """Find the main ELF's export table by its 12-byte (name, value, hash) rows."""
    def row(o):
        return struct.unpack_from('<III', elf, o)

    def plausible(o):
        name, value, _ = row(o)
        return 0x100000 <= name < 0x400000 and 0x100000 <= value < 0x2000000

    # memset's obfuscated name anchors the search
    anchor = elf.find(b'\0' + b'sEM&d~\0') + 1
    hit = elf.find(struct.pack('<I', anchor + ELF_VADDR_DELTA))
    start = hit
    while plausible(start - 12):
        start -= 12
    end = hit
    while plausible(end + 12):
        end += 12
    exports = {}
    for o in range(start, end + 12, 12):
        name, value, _ = row(o)
        exports[deobfuscate(cstr(elf, name - ELF_VADDR_DELTA))] = value
    return exports


def demangle(names):
    """GCC 2.9x names need Ghidra's bundled binutils 2.24 demangler (modern c++filt dropped it)."""
    ghidra = Path(os.environ.get('GHIDRA_INSTALL_DIR', Path.home() / '.local/opt/ghidra_12.1.4_PUBLIC'))
    tool = ghidra / 'GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_24'
    out = subprocess.run([tool, '-s', 'gnu'], input='\n'.join(names) + '\n',
                         capture_output=True, text=True, check=True).stdout.splitlines()
    assert len(out) == len(names)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('overlay')
    ap.add_argument('elf')
    ap.add_argument('out')
    a = ap.parse_args()

    d = bytearray(Path(a.overlay).read_bytes())
    assert d[:4] == b'SNR2'
    rel_off, nrel, sym_off, nsym = struct.unpack_from('<IIII', d, 4)
    entry, ctors = struct.unpack_from('<II', d, 0x18)
    exports = elf_exports(Path(a.elf).read_bytes())

    syms = []
    for i in range(nsym):
        name, value, _ = struct.unpack_from('<III', d, sym_off + i * 12)
        syms.append((deobfuscate(cstr(d, name)) if name else '', value))

    stub = {}
    rows = [(entry, 'func', 'snr2_entry', ''), (ctors, 'func', 'snr2_run_ctors', '')]
    for i, (name, value) in enumerate(syms):
        if not name:
            continue
        if value:
            kind = 'data' if name.startswith('_vt$') else 'func'
            rows.append((value, kind, name, ''))
        else:
            stub[i] = EXTERN_BASE + 8 * len(stub)
            ext = exports.get(name)
            rows.append((stub[i], 'extern', name, f'{ext:#x}' if ext else ''))

    hi = {}
    for i in range(nrel):
        off, info, addend = struct.unpack_from('<III', d, rel_off + i * 12)
        kind, sym = info & 0xFF, info >> 8
        target = stub[sym] + addend
        insn = struct.unpack_from('<I', d, off)[0]
        if kind == 2:  # R_MIPS_32: a whole word holding the address
            insn = target & 0xFFFFFFFF
        elif kind == 4:
            insn = (insn & 0xFC000000) | (target >> 2) & 0x3FFFFFF
        elif kind == 5:
            insn = (insn & 0xFFFF0000) | ((target + 0x8000) >> 16)
        elif kind == 6:
            insn = (insn & 0xFFFF0000) | (target & 0xFFFF)
        else:
            raise ValueError(f'relocation type {kind} at {off:#x}')
        struct.pack_into('<I', d, off, insn)

    pretty = demangle([r[2] for r in rows])
    out = Path(a.out)
    out.with_suffix('.bin').write_bytes(d)
    with out.with_suffix('.syms.tsv').open('w') as f:
        for (addr, kind, name, ext), nice in sorted(zip(rows, pretty)):
            f.write(f'{addr:#x}\t{kind}\t{name}\t{nice}\t{ext}\n')
    resolved = sum(1 for r in rows if r[1] == 'extern' and r[3])
    print(f'{len(rows)} symbols, {len(stub)} imports ({resolved} resolved), {nrel} relocations')


if __name__ == '__main__':
    main()
