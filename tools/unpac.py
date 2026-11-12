"""Extract the overlays in SvR 2007's BIN/BIN.PAC (DPAC container, Yuke's BPE)."""
import struct
import sys
from pathlib import Path


def bpe_expand(src, out_size, size_le):
    out = bytearray()
    p = 0
    while p < len(src) and len(out) < out_size:
        left = list(range(256))
        right = [0] * 256
        c = 0
        while c < 256:
            count = src[p]; p += 1
            if count > 127:
                c += count - 127
                count = 0
            if c == 256:
                break
            for _ in range(count + 1):
                left[c] = src[p]; p += 1
                if left[c] != c:
                    right[c] = src[p]; p += 1
                c += 1
        if size_le:
            size = src[p] | src[p + 1] << 8
        else:
            size = src[p] << 8 | src[p + 1]
        p += 2
        block = src[p:p + size]; p += size
        for b in block:
            stack = [b]
            while stack:
                x = stack.pop()
                if left[x] == x:
                    out.append(x)
                else:
                    stack.append(right[x])
                    stack.append(left[x])
    return bytes(out)


def main(pac, outdir):
    d = Path(pac).read_bytes()
    assert d[:4] == b'DPAC'
    assert d[0x800:0x804] == b'OVRM'
    n = struct.unpack_from('<I', d, 0x804)[0] // 2
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        name, start, cnt = struct.unpack_from('<4sHH', d, 0x808 + i * 8)
        name = name.decode().strip()
        off = 0x4000 + start * 0x800
        assert d[off:off + 4] == b'PAC ', (name, hex(off))
        assert d[off + 0x10:off + 0x14] == b'BPE '
        csize, usize = struct.unpack_from('<II', d, off + 0x18)
        src = d[off + 0x20:off + 0x20 + csize]
        data = None
        for le in (False, True):
            try:
                data = bpe_expand(src, usize, le)
                if len(data) == usize:
                    break
            except IndexError:
                data = None
        status = 'ok' if data and len(data) == usize else f'FAIL ({len(data) if data else 0})'
        print(f'{name:5} off={off:#x} c={csize:#x} u={usize:#x} {status}')
        if data:
            (outdir / f'{name}.bin').write_bytes(data)


if __name__ == '__main__':
    main(*sys.argv[1:3])
