"""Read local classic-pcap test captures; never print account/ticket contents."""
import collections
import json
from pathlib import Path
import socket
import struct
import sys


class Bits:
    def __init__(self, data):
        self.data, self.pos = data, 0
        self.typed = bool(self.read(1))

    def read(self, n):
        if self.pos + n > len(self.data) * 8:
            raise ValueError('short bit buffer')
        v = sum(((self.data[(self.pos+i)//8] >> ((self.pos+i)%8)) & 1) << i for i in range(n))
        self.pos += n
        return v

    def raw(self, n):
        return bytes(self.read(8) for _ in range(n))

    def field(self):
        t = self.read(5)
        widths = {1:1,2:8,3:8,5:16,6:16,7:32,8:32,9:64,10:64,13:32,14:64}
        if t in widths:
            return t, self.read(widths[t])
        if t == 19:
            if self.read(5) != 8:
                raise ValueError('blob without length')
            return t, self.raw(self.read(32))
        if t == 16:
            out = bytearray()
            while (c := self.read(8)):
                out.append(c)
            return t, bytes(out)
        raise ValueError(f'unknown field {t}')


def packets(path):
    data = Path(path).read_bytes()
    if len(data) < 24:
        return
    order = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    link = struct.unpack_from(order+'I', data, 20)[0]
    pos, seen = 24, set()
    while pos + 16 <= len(data):
        sec, usec, length, _ = struct.unpack_from(order+'4I', data, pos)
        pos += 16
        frame = data[pos:pos+length]
        pos += length
        if len(frame) < length:
            break
        offset = {1:14,113:16,276:20,101:0}.get(link)
        if offset is None:
            raise ValueError(f'unsupported link type {link}')
        ip = frame[offset:]
        if not ip or ip[0] >> 4 != 4 or len(ip) < 20:
            continue
        total = struct.unpack_from('!H',ip,2)[0]
        ip = ip[:total]
        ihl = (ip[0] & 15)*4
        proto, src, dst = ip[9], socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        segment = ip[ihl:]
        # The any interface sees bridge traffic twice. Deduplicate identical IP packets
        # within a timestamp second, retaining later legitimate UDP keepalives.
        sig = (sec, ip)
        if sig in seen:
            continue
        seen.add(sig)
        if proto == 6 and len(segment) >= 20:
            sp, dp, seq = struct.unpack_from('!HHI',segment)
            hlen = (segment[12] >> 4)*4
            yield sec+usec/1e6, 'tcp', (src,sp,dst,dp), seq, segment[hlen:]
        elif proto == 17 and len(segment) >= 8:
            sp, dp, n = struct.unpack_from('!HHH',segment)
            yield sec+usec/1e6, 'udp', (src,sp,dst,dp), None, segment[8:n]


def analyze(path):
    streams = collections.defaultdict(dict)
    udp = collections.Counter()
    endpoints = collections.Counter()
    for t, proto, flow, seq, payload in packets(path):
        if proto == 'tcp' and payload:
            streams[flow][seq] = (t,payload)
        elif proto == 'udp':
            udp[(payload[:3].hex(),len(payload))] += 1
            endpoints[flow] += 1
    auth, rooms, plain_login_keys, stats = [], [], {}, collections.Counter()
    for flow, segments in streams.items():
        joined = bytearray()
        expected = None
        for seq,(t,payload) in sorted(segments.items()):
            if expected is not None and seq > expected:
                break
            skip = max(0,(expected or seq)-seq)
            joined.extend(payload[skip:])
            expected = max(expected or seq, seq+len(payload))
        pos = 0
        while pos+4 <= len(joined):
            n = struct.unpack_from('<H',joined,pos)[0]
            if n < 2 or pos+2+n > len(joined):
                break
            body = joined[pos+2:pos+2+n]
            pos += n+2
            stats[(flow[2],flow[3],body[0])] += 1
            if body[0] != 0:
                continue
            kind, payload = body[1],body[2:]
            try:
                b = Bits(payload)
                if flow[3] == 3074 and kind in (0,2,6,10,16) and not b.typed:
                    seed,title = b.read(32),b.read(32)
                    if title == 4669:
                        auth.append({'flow':flow,'type':kind,'seed':f'{seed:08x}'})
                elif flow[1] == 3074 and kind == 17 and not b.typed:
                    if b.read(32) == 700:
                        b.read(32)
                        ticket = b.raw(128)
                        plain_login_keys[(flow[2],flow[3])] = ticket[97:121].hex()
                elif flow[1] == 3074 and kind == 1 and b.typed:
                    fields = [b.field() for _ in range(5)]
                    if [x[0] for x in fields] == [3,3,8,3,8] and fields[2][1] == 0 and fields[3][1] == 1 and fields[4][1] == 1:
                        sid,key = b.field(),b.field()
                        if sid[0] == key[0] == 19 and len(sid[1]) == 8 and len(key[1]) == 16:
                            rooms.append({'id':sid[1].hex(),'key':key[1].hex(),'flow':flow})
            except (ValueError,IndexError):
                pass
    return {'auth':auth,'rooms':rooms,'udp':[{'header':h,'length':n,'count':c} for (h,n),c in udp.items()],
            'udp_endpoints':[{'flow':f,'count':n} for f,n in endpoints.items()],
            'plain_login_key_count':len(plain_login_keys)}


if __name__ == '__main__':
    result = analyze(sys.argv[1])
    if len(sys.argv)>2:
        Path(sys.argv[2]).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({**result,'rooms':[{'id':x['id'],'key':'[withheld]','flow':x['flow']} for x in result['rooms']]},indent=2))
