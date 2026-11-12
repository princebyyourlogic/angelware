"""Offline proof: rewrite the host's SvR join-accept addresses for a relay.

This edits a supplied capture; it never sends packets or changes a running server.
Requires keys recovered by svr_recover.py. Unsupported chunk layouts pass unchanged.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import socket
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from svr_capture import Bits, packets
from svr_recover import tiger


def endpoint(text):
    host,port=text.rsplit(':',1)
    ipaddress.IPv4Address(host)
    port=int(port)
    if not 0<port<65536:
        raise ValueError('port outside 1..65535')
    return host,port


def unpack_addr(data):
    return f'{socket.inet_ntoa(data[:4])}:{int.from_bytes(data[4:6],"little")}'


def data_chunks(body):
    """Bounded parser for compact tail lengths, DATA and SACK chunks in this capture.

    Each chunk is prefixed by its clear-tail byte count (a compact 15-bit value).
    Other chunk types cause the packet to pass through; never scan arbitrary bytes
    for something that merely resembles a DATA header.
    """
    pos=4  # bdPacket's u32 association verification tag
    while pos<len(body):
        tail=body[pos]
        pos+=1
        if tail&128:
            if pos>=len(body): raise ValueError('short compact length')
            tail=((tail&127)<<8)|body[pos]
            pos+=1
        if pos>=len(body): raise ValueError('missing chunk type')
        kind=body[pos]
        if kind==2:
            if pos+7>len(body): raise ValueError('short DATA header')
            flags,size,mt,sequence=struct.unpack_from('<BHBH',body,pos+1)
            begin,end=pos+7,pos+7+size
            if end>len(body): raise ValueError('short DATA payload')
            yield mt,sequence,begin,end,flags,tail
            pos=end
        elif kind==5:
            if pos+15>len(body): raise ValueError('short SACK')
            gaps=struct.unpack_from('<H',body,pos+11)[0]
            pos+=15+gaps*4
            if pos>len(body): raise ValueError('short SACK gap list')
        else:
            raise ValueError(f'unsupported chunk type {kind}')


def rewrite_join_accept(payload,room_id,relay):
    """Match verified host-record prefixes; change only their 25-byte address blobs.

    Join-accept (0x4f) contains generic and game-specific host records. The latter
    includes the room ID. Require that binding before changing either copy.
    """
    bits=Bits(payload)
    if bits.typed: raise ValueError('typed join-accept is unsupported')
    name=bytearray()
    while (c:=bits.read(8)):
        name.append(c)
        if len(name)>32: raise ValueError('invalid host name length')
    bits.read(64)  # host user ID
    if bits.read(32)!=25: raise ValueError('missing host address blob')
    address_bit=bits.pos
    old=bits.raw(25)
    value=int.from_bytes(payload,'little')
    # This prefix includes name, ID, the exact blob length, and the old address.
    prefix_bits=address_bit+200-1
    prefix_mask=(1<<prefix_bits)-1
    prefix=(value>>1)&prefix_mask
    starts=[]
    bound=False
    for start in range(1,len(payload)*8-prefix_bits+1):
        if ((value>>start)&prefix_mask)!=prefix: continue
        address=start+address_bit-1
        starts.append(address)
        after=address+200
        if after+96<=len(payload)*8:
            probe=Bits(payload);probe.pos=after
            if probe.read(32)==8 and probe.raw(8)==room_id:
                bound=True
    if not bound or not starts:
        raise ValueError('join-accept does not bind the expected room')
    packed=socket.inet_aton(relay[0])+struct.pack('<H',relay[1])
    new=packed+old[6:18]+packed+old[24:25]
    mask=(1<<200)-1
    permitted=0
    for start in starts:
        value=(value&~(mask<<start))|(int.from_bytes(new,'little')<<start)
        permitted|=mask<<start
    rewritten=value.to_bytes(len(payload),'little')
    # An independent bit mask ensures every bit outside the address blobs survives.
    assert ((int.from_bytes(payload,'little')^value)&~permitted)==0
    return rewritten,{'address_bits':starts,'local_before':unpack_addr(old[:6]),
                      'public_before':unpack_addr(old[18:24]),'local_after':unpack_addr(new[:6]),
                      'public_after':unpack_addr(new[18:24])}


def rewrite_datagram(data,key,room_id,relay):
    expected=hmac.new(key,data[:6]+data[16:],hashlib.sha1).digest()[:8]
    if not hmac.compare_digest(expected,data[6:14]):
        raise ValueError('original HMAC invalid')
    size=struct.unpack_from('<H',data,14)[0]
    padded=(size+7)&~7
    if 16+padded>len(data): raise ValueError('short encrypted payload')
    seq=struct.unpack_from('<H',data,4)[0]
    iv=tiger(struct.pack('<I',seq))[:8]
    decrypt=Cipher(TripleDES(key),modes.CBC(iv)).decryptor()
    plain=decrypt.update(data[16:16+padded])+decrypt.finalize()
    body=bytearray(plain[:size])
    edits=[]
    # Materialize first: an unsupported later chunk leaves the entire packet alone.
    chunks=list(data_chunks(body))
    for mt,sequence,begin,end,flags,tail in chunks:
        if mt!=0x4f: continue
        if flags!=0 or tail!=0: raise ValueError('fragmented/raw-tail join-accept unsupported')
        new,edit=rewrite_join_accept(bytes(body[begin:end]),room_id,relay)
        body[begin:end]=new
        edits.append({'message_type':mt,'message_sequence':sequence,'chunk_payload_offset':begin,**edit})
    if not edits: return data,[]
    encrypt=Cipher(TripleDES(key),modes.CBC(iv)).encryptor()
    ciphertext=encrypt.update(bytes(body)+plain[size:])+encrypt.finalize()
    new=bytearray(data)
    new[16:16+padded]=ciphertext
    new[6:14]=hmac.new(key,new[:6]+new[16:],hashlib.sha1).digest()[:8]
    assert len(new)==len(data)
    assert hmac.compare_digest(hmac.new(key,new[:6]+new[16:],hashlib.sha1).digest()[:8],new[6:14])
    # Reopen the completed packet and check the exact intended bytes, not just HMAC.
    check=Cipher(TripleDES(key),modes.CBC(iv)).decryptor()
    opened=check.update(new[16:16+padded])+check.finalize()
    assert opened[:size]==bytes(body) and opened[size:]==plain[size:]
    for edit in edits: edit['dtls_sequence']=seq
    return bytes(new),edits


def checksum(data):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535


def patch_capture(source,dest,changes):
    """Replace exact UDP payloads and update UDP checksums; preserve IP lengths."""
    raw=bytearray(source.read_bytes())
    order='<' if raw[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
    link=struct.unpack_from(order+'I',raw,20)[0]
    l2={1:14,113:16,276:20,101:0}[link]
    pos=24;changed=0
    while pos+16<=len(raw):
        length=struct.unpack_from(order+'I',raw,pos+8)[0]
        frame=pos+16;pos=frame+length
        ip=frame+l2
        if pos>len(raw) or ip+20>pos or raw[ip]>>4!=4 or raw[ip+9]!=17:continue
        udp=ip+(raw[ip]&15)*4
        if udp+8>pos:continue
        n=struct.unpack_from('!H',raw,udp+4)[0]
        start,end=udp+8,udp+n
        if end>pos:continue
        flow=(socket.inet_ntoa(raw[ip+12:ip+16]),struct.unpack_from('!H',raw,udp)[0],
              socket.inet_ntoa(raw[ip+16:ip+20]),struct.unpack_from('!H',raw,udp+2)[0])
        replacement=changes.get((flow,bytes(raw[start:end])))
        if replacement is None:continue
        raw[start:end]=replacement
        raw[udp+6:udp+8]=b'\0\0'
        pseudo=bytes(raw[ip+12:ip+20])+b'\0\x11'+struct.pack('!H',n)
        value=checksum(pseudo+bytes(raw[udp:end])) or 65535
        struct.pack_into('!H',raw,udp+6,value)
        changed+=1
    dest.touch(mode=0o600,exist_ok=True)
    dest.write_bytes(raw)
    return changed


def run(capture,keys,host,relay,output):
    entries=json.loads(keys.read_text())
    changes={};edits=[]
    for _,proto,flow,_,data in packets(capture):
        if proto!='udp' or flow[:2]!=host or data[:2]!=b'\6\2':continue
        for entry in entries:
            if {tuple(entry['endpoint']),tuple(entry['remote'])}!={flow[:2],flow[2:]}:continue
            try:
                new,items=rewrite_datagram(data,bytes.fromhex(entry['traffic_key']),bytes.fromhex(entry['room_id']),relay)
            except ValueError:
                continue
            if items:
                changes[(flow,data)]=new;edits.extend(items)
            break
    output.mkdir(parents=True,exist_ok=True)
    changed=patch_capture(capture,output/'rewritten.pcap',changes)
    report={'offline_only':True,'host':host,'relay':relay,'modified_datagrams':len(changes),
            'modified_capture_records':changed,'rewritten_address_blobs':sum(len(x['address_bits']) for x in edits),
            'packet_lengths_preserved':True,'recomputed_hmacs_verified':True,'edits':edits}
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    if not changes:raise SystemExit('No supported host join-accept found; nothing was rewritten.')


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('capture',type=Path)
    ap.add_argument('--keys',type=Path,default=Path('work/svr-key-recovery/recovered-keys.json'))
    ap.add_argument('--host',type=endpoint,required=True)
    ap.add_argument('--relay',type=endpoint,required=True)
    ap.add_argument('--output',type=Path,default=Path('work/svr-relay-rewrite'))
    args=ap.parse_args()
    run(args.capture,args.keys,args.host,args.relay,args.output)
