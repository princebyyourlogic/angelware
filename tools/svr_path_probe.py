"""Report native SvR direct-handshake evidence from a local classic pcap.

Does not inject or replay packets. A completed handshake plus encrypted traffic
in both directions establishes the observed lobby peer path, not a different
match destination selected later by the game.
"""
import argparse
import collections
import json
from pathlib import Path

from svr_capture import packets


def analyze(path,relay_lo=20000,relay_hi=20199):
    observed=collections.defaultdict(list)
    relay=collections.Counter()
    for timestamp,proto,flow,_,data in packets(path):
        if proto!='udp' or len(data)<6 or data[1]!=2:continue
        kind=data[0]
        sizes={1:8,2:30,3:169,4:106}
        if kind in sizes and len(data)!=sizes[kind]:continue
        if kind==6 and len(data)<16:continue
        if kind not in (1,2,3,4,6):continue
        if relay_lo<=flow[1]<=relay_hi or relay_lo<=flow[3]<=relay_hi:
            relay[kind]+=1
            continue
        pair=tuple(sorted((flow[:2],flow[2:])))
        observed[pair].append((timestamp,flow,kind))
    paths=[]
    for pair,events in observed.items():
        complete=False
        encrypted=collections.Counter()
        for timestamp,flow,kind in events:
            if kind==6:encrypted[(flow[:2],flow[2:])]+=1
            if kind!=1:continue
            a,b=flow[:2],flow[2:]
            expected=2
            for later,other,k in events:
                if later<timestamp or later-timestamp>10:continue
                source,target=(b,a) if expected in (2,4) else (a,b)
                if other[:2]==source and other[2:]==target and k==expected:
                    expected+=1
                    if expected==5:
                        complete=True
                        break
        both=all(encrypted[(a,b)]>0 for a,b in ((pair[0],pair[1]),(pair[1],pair[0])))
        paths.append({'endpoints':pair,'complete_direct_handshake':complete,
                      'encrypted_traffic_both_directions':both,
                      'direct_peer_path_observed':complete and both,
                      'encrypted_packet_count':sum(encrypted.values())})
    return {'direct_paths':paths,'relayed_dtls_packets_by_type':dict(relay),
            'direct_peer_path_observed':any(p['direct_peer_path_observed'] for p in paths),
            'scope':'Observed lobby peer transport; later match-address selection is separate.'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=analyze(args.capture)
    if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
