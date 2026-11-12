"""Verify native SvR match packet delivery/ACKs across a captured relay route.

This is an offline check, not a packet injector. It requires the receiver to ACK
the forwarded packet's sequence AND generation, from the expected game socket.
"""
import argparse
import json
from pathlib import Path

from svr_capture import packets


def game_header(data):
    if len(data)<8 or data[5]!=2 or int.from_bytes(data[2:4],'big')+8!=len(data):
        return None
    if data[4]==0:
        return 'data',bytes((data[0],data[6]))
    if data[4]==8 and len(data)==10:
        return 'ack',data[8:10]
    return None


def analyze(capture,lo=20000,hi=20199):
    rows=[(t,flow,data) for t,proto,flow,_,data in packets(capture) if proto=='udp']
    incoming=[]
    forwarded=[]
    proofs=[]
    for timestamp,flow,data in rows:
        header=game_header(data)
        if header is None:continue
        kind,token=header
        if kind=='data' and lo<=flow[3]<=hi:
            incoming.append((timestamp,flow,data))
        if kind=='data' and lo<=flow[1]<=hi:
            original=[x for x in incoming if x[2]==data and 0<=timestamp-x[0]<1]
            if original:
                forwarded.append((timestamp,flow,token,original[-1]))
        if kind=='ack' and lo<=flow[3]<=hi:
            matches=[x for x in forwarded if x[1][:2]==flow[2:] and x[1][2:]==flow[:2]
                     and x[2]==token and 0<=timestamp-x[0]<3]
            if matches:
                sent,route,_,original=matches[-1]
                proofs.append({'request_origin':original[1][:2],'receiver':flow[:2],
                               'request_relay':original[1][2:],'reply_relay':flow[2:],
                               'sequence':token[0],'generation':token[1],
                               'receiver_round_trip_ms':round((timestamp-sent)*1000,3),
                               'request_payload_bytes':len(original[2]),
                               'ack_time':timestamp,'ack_payload':data.hex(),
                               'ack_forwarded_back':False})
        if kind=='ack' and lo<=flow[1]<=hi:
            for proof in reversed(proofs):
                if (tuple(proof['request_relay'])==flow[:2] and tuple(proof['request_origin'])==flow[2:]
                        and proof['ack_payload']==data.hex() and 0<=timestamp-proof['ack_time']<1):
                    proof['ack_forwarded_back']=True
                    break
    receivers={tuple(p['receiver']) for p in proofs}
    directions={}
    for proof in proofs:
        origin,receiver=tuple(proof['request_origin']),tuple(proof['receiver'])
        pair=tuple(sorted((origin,receiver)))
        directions.setdefault(pair,set()).add((origin,receiver))
    verified_pairs=[pair for pair,seen in directions.items() if len(seen)==2]
    for proof in proofs:
        del proof['ack_payload']
    return {'offline_only':True,'acknowledged_forwarded_match_packets':len(proofs),
            'acknowledging_game_sockets':sorted(receivers),
            'verified_both_directions':bool(verified_pairs),'verified_pairs':verified_pairs,
            'complete_request_ack_cycles':sum(p['ack_forwarded_back'] for p in proofs),
            'proofs':proofs}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=analyze(args.capture)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
