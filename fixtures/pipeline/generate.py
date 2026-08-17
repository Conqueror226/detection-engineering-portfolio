#!/usr/bin/env python3
"""Generate the pipeline pcap: two RDP hops WS->SRV-APP-01->DC01."""
import logging, pathlib
logging.getLogger("scapy").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Ether, wrpcap
OUT = pathlib.Path(__file__).resolve().parent / "privileged_unapproved_path.pcap"
BASE = 1786356000.0
def flow(src, dst, sport, t):
    pk=[]
    for k,(s,d,sp,dp,fl) in enumerate([(src,dst,sport,3389,"S"),(dst,src,3389,sport,"SA"),(src,dst,sport,3389,"PA")]):
        p=Ether()/IP(src=s,dst=d)/TCP(sport=sp,dport=dp,flags=fl); p.time=t+k*0.01; pk.append(p)
    return pk
pk = flow("10.0.0.10","10.0.0.60",49711,BASE) + flow("10.0.0.60","10.0.0.90",49712,BASE+60)
wrpcap(str(OUT), pk); print("wrote", OUT.name)
